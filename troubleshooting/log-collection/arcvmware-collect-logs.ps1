<#
.SYNOPSIS
    Collects Azure Arc-enabled VMware vSphere diagnostic data from the customer's on-premises
    workstation, the Arc resource bridge and the vCenter-connected Azure resources, into a single
    redacted archive that can be attached to a support case or an IcM.

.DESCRIPTION
    This script is strictly READ-ONLY. It never creates, updates or deletes anything in Azure,
    in Kubernetes, or in VMware vCenter. Every step is a read, a describe or a file copy.

    It exists because a large part of the data an Arc VMware engineer needs is NOT available to
    them from Azure-side telemetry:

      * The resource provider ships only the single 'vmware-operator' container's log to its
        telemetry pipeline, only for the duration of a workflow, and - when the correlation-ID
        filter is enabled - only the lines carrying that one correlation ID. Everything else the
        operator logged is dropped.
      * It never collects the PREVIOUS container log, so a crash loop or an OOMKill erases the
        evidence of why the container died.
      * It collects nothing at all when the resource bridge or the custom location is unreachable,
        which is precisely the state most escalations are in.
      * The custom-resource bodies on the cluster - the state machine's state, phase, task info
        and conditions, which is where the real error text lives - are never sent to Azure.
      * During first-time onboarding, nothing exists in Azure yet, so there is no telemetry at all.
        The only evidence is on the workstation: the onboarding script log, kva.log, the az CLI
        versions, the proxy settings and the endpoint reachability.

    Run it on the SAME machine the customer ran the onboarding from. 'az arcappliance' needs the
    SSH key under $HOME/.kva/.ssh and the appliance kubeconfig, both of which are written on that
    machine, and it is not supported over remote PowerShell - use a console session or RDP.

    Two scenarios are supported and they collect different things:

      -Scenario Onboarding   First-time connection of a vCenter to Azure Arc. The bridge may be
                             half-deployed or absent. Weight is on workstation prerequisites,
                             proxy and endpoint reachability, the onboarding script log, kva.log,
                             the appliance YAML configs and whatever ARM resources did get created.

      -Scenario Onboarded    vCenter is already connected and something is failing. Weight is on
                             ARM resource state, the appliance log bundle, the full operator pod
                             logs including the previous container, every vsphere.vmware.microsoft.com
                             custom resource, and Kubernetes events.

    Secrets are redacted before anything is written: Kubernetes Secret bodies are never dumped
    (only their names and types), and password/token/key values, bearer tokens, JWTs and PEM
    private key blocks are masked in every captured file.

.PARAMETER Scenario
    'Onboarding' or 'Onboarded'. See above.

.PARAMETER VCenterId
    ARM ID of the Microsoft.ConnectedVMwarevSphere/VCenters resource. Used in the 'Onboarded'
    scenario to resolve the custom location, the resource bridge and the region automatically.

.PARAMETER SubscriptionId
    Subscription holding the resource bridge. Required for 'Onboarding' when -VCenterId is absent.

.PARAMETER ResourceGroup
    Resource group holding the resource bridge. Required for 'Onboarding' when -VCenterId is absent.

.PARAMETER ApplianceName
    Name of the Microsoft.ResourceConnector/appliances (resource bridge) resource, if known.

.PARAMETER VmName
    One or more affected VM names as they appear in vCenter. Their inventory items, Arc machines
    and virtualMachineInstances are collected individually.

.PARAMETER ArcMachineId
    One or more Microsoft.HybridCompute/machines ARM IDs, for guest-agent or linking problems.

.PARAMETER VCenterAddress
    vCenter FQDN or IP, used for a TCP reachability probe from this workstation.

.PARAMETER KubeConfig
    Path to the Arc resource bridge kubeconfig. If omitted the script looks in the usual places.

.PARAMETER ApplianceVmIp
    IP address of the resource bridge appliance VM. Used for 'az arcappliance logs --ip' when no
    kubeconfig is available, and for a reachability probe.

.PARAMETER SinceHours
    How far back to pull pod logs, Kubernetes events and the Azure activity log. Default 24.

.PARAMETER IncidentId
    Support case or IcM number, recorded in the summary so the archive is self-identifying.

.PARAMETER OutDir
    Output directory. Defaults to .\arcvmware-logs-<timestamp> in the current directory.

.EXAMPLE
    # First-time onboarding is failing
    .\arcvmware-collect-logs.ps1 -Scenario Onboarding `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroup rg-arc -ApplianceName my-bridge -VCenterAddress vcenter.contoso.com

.EXAMPLE
    # Already onboarded, one VM is stuck
    .\arcvmware-collect-logs.ps1 -Scenario Onboarded `
        -VCenterId "/subscriptions/0000.../resourceGroups/rg-arc/providers/Microsoft.ConnectedVMwarevSphere/VCenters/my-vcenter" `
        -VmName "app-server-01" -SinceHours 48 -IncidentId 123456789
#>

param(
    # Which of the two collection profiles to run.
    [Parameter(Mandatory = $false)][ValidateSet('Onboarding', 'Onboarded')][string]$Scenario = 'Onboarded',

    # ARM ID of the connected vCenter - the single input that resolves everything else.
    [Parameter(Mandatory = $false)][string]$VCenterId,

    # Subscription and resource group of the resource bridge, for when the vCenter does not exist yet.
    [Parameter(Mandatory = $false)][string]$SubscriptionId,
    [Parameter(Mandatory = $false)][string]$ResourceGroup,
    [Parameter(Mandatory = $false)][string]$ApplianceName,

    # The specific resources the incident is about.
    [Parameter(Mandatory = $false)][string[]]$VmName = @(),
    [Parameter(Mandatory = $false)][string[]]$ArcMachineId = @(),

    # On-premises endpoints to probe.
    [Parameter(Mandatory = $false)][string]$VCenterAddress,
    [Parameter(Mandatory = $false)][string]$ApplianceVmIp,

    # Where the appliance kubeconfig lives, if it is not in a default location.
    [Parameter(Mandatory = $false)][string]$KubeConfig,

    # Look-back window for pod logs, Kubernetes events and the Azure activity log.
    [Parameter(Mandatory = $false)][int]$SinceHours = 24,

    # Case or IcM identifier, written into the summary.
    [Parameter(Mandatory = $false)][string]$IncidentId,

    # Output location and opt-outs.
    [Parameter(Mandatory = $false)][string]$OutDir,
    [Parameter(Mandatory = $false)][switch]$SkipAzure,
    [Parameter(Mandatory = $false)][switch]$SkipApplianceLogs,
    [Parameter(Mandatory = $false)][switch]$SkipClusterDump,
    [Parameter(Mandatory = $false)][switch]$NoArchive
)

# Individual collection steps are expected to fail - a missing resource bridge is itself a finding.
# Each step is wrapped and recorded, so the script must not abort on the first error.
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Output layout
# ---------------------------------------------------------------------------

$startedUtc = (Get-Date).ToUniversalTime()
$stamp = $startedUtc.ToString('yyyyMMdd-HHmmss')

if (-not $OutDir) { $OutDir = Join-Path (Get-Location).Path "arcvmware-logs-$stamp" }
$null = New-Item -ItemType Directory -Force -Path $OutDir

# One folder per data source, numbered so the order of investigation is obvious in the archive.
$dirs = [ordered]@{
    Workstation = '01-workstation'
    Azure       = '02-azure'
    Appliance   = '03-appliance'
    Cluster     = '04-cluster'
}
foreach ($d in $dirs.Values) { $null = New-Item -ItemType Directory -Force -Path (Join-Path $OutDir $d) }

# Every step appends an entry here; the manifest is what tells the engineer what is missing and why.
$script:Manifest = New-Object System.Collections.ArrayList

# Facts discovered along the way that belong in the IcM summary.
$script:Facts = [ordered]@{}

function Write-Banner {
    param([string]$Text)
    Write-Host ""
    Write-Host "=== $Text ===" -ForegroundColor Cyan
}

function Write-Step {
    param([string]$Text)
    Write-Host "  - $Text" -ForegroundColor Gray
}

# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

# Applied to every byte this script writes. The goal is that the archive can be handed to
# Microsoft support over a normal case attachment without leaking a credential.
function Protect-Secret {
    param([string]$Text)

    if ([string]::IsNullOrEmpty($Text)) { return $Text }

    # Named sensitive fields in JSON, YAML, env-var dumps and connection strings.
    $sensitiveKey = 'password|passwd|pwd|secret|clientsecret|client_secret|token|accesskey|account_key|accountkey|sharedkey|shared_key|apikey|api_key|credential|privatekey|private_key|sshprivatekey|sas|connectionstring|bootstrapkey'
    $Text = [regex]::Replace($Text, "(?im)^(\s*[""']?(?:$sensitiveKey)[""']?\s*[:=]\s*)(?!null\b)(.+)$", '$1<redacted>')
    $Text = [regex]::Replace($Text, "(?i)([""'](?:$sensitiveKey)[""']\s*:\s*)(""[^""]*"")", '$1"<redacted>"')

    # Credentials embedded in a proxy or repository URL.
    $Text = [regex]::Replace($Text, '(?i)(https?|ftp)://[^:/\s]+:[^@/\s]+@', '$1://<redacted>:<redacted>@')

    # Bearer tokens and raw JWTs.
    $Text = [regex]::Replace($Text, '(?i)bearer\s+[A-Za-z0-9._\-]{20,}', 'Bearer <redacted>')
    $Text = [regex]::Replace($Text, 'eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]*', '<redacted-jwt>')

    # PEM-encoded private keys, however they are wrapped.
    $Text = [regex]::Replace($Text, '(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----', '<redacted-private-key>')

    return $Text
}

# ---------------------------------------------------------------------------
# Step execution
# ---------------------------------------------------------------------------

# Runs one collection step, writes its (redacted) output to a file, and records the outcome.
# A failing step is data too: "az arcappliance show returned ResourceNotFound" is often the answer.
function Invoke-Collect {
    param(
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$FileName,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][scriptblock]$Script
    )

    Write-Step $Description
    $path = Join-Path (Join-Path $OutDir $dirs[$Section]) $FileName
    $status = 'Collected'
    $detail = ''

    try {
        # Native commands write warnings to stderr even when they succeed, so merge and judge by
        # the exit code rather than by the presence of stderr text.
        $output = & $Script 2>&1
        $exitCode = $LASTEXITCODE

        $text = ($output | Out-String)
        if ([string]::IsNullOrWhiteSpace($text)) {
            $text = "(no output)"
            $status = 'Empty'
        }

        if ($null -ne $exitCode -and $exitCode -ne 0) {
            $status = 'Failed'
            $detail = "exit code $exitCode"
        }

        Set-Content -Path $path -Value (Protect-Secret $text) -Encoding UTF8
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
        Set-Content -Path $path -Value (Protect-Secret "ERROR: $($_.Exception.Message)") -Encoding UTF8
    }

    $null = $script:Manifest.Add([pscustomobject]@{
            Section     = $dirs[$Section]
            File        = $FileName
            Description = $Description
            Status      = $status
            Detail      = $detail
        })

    # Reset so the next step's check is not confused by this one's exit code.
    $global:LASTEXITCODE = 0
}

# Copies an existing log file into the archive, redacting it on the way in.
function Copy-LogFile {
    param(
        [Parameter(Mandatory = $true)][string]$Section,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $false)][string]$FileName
    )

    if (-not $FileName) { $FileName = Split-Path $Path -Leaf }
    Write-Step $Description

    $target = Join-Path (Join-Path $OutDir $dirs[$Section]) $FileName
    $status = 'Collected'
    $detail = ''

    try {
        if (Test-Path $Path) {
            $content = Get-Content -Path $Path -Raw -ErrorAction Stop
            Set-Content -Path $target -Value (Protect-Secret $content) -Encoding UTF8
            $detail = "from $Path"
        }
        else {
            $status = 'Missing'
            $detail = "not found at $Path"
        }
    }
    catch {
        $status = 'Failed'
        $detail = $_.Exception.Message
    }

    $null = $script:Manifest.Add([pscustomobject]@{
            Section     = $dirs[$Section]
            File        = $FileName
            Description = $Description
            Status      = $status
            Detail      = $detail
        })
}

# Runs 'az' without letting its stderr chatter abort the step, and returns stdout.
function Invoke-Az {
    # Capture the arguments before entering the child scope: a nested scriptblock has its own
    # empty $args, so splatting $args directly inside it would call 'az' with no arguments.
    $azArgs = $args
    $azOutput = & { $ErrorActionPreference = 'Continue'; & az @azArgs 2>&1 }
    $azExitCode = $LASTEXITCODE
    $azStdOut = @($azOutput | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
    if ($azExitCode -ne 0) {
        # Surface the failure text - a NotFound or an RBAC denial is itself the diagnostic.
        $azOutput | Out-String
    }
    else {
        $azStdOut
    }
    $global:LASTEXITCODE = $azExitCode
}

# Runs kubectl against the appliance kubeconfig with a short timeout so an unreachable
# API server fails fast instead of hanging the whole collection.
function Invoke-Kubectl {
    $kubeArgs = @()
    if ($script:ResolvedKubeConfig) { $kubeArgs += @('--kubeconfig', $script:ResolvedKubeConfig) }
    $kubeArgs += @('--request-timeout', '60s')
    $kubeArgs += $args
    & { $ErrorActionPreference = 'Continue'; & kubectl @kubeArgs 2>&1 }
}

function Test-Command {
    param([string]$Name)
    return [bool](Get-Command $Name -ErrorAction SilentlyContinue)
}

# TCP reachability probe that works on Windows PowerShell and on PowerShell 7 on any OS.
function Test-TcpEndpoint {
    param(
        [Parameter(Mandatory = $true)][string]$ComputerName,
        [Parameter(Mandatory = $false)][int]$Port = 443,
        [Parameter(Mandatory = $false)][int]$TimeoutMs = 5000
    )

    $result = [ordered]@{
        Endpoint   = "$ComputerName`:$Port"
        Resolved   = $false
        Addresses  = ''
        TcpConnect = $false
        Error      = ''
    }

    try {
        $addresses = [System.Net.Dns]::GetHostAddresses($ComputerName)
        $result.Resolved = $true
        $result.Addresses = ($addresses | ForEach-Object { $_.IPAddressToString }) -join ', '
    }
    catch {
        $result.Error = "DNS: $($_.Exception.Message)"
        return [pscustomobject]$result
    }

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($ComputerName, $Port, $null, $null)
        if ($async.AsyncWaitHandle.WaitOne($TimeoutMs, $false) -and $client.Connected) {
            $client.EndConnect($async)
            $result.TcpConnect = $true
        }
        else {
            $result.Error = "TCP connect timed out after $TimeoutMs ms"
        }
    }
    catch {
        $result.Error = "TCP: $($_.Exception.Message)"
    }
    finally {
        $client.Close()
    }

    return [pscustomobject]$result
}

# ---------------------------------------------------------------------------
# Start
# ---------------------------------------------------------------------------

Write-Host ""
Write-Host "Azure Arc-enabled VMware vSphere - diagnostic log collection" -ForegroundColor Green
Write-Host "Scenario : $Scenario"
Write-Host "Output   : $OutDir"
Write-Host "Read-only: this script does not create, modify or delete anything." -ForegroundColor Yellow

if ($Scenario -eq 'Onboarded' -and -not $VCenterId) {
    Write-Host "No -VCenterId supplied. Azure-side collection will be limited to what -SubscriptionId/-ResourceGroup cover." -ForegroundColor Yellow
}

$script:Facts['CollectionStartedUtc'] = $startedUtc.ToString('u')
$script:Facts['Scenario'] = $Scenario
$script:Facts['IncidentId'] = $IncidentId
$script:Facts['CollectedFromHost'] = [System.Net.Dns]::GetHostName()

# ---------------------------------------------------------------------------
# 01 - Workstation
#
# For the onboarding scenario this is the whole story: the deployment runs from here, so the
# tool versions, the proxy configuration and the endpoint reachability are the evidence.
# None of it is visible to Microsoft from Azure.
# ---------------------------------------------------------------------------

Write-Banner "01 - Workstation"

Invoke-Collect -Section Workstation -FileName 'host.txt' -Description 'Host, OS and PowerShell version' -Script {
    "Hostname           : $([System.Net.Dns]::GetHostName())"
    "PowerShell version : $($PSVersionTable.PSVersion)"
    "PowerShell edition : $($PSVersionTable.PSEdition)"
    "OS                 : $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)"
    "Architecture       : $([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture)"
    "Local time         : $(Get-Date -Format 'u')"
    "UTC time           : $((Get-Date).ToUniversalTime().ToString('u'))"
    "Time zone          : $([System.TimeZoneInfo]::Local.Id)"
    "User               : $([System.Environment]::UserName)"
    "Current directory  : $((Get-Location).Path)"
}

# Clock skew on the deployment workstation breaks token acquisition and TLS, and is a recurring
# root cause for bridge deployment failures. Windows-only, and harmless when the service is off.
if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    Invoke-Collect -Section Workstation -FileName 'time-sync.txt' -Description 'Windows time service status' -Script {
        & w32tm /query /status
    }
}

Invoke-Collect -Section Workstation -FileName 'proxy-env.txt' -Description 'Proxy environment variables' -Script {
    $names = @('HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy', 'REQUESTS_CA_BUNDLE', 'SSL_CERT_FILE', 'CURL_CA_BUNDLE')
    foreach ($n in $names) {
        $v = [System.Environment]::GetEnvironmentVariable($n)
        if ($v) { "$n = $v" } else { "$n = (not set)" }
    }
}

Invoke-Collect -Section Workstation -FileName 'tooling.txt' -Description 'az, kubectl and helm presence' -Script {
    foreach ($tool in @('az', 'kubectl', 'helm', 'ssh')) {
        $cmd = Get-Command $tool -ErrorAction SilentlyContinue
        if ($cmd) { "$tool : $($cmd.Source)" } else { "$tool : NOT FOUND on PATH" }
    }
}

if (Test-Command 'az') {
    # The az CLI core version and, more importantly, the connectedvmware / arcappliance / k8s-extension
    # extension versions. Several known failures are "extension is too old" and nothing else.
    Invoke-Collect -Section Workstation -FileName 'az-version.txt' -Description 'Azure CLI and extension versions' -Script { Invoke-Az version }
    Invoke-Collect -Section Workstation -FileName 'az-extensions.txt' -Description 'Installed az extensions' -Script { Invoke-Az extension list -o table }
}
else {
    Write-Host "  ! Azure CLI not found - Azure and appliance collection will be skipped." -ForegroundColor Yellow
    $SkipAzure = $true
    $SkipApplianceLogs = $true
}

if (Test-Command 'kubectl') {
    Invoke-Collect -Section Workstation -FileName 'kubectl-version.txt' -Description 'kubectl client version' -Script { & kubectl version --client }
}

# ---------------------------------------------------------------------------
# Resolve the identifiers we were given into the ones we need.
# ---------------------------------------------------------------------------

$script:Region = $null
$script:CustomLocationId = $null
$script:ApplianceId = $null

if ($VCenterId) {
    $m = [regex]::Match($VCenterId.TrimEnd('/'),
        '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/providers/Microsoft\.ConnectedVMwarevSphere/vCenters/([^/]+)$')
    if ($m.Success) {
        if (-not $SubscriptionId) { $SubscriptionId = $m.Groups[1].Value }
        if (-not $ResourceGroup) { $ResourceGroup = $m.Groups[2].Value }
        $script:Facts['VCenterName'] = $m.Groups[3].Value
    }
    else {
        Write-Host "  ! -VCenterId is not a valid vCenter ARM ID; continuing without it." -ForegroundColor Yellow
    }
}

$script:Facts['SubscriptionId'] = $SubscriptionId
$script:Facts['ResourceGroup'] = $ResourceGroup
$script:Facts['VCenterId'] = $VCenterId

# ---------------------------------------------------------------------------
# 02 - Azure resource state
#
# Items 1-3 of the data-collection checklist: subscription IDs, resource IDs and provisioning
# state for the vCenter, the resource bridge, the custom location and each affected VM. Support
# can read these themselves only if they are given the IDs, which is the single most common
# reason an IcM goes back to the submitter.
# ---------------------------------------------------------------------------

if (-not $SkipAzure) {
    Write-Banner "02 - Azure resource state"

    Invoke-Collect -Section Azure -FileName 'account.txt' -Description 'Signed-in account, tenant and subscription' -Script {
        Invoke-Az account show -o json
    }

    if ($SubscriptionId) {
        # Setting the subscription is a client-side context change only; nothing in Azure is modified.
        $null = Invoke-Az account set -s $SubscriptionId
    }

    # An unregistered resource provider is a self-inflicted onboarding failure with a confusing error.
    Invoke-Collect -Section Azure -FileName 'provider-registration.txt' -Description 'Resource provider registration state' -Script {
        foreach ($rp in @('Microsoft.ConnectedVMwarevSphere', 'Microsoft.ResourceConnector', 'Microsoft.ExtendedLocation',
                'Microsoft.KubernetesConfiguration', 'Microsoft.HybridCompute', 'Microsoft.GuestConfiguration',
                'Microsoft.HybridConnectivity', 'Microsoft.Kubernetes')) {
            $state = (Invoke-Az provider show -n $rp --query registrationState -o tsv | Out-String).Trim()
            "{0,-42} {1}" -f $rp, $state
        }
    }

    if ($ResourceGroup) {
        # The flat resource list shows what actually exists, including a half-created bridge or a
        # custom location whose cluster extension never came up.
        Invoke-Collect -Section Azure -FileName 'resource-group-contents.txt' -Description "Resources in '$ResourceGroup'" -Script {
            Invoke-Az resource list -g $ResourceGroup -o table
        }

        # The activity log is the only place that records who deleted the bridge, and when.
        Invoke-Collect -Section Azure -FileName 'activity-log.json' -Description "Activity log for '$ResourceGroup' (last $SinceHours h)" -Script {
            $start = (Get-Date).ToUniversalTime().AddHours(-$SinceHours).ToString('yyyy-MM-ddTHH:mm:ssZ')
            Invoke-Az monitor activity-log list -g $ResourceGroup --start-time $start `
                --query "[].{time:eventTimestamp,caller:caller,op:operationName.value,status:status.value,sub:subStatus.value,res:resourceId,msg:properties.statusMessage}" -o json
        }
    }

    if ($VCenterId) {
        # Provisioning state plus connection status - the two fields that say whether the RP can
        # still talk to this vCenter at all.
        Invoke-Collect -Section Azure -FileName 'vcenter.json' -Description 'vCenter ARM resource' -Script {
            Invoke-Az resource show --ids $VCenterId -o json
        }

        # Inventory items are not in any Azure-side log. For a stale-link or missing-VM symptom this
        # file is the evidence: it carries moRefId, managedResourceId and the inventory item's state.
        Invoke-Collect -Section Azure -FileName 'inventory-items.json' -Description 'vCenter inventory items' -Script {
            Invoke-Az rest --method get --url "https://management.azure.com$VCenterId/inventoryItems?api-version=2023-12-01"
        }

        # Follow the vCenter's extendedLocation to the custom location. It is routinely in a
        # different resource group - and even a different subscription - from the vCenter, so
        # searching the vCenter's own resource group for it finds nothing.
        $vcPath = Join-Path (Join-Path $OutDir $dirs.Azure) 'vcenter.json'
        if (Test-Path $vcPath) {
            try {
                $vcObj = Get-Content $vcPath -Raw | ConvertFrom-Json
                if ($vcObj.location) { $script:Region = $vcObj.location }
                if ($vcObj.extendedLocation -and $vcObj.extendedLocation.name) {
                    $script:CustomLocationId = $vcObj.extendedLocation.name
                }
                $script:Facts['VCenterProvisioningState'] = $vcObj.properties.provisioningState
                $script:Facts['VCenterConnectionStatus'] = $vcObj.properties.connectionStatus
            }
            catch { }
        }
    }

    # The custom location, and through it the connected cluster that hosts the operator.
    Invoke-Collect -Section Azure -FileName 'custom-location.json' -Description 'Custom location and its enabled resource types' -Script {
        if ($script:CustomLocationId) {
            "### custom location"
            Invoke-Az resource show --ids $script:CustomLocationId -o json
            "### enabled resource types (names the cluster extension backing this custom location)"
            Invoke-Az rest --method get --url "https://management.azure.com$($script:CustomLocationId)/enabledResourceTypes?api-version=2021-08-31"
        }
        elseif ($ResourceGroup) {
            "### no extendedLocation on the vCenter - listing custom locations in '$ResourceGroup'"
            Invoke-Az customlocation list -g $ResourceGroup -o json
        }
        else {
            Invoke-Az customlocation list -o json
        }
    }

    # Resolve the connected cluster from the custom location's hostResourceId, which also gives us
    # the resource group the resource bridge actually lives in.
    $script:HostClusterId = $null
    $clPath = Join-Path (Join-Path $OutDir $dirs.Azure) 'custom-location.json'
    if (Test-Path $clPath) {
        $clText = Get-Content $clPath -Raw
        $hostMatch = [regex]::Match($clText, '(?i)"hostResourceId"\s*:\s*"([^"]+)"')
        if ($hostMatch.Success) {
            $script:HostClusterId = $hostMatch.Groups[1].Value
            $script:Facts['HostConnectedClusterId'] = $script:HostClusterId
        }
    }

    Invoke-Collect -Section Azure -FileName 'appliance.json' -Description 'Arc resource bridge (appliance) resource' -Script {
        if ($ApplianceName -and $ResourceGroup) {
            Invoke-Az arcappliance show --resource-group $ResourceGroup --name $ApplianceName -o json
        }
        else {
            # The bridge sits in the same resource group as the connected cluster that hosts the
            # custom location, which is not necessarily the vCenter's resource group.
            $bridgeRg = $ResourceGroup
            $bridgeSub = $SubscriptionId
            if ($script:HostClusterId) {
                $hm = [regex]::Match($script:HostClusterId, '(?i)^/subscriptions/([^/]+)/resourceGroups/([^/]+)/')
                if ($hm.Success) { $bridgeSub = $hm.Groups[1].Value; $bridgeRg = $hm.Groups[2].Value }
            }
            if ($bridgeRg) {
                "### appliances in resource group '$bridgeRg' (subscription $bridgeSub)"
                Invoke-Az resource list -g $bridgeRg --subscription $bridgeSub --resource-type 'Microsoft.ResourceConnector/appliances' -o json
            }
            else {
                Invoke-Az resource list --resource-type 'Microsoft.ResourceConnector/appliances' -o json
            }
        }
    }

    # The cluster extension carries the deployed operator version and its own provisioning state;
    # a failed extension upgrade looks like "everything is fine but nothing works".
    Invoke-Collect -Section Azure -FileName 'cluster-extensions.json' -Description 'Cluster extensions on the connected cluster' -Script {
        # The custom location names its backing extensions explicitly - prefer that over guessing.
        $extensionIds = @()
        if (Test-Path $clPath) {
            foreach ($mm in [regex]::Matches((Get-Content $clPath -Raw), '(?i)"(/subscriptions/[^"]+/providers/Microsoft\.KubernetesConfiguration/extensions/[^"]+)"')) {
                $extensionIds += $mm.Groups[1].Value
            }
        }

        if ($extensionIds.Count -gt 0) {
            foreach ($extId in ($extensionIds | Select-Object -Unique)) {
                "### $extId"
                Invoke-Az resource show --ids $extId -o json
            }
        }
        elseif ($script:HostClusterId) {
            Invoke-Az rest --method get --url "https://management.azure.com$($script:HostClusterId)/providers/Microsoft.KubernetesConfiguration/extensions?api-version=2023-05-01"
        }
        elseif ($ResourceGroup) {
            $clusters = Invoke-Az resource list -g $ResourceGroup --resource-type 'Microsoft.Kubernetes/connectedClusters' --query "[].name" -o tsv
            foreach ($c in $clusters) {
                "### connectedCluster: $c"
                Invoke-Az k8s-extension list --cluster-name $c --cluster-type connectedClusters -g $ResourceGroup -o json
            }
        }
        else {
            "SKIPPED: no connected cluster could be resolved."
        }
    }

    # Per-VM detail for the VMs the incident is actually about.
    if ($VmName -and $VCenterId) {
        foreach ($vm in $VmName) {
            $safe = ($vm -replace '[^A-Za-z0-9._-]', '_')
            Invoke-Collect -Section Azure -FileName "vm-$safe.json" -Description "Arc machine and VM instance for '$vm'" -Script {
                "### Microsoft.HybridCompute/machines matching the name"
                Invoke-Az resource list --resource-type 'Microsoft.HybridCompute/machines' --name $vm -o json
                "### virtualMachineInstances/default"
                $machineIds = Invoke-Az resource list --resource-type 'Microsoft.HybridCompute/machines' --name $vm --query "[].id" -o tsv
                foreach ($id in $machineIds) {
                    "## $id"
                    Invoke-Az rest --method get --url "https://management.azure.com$id/providers/Microsoft.ConnectedVMwarevSphere/virtualMachineInstances/default?api-version=2023-12-01"
                    "## extensions"
                    Invoke-Az rest --method get --url "https://management.azure.com$id/extensions?api-version=2024-07-10"
                }
            }
        }
    }

    foreach ($machineId in $ArcMachineId) {
        $safe = (($machineId -split '/')[-1] -replace '[^A-Za-z0-9._-]', '_')
        Invoke-Collect -Section Azure -FileName "machine-$safe.json" -Description "Arc machine '$safe'" -Script {
            "### machine"
            Invoke-Az resource show --ids $machineId -o json
            "### virtualMachineInstances/default"
            Invoke-Az rest --method get --url "https://management.azure.com$machineId/providers/Microsoft.ConnectedVMwarevSphere/virtualMachineInstances/default?api-version=2023-12-01"
            "### extensions"
            Invoke-Az rest --method get --url "https://management.azure.com$machineId/extensions?api-version=2024-07-10"
        }
    }
}

# ---------------------------------------------------------------------------
# Endpoint reachability
#
# Done after the Azure section so the region can be taken from the resources when it is known.
# A blocked endpoint is the most common onboarding failure and it can only be observed from
# inside the customer's network.
# ---------------------------------------------------------------------------

Write-Banner "01 - Network reachability"

# Pull the region out of whatever ARM resource we managed to read, if the vCenter step did not
# already provide it.
$vcenterJsonPath = Join-Path (Join-Path $OutDir $dirs.Azure) 'vcenter.json'
if (-not $script:Region -and (Test-Path $vcenterJsonPath)) {
    try {
        $vcenterObj = Get-Content $vcenterJsonPath -Raw | ConvertFrom-Json
        if ($vcenterObj.location) { $script:Region = $vcenterObj.location }
    }
    catch { }
}

Invoke-Collect -Section Workstation -FileName 'endpoint-reachability.txt' -Description 'DNS and TCP 443 to the required Azure endpoints' -Script {
    $targets = @(
        'management.azure.com',
        'login.microsoftonline.com',
        'login.windows.net',
        'graph.microsoft.com',
        'mcr.microsoft.com',
        'packages.microsoft.com',
        'gbl.his.arc.azure.com',
        'guestnotificationservice.azure.com',
        'azurearcfork8s.azurecr.io',
        'ecpacr.azurecr.io',
        'linuxgeneva-microsoft.azurecr.io'
    )
    if ($script:Region) {
        $targets += "$($script:Region).dp.kubernetesconfiguration.azure.com"
        $targets += "$($script:Region).his.arc.azure.com"
        $targets += "$($script:Region).obo.arc.azure.com"
    }
    else {
        "NOTE: region unknown - the regional endpoints (<region>.dp.kubernetesconfiguration.azure.com,"
        "      <region>.his.arc.azure.com, <region>.obo.arc.azure.com) were NOT probed."
        ""
    }

    "The authoritative endpoint list is in the public documentation; this probe covers the common ones."
    ""
    $results = foreach ($t in $targets) { Test-TcpEndpoint -ComputerName $t -Port 443 }
    $results | Format-Table -AutoSize | Out-String -Width 220
}

if ($VCenterAddress -or $ApplianceVmIp) {
    Invoke-Collect -Section Workstation -FileName 'onprem-reachability.txt' -Description 'Reachability of vCenter and the appliance VM' -Script {
        $results = @()
        if ($VCenterAddress) { $results += Test-TcpEndpoint -ComputerName $VCenterAddress -Port 443 }
        if ($ApplianceVmIp) {
            $results += Test-TcpEndpoint -ComputerName $ApplianceVmIp -Port 443
            $results += Test-TcpEndpoint -ComputerName $ApplianceVmIp -Port 22
            $results += Test-TcpEndpoint -ComputerName $ApplianceVmIp -Port 6443
        }
        $results | Format-Table -AutoSize | Out-String -Width 220
    }
}

# ---------------------------------------------------------------------------
# 03 - Arc resource bridge (appliance)
#
# kva.log and the onboarding script log live only on this workstation. The appliance log bundle
# is the only view into the appliance VM itself, and it is what distinguishes "the bridge is
# broken" from "VMware refused the request".
# ---------------------------------------------------------------------------

Write-Banner "03 - Arc resource bridge"

# kva.log - written by the appliance CLI on this machine during every deployment and day-2 operation.
$kvaLog = if ($IsWindows -or $env:OS -eq 'Windows_NT') {
    $programData = $env:ProgramData; if (-not $programData) { $programData = 'C:\ProgramData' }
    Join-Path (Join-Path $programData 'kva') 'kva.log'
}
else {
    Join-Path (Join-Path $HOME '.kva') 'kva.log'
}
Copy-LogFile -Section Appliance -Path $kvaLog -Description 'kva.log (appliance CLI log)'

# The onboarding script writes this next to itself; check the usual spots.
foreach ($candidate in @(
        (Join-Path (Get-Location).Path 'arcvmware-output.log'),
        (Join-Path $HOME 'arcvmware-output.log'))) {
    if (Test-Path $candidate) {
        Copy-LogFile -Section Appliance -Path $candidate -Description 'arcvmware-setup onboarding script log'
        break
    }
}

# Locate the appliance kubeconfig. Without it neither 'az arcappliance logs' nor the cluster dump
# can run, and saying so explicitly saves a round trip.
$script:ResolvedKubeConfig = $null
$kubeCandidates = @()
if ($KubeConfig) { $kubeCandidates += $KubeConfig }
if ($ApplianceName) {
    $kubeCandidates += (Join-Path (Get-Location).Path "$ApplianceName-appliance.kubeconfig")
    $kubeCandidates += (Join-Path (Get-Location).Path "$ApplianceName.kubeconfig")
}
# 'az arcappliance get-credentials' writes the kubeconfig into the working directory.
$kubeCandidates += (Join-Path (Get-Location).Path 'kubeconfig')
$kubeCandidates += @(Get-ChildItem -Path (Get-Location).Path -Filter '*kubeconfig*' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })

# $HOME/.kube/config is deliberately NOT a candidate: on most workstations it points at an
# unrelated cluster, and dumping the wrong cluster is both useless and a privacy problem.
# If the appliance kubeconfig lives there, pass it explicitly with -KubeConfig.
foreach ($c in $kubeCandidates) {
    if ($c -and (Test-Path $c)) { $script:ResolvedKubeConfig = (Resolve-Path $c).Path; break }
}

if ($script:ResolvedKubeConfig) {
    Write-Host "  kubeconfig: $($script:ResolvedKubeConfig)" -ForegroundColor Gray
}
else {
    Write-Host "  ! No appliance kubeconfig found in the current directory." -ForegroundColor Yellow
    Write-Host "    Pass -KubeConfig <path> (the file 'az arcappliance get-credentials' wrote), or" -ForegroundColor Yellow
    Write-Host "    -ApplianceVmIp <ip> to still collect the appliance log bundle." -ForegroundColor Yellow
}
$script:Facts['KubeConfig'] = $script:ResolvedKubeConfig

# The appliance YAML configs record how the bridge was deployed: vCenter address, datastore,
# network, static IPs and the control-plane IP. They are frequently the whole answer for a
# deployment failure. They contain the vCenter username, so they go through redaction.
foreach ($suffix in @('appliance', 'infra', 'resource')) {
    $pattern = if ($ApplianceName) { "$ApplianceName-$suffix.yaml" } else { "*-$suffix.yaml" }
    Get-ChildItem -Path (Get-Location).Path -Filter $pattern -ErrorAction SilentlyContinue | ForEach-Object {
        Copy-LogFile -Section Appliance -Path $_.FullName -Description "Appliance config $($_.Name)"
    }
}

if (-not $SkipApplianceLogs -and (Test-Command 'az')) {
    # 'az arcappliance logs' SSHes into the appliance VM and pulls its service logs. It needs the
    # log key under $HOME/.kva/.ssh, which exists only on the deployment machine.
    $applianceLogDir = Join-Path (Join-Path $OutDir $dirs.Appliance) 'appliance-log-bundle'
    $null = New-Item -ItemType Directory -Force -Path $applianceLogDir

    Invoke-Collect -Section Appliance -FileName 'arcappliance-logs.txt' -Description 'az arcappliance logs (appliance VM log bundle)' -Script {
        if ($script:ResolvedKubeConfig) {
            Invoke-Az arcappliance logs vmware --kubeconfig $script:ResolvedKubeConfig --out-dir $applianceLogDir
        }
        elseif ($ApplianceVmIp) {
            Invoke-Az arcappliance logs vmware --ip $ApplianceVmIp --out-dir $applianceLogDir
        }
        else {
            "SKIPPED: neither a kubeconfig nor -ApplianceVmIp was available."
            "Run: az arcappliance logs vmware --kubeconfig <path> --out-dir <dir>"
            "  or az arcappliance logs vmware --ip <appliance-vm-ip> --out-dir <dir>"
            "This must be run from the machine the bridge was deployed from - the SSH key in"
            "`$HOME/.kva/.ssh (logkey, logkey.pub) is required, and remote PowerShell is not supported."
        }
    }
}

# ---------------------------------------------------------------------------
# 04 - Resource bridge Kubernetes cluster
#
# Everything in this section is invisible to Azure-side telemetry. The custom resources carry the
# operator's state machine state, phase, task info and conditions - which is where the real error
# text lives - and the previous container log is the only record of a crash or an OOMKill.
# ---------------------------------------------------------------------------

if (-not $SkipClusterDump -and (Test-Command 'kubectl') -and $script:ResolvedKubeConfig) {
    Write-Banner "04 - Resource bridge cluster"

    Invoke-Collect -Section Cluster -FileName 'cluster-info.txt' -Description 'Cluster version and nodes' -Script {
        "### kubectl version"
        Invoke-Kubectl version
        "### nodes"
        Invoke-Kubectl get nodes -o wide
        "### node conditions"
        Invoke-Kubectl describe nodes
    }

    Invoke-Collect -Section Cluster -FileName 'pods-all-namespaces.txt' -Description 'All pods, all namespaces' -Script {
        Invoke-Kubectl get pods -A -o wide
    }

    # Events expire from the cluster after an hour by default, so this is a genuinely perishable
    # artifact - it is the reason to run this script early rather than after the next round trip.
    Invoke-Collect -Section Cluster -FileName 'events-all-namespaces.txt' -Description 'Kubernetes events (perishable - default TTL is 1 hour)' -Script {
        Invoke-Kubectl get events -A --sort-by=.lastTimestamp
    }

    # Secret names and types only. Their contents are never written to the archive.
    Invoke-Collect -Section Cluster -FileName 'secrets-inventory.txt' -Description 'Secret names and types (no contents)' -Script {
        Invoke-Kubectl get secrets -A -o 'custom-columns=NAMESPACE:.metadata.namespace,NAME:.metadata.name,TYPE:.type,AGE:.metadata.creationTimestamp'
    }

    # Find the operator the same way the resource provider does: by its control-plane label,
    # because the namespace is the cluster extension's install namespace and is not fixed.
    $operatorPods = @()
    try {
        $podLine = Invoke-Kubectl get pods -A -l control-plane=vmware-operator -o 'jsonpath={range .items[*]}{.metadata.namespace}{" "}{.metadata.name}{"\n"}{end}'
        $operatorPods = @(($podLine | Out-String) -split "`n" | Where-Object { $_.Trim() })
    }
    catch { }

    if ($operatorPods.Count -eq 0) {
        Write-Host "  ! No pod with label control-plane=vmware-operator found. The operator extension may not be installed." -ForegroundColor Yellow
        $null = $script:Manifest.Add([pscustomobject]@{
                Section = $dirs.Cluster; File = '(none)'
                Description = 'VMware operator pod'; Status = 'Missing'
                Detail = 'No pod matched label control-plane=vmware-operator'
            })
    }

    foreach ($entry in $operatorPods) {
        $parts = $entry.Trim() -split '\s+'
        $ns = $parts[0]
        $pod = $parts[1]
        $safePod = ($pod -replace '[^A-Za-z0-9._-]', '_')

        Write-Host "  operator pod: $ns/$pod" -ForegroundColor Gray
        $script:Facts['OperatorPod'] = "$ns/$pod"

        # The deployment spec carries the container image tag, which is the deployed operator version.
        Invoke-Collect -Section Cluster -FileName "operator-deployment-$ns.yaml" -Description "Operator deployment in '$ns' (image tag = operator version)" -Script {
            Invoke-Kubectl get deployment -n $ns -l control-plane=vmware-operator -o yaml
        }

        # Describe shows restart counts, OOMKills, image pull failures and the scheduling history.
        Invoke-Collect -Section Cluster -FileName "operator-pod-describe-$safePod.txt" -Description "Describe operator pod '$pod'" -Script {
            Invoke-Kubectl describe pod -n $ns $pod
        }

        # Current logs for every container. The resource provider only ever ships the
        # 'vmware-operator' container, so the sidecars are collected nowhere else.
        Invoke-Collect -Section Cluster -FileName "operator-logs-$safePod.log" -Description "Operator logs, all containers, last $SinceHours h" -Script {
            Invoke-Kubectl logs -n $ns $pod --all-containers=true --timestamps=true --since="${SinceHours}h"
        }

        # The previous container instance. This is the unique value of running this script: after a
        # crash or an OOMKill, the log explaining it is gone from Azure-side telemetry entirely.
        Invoke-Collect -Section Cluster -FileName "operator-logs-previous-$safePod.log" -Description "Operator logs from the PREVIOUS container instance (crash evidence)" -Script {
            Invoke-Kubectl logs -n $ns $pod --all-containers=true --timestamps=true --previous
        }
    }

    # The Arc agents that connect this cluster to Azure. When they are unhealthy the resource
    # provider cannot reach the operator at all, and so collects nothing.
    Invoke-Collect -Section Cluster -FileName 'azure-arc-agents.txt' -Description 'azure-arc namespace pods and recent logs' -Script {
        "### pods"
        Invoke-Kubectl get pods -n azure-arc -o wide
        ""
        $names = (Invoke-Kubectl get pods -n azure-arc -o 'jsonpath={range .items[*]}{.metadata.name}{"\n"}{end}' | Out-String) -split "`n" | Where-Object { $_.Trim() }
        foreach ($p in $names) {
            "### logs: $($p.Trim()) (last 200 lines)"
            Invoke-Kubectl logs -n azure-arc $p.Trim() --all-containers=true --tail=200
            ""
        }
    }

    # ---------------------------------------------------------------------------
    # Custom resources
    #
    # The operator is a state machine and its state lives here: status.state, the current phase,
    # taskInfo and conditions, with the verbatim vCenter error. None of this is sent to Azure.
    # The resource kinds are discovered rather than hard-coded, so the dump stays correct as the
    # CRD set changes.
    # ---------------------------------------------------------------------------

    $crDir = Join-Path (Join-Path $OutDir $dirs.Cluster) 'custom-resources'
    $null = New-Item -ItemType Directory -Force -Path $crDir

    $apiGroup = 'vsphere.vmware.microsoft.com'
    $resourceTypes = @()
    try {
        $raw = Invoke-Kubectl api-resources --api-group=$apiGroup -o name
        $resourceTypes = @(($raw | Out-String) -split "`n" | Where-Object { $_.Trim() -and $_ -notmatch 'error|Error' } | ForEach-Object { $_.Trim() })
    }
    catch { }

    if ($resourceTypes.Count -eq 0) {
        Write-Host "  ! No $apiGroup resources found - the operator CRDs are not installed on this cluster." -ForegroundColor Yellow
        $null = $script:Manifest.Add([pscustomobject]@{
                Section = $dirs.Cluster; File = 'custom-resources/'
                Description = "Custom resources in $apiGroup"; Status = 'Missing'
                Detail = 'kubectl api-resources returned nothing for the group'
            })
    }

    # A single overview table first, so the engineer can see every resource and its state at a glance.
    Invoke-Collect -Section Cluster -FileName 'custom-resources-overview.txt' -Description 'All VMware custom resources, summary table' -Script {
        foreach ($rt in $resourceTypes) {
            "### $rt"
            Invoke-Kubectl get $rt -A
            ""
        }
    }

    foreach ($rt in $resourceTypes) {
        $safeRt = ($rt -replace '[^A-Za-z0-9._-]', '_')
        Write-Step "Custom resource dump: $rt"
        $crPath = Join-Path $crDir "$safeRt.yaml"
        try {
            $yaml = (Invoke-Kubectl get $rt -A -o yaml | Out-String)
            Set-Content -Path $crPath -Value (Protect-Secret $yaml) -Encoding UTF8
            $null = $script:Manifest.Add([pscustomobject]@{
                    Section = "$($dirs.Cluster)/custom-resources"; File = "$safeRt.yaml"
                    Description = "Full body of $rt"; Status = 'Collected'; Detail = ''
                })
        }
        catch {
            $null = $script:Manifest.Add([pscustomobject]@{
                    Section = "$($dirs.Cluster)/custom-resources"; File = "$safeRt.yaml"
                    Description = "Full body of $rt"; Status = 'Failed'; Detail = $_.Exception.Message
                })
        }
    }

    # The CRD versions themselves, to confirm the operator and the CRDs are the same generation.
    Invoke-Collect -Section Cluster -FileName 'crds.txt' -Description 'Installed VMware CRDs and versions' -Script {
        Invoke-Kubectl get crd -o 'custom-columns=NAME:.metadata.name,CREATED:.metadata.creationTimestamp' | Select-String -Pattern 'vmware|vsphere'
    }
}
elseif (-not $SkipClusterDump) {
    Write-Banner "04 - Resource bridge cluster"
    $reason = if (-not (Test-Command 'kubectl')) { 'kubectl is not installed on this machine' } else { 'no appliance kubeconfig was found' }
    Write-Host "  ! Skipped: $reason." -ForegroundColor Yellow
    $null = $script:Manifest.Add([pscustomobject]@{
            Section = $dirs.Cluster; File = '(none)'
            Description = 'Cluster dump'; Status = 'Skipped'; Detail = $reason
        })
}

# ---------------------------------------------------------------------------
# Summary, manifest and archive
# ---------------------------------------------------------------------------

Write-Banner "Writing summary"

$manifestPath = Join-Path $OutDir 'manifest.json'
$script:Manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding UTF8

# The summary is written for the person who opens the archive: what was collected, what was not,
# and the identifiers that an IcM is useless without.
$summary = New-Object System.Text.StringBuilder
$null = $summary.AppendLine("# Arc-enabled VMware vSphere - diagnostic collection")
$null = $summary.AppendLine()
foreach ($k in $script:Facts.Keys) {
    $v = $script:Facts[$k]
    if ($v) { $null = $summary.AppendLine("- **$k**: $v") }
}
$null = $summary.AppendLine("- **CollectionFinishedUtc**: $((Get-Date).ToUniversalTime().ToString('u'))")
$null = $summary.AppendLine("- **LogWindowHours**: $SinceHours")
$null = $summary.AppendLine()

$null = $summary.AppendLine("## Collection results")
$null = $summary.AppendLine()
$null = $summary.AppendLine("| Section | File | What it is | Status | Detail |")
$null = $summary.AppendLine("|---|---|---|---|---|")
foreach ($row in $script:Manifest) {
    $null = $summary.AppendLine("| $($row.Section) | $($row.File) | $($row.Description) | $($row.Status) | $($row.Detail) |")
}
$null = $summary.AppendLine()

# These are the items the support and dev teams cannot obtain for themselves and which no script
# can read from this machine. Listing them here is what stops the IcM bouncing back.
$null = $summary.AppendLine("## Still needed from the customer - please fill in")
$null = $summary.AppendLine()
$null = $summary.AppendLine("1. **When** did it happen (date and time with time zone), and **what was the customer doing**?")
$null = $summary.AppendLine("2. **Verbatim error text** - copy the portal or CLI error as plain text, not a screenshot.")
$null = $summary.AppendLine("3. If a VM shows **""Action Needed""**, the exact message text.")
$null = $summary.AppendLine("4. Was **public guidance** followed to onboard or offboard? Which document or command?")
$null = $summary.AppendLine("5. Were the vCenter, custom location, resource bridge or VMs previously **deleted, turned off or modified**?")
$null = $summary.AppendLine("6. If ""migration"" was mentioned, what was actually done - bridge recreated under a new name, subscription or resource group? One bridge for several vCenters? Enhanced Linked Mode or vMotion?")
$null = $summary.AppendLine("7. Do the onboarded VM states **match what the customer sees in their own vCenter**?")
$null = $summary.AppendLine()
$null = $summary.AppendLine("### vCenter-side facts (read from the vSphere client)")
$null = $summary.AppendLine()
$null = $summary.AppendLine("- vCenter version and build, and the ESXi version of the affected hosts.")
$null = $summary.AppendLine("- The privileges held by the account the resource bridge uses.")
$null = $summary.AppendLine("- For an affected VM: its folder, resource pool, datastore, power state and VMware Tools status and version.")
$null = $summary.AppendLine()
$null = $summary.AppendLine("### Guest-agent problems")
$null = $summary.AppendLine()
$null = $summary.AppendLine("Guest agent installation and heartbeat logs live inside the guest VM, not on this machine. On the affected VM run ``azcmagent logs``, or collect:")
$null = $summary.AppendLine()
$null = $summary.AppendLine("- Windows: ``%ProgramData%\AzureConnectedMachineAgent\Log\himds.log`` and ``azcmagent.log``")
$null = $summary.AppendLine("- Linux: ``/var/opt/azcmagent/log/himds.log`` and ``/var/opt/azcmagent/log/azcmagent.log``")

Set-Content -Path (Join-Path $OutDir 'SUMMARY.md') -Value $summary.ToString() -Encoding UTF8

$collected = @($script:Manifest | Where-Object { $_.Status -eq 'Collected' }).Count
$problems = @($script:Manifest | Where-Object { $_.Status -in @('Failed', 'Missing', 'Skipped') }).Count

Write-Host ""
Write-Host "Collected $collected item(s); $problems item(s) missing, skipped or failed - see SUMMARY.md." -ForegroundColor Green

if (-not $NoArchive) {
    $zipPath = "$OutDir.zip"
    try {
        Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zipPath -Force
        Write-Host "Archive : $zipPath" -ForegroundColor Green
    }
    catch {
        Write-Host "Could not create the archive: $($_.Exception.Message). The folder is still at $OutDir." -ForegroundColor Yellow
    }
}

Write-Host "Folder  : $OutDir" -ForegroundColor Green
Write-Host ""
Write-Host "Review SUMMARY.md before sending - secrets are redacted automatically, but confirm the contents are acceptable to share." -ForegroundColor Yellow
