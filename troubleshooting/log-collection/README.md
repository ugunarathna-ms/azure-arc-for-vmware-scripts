# Diagnostic log collection for Azure Arc-enabled VMware vSphere

`arcvmware-collect-logs.ps1` gathers, into one redacted archive, the diagnostic data that a
Microsoft engineer **cannot obtain from Azure**. Run it on the customer's on-premises workstation
and attach the resulting `.zip` to the support case or the IcM.

The script is **read-only**. It never creates, updates or deletes anything in Azure, in Kubernetes,
or in VMware vCenter.

## Why this exists

Most of the Azure-side telemetry for this service is deliberately narrow:

| What the service sends to Azure | What it leaves behind |
|---|---|
| The `vmware-operator` container's log, for the duration of one workflow | Everything the operator logged outside that window |
| Often only the lines carrying the current correlation ID | Every other line, including the failure that preceded the request |
| Only the current container instance | The **previous** container log - the only record of a crash loop or an OOMKill |
| Nothing at all when the resource bridge or custom location is unreachable | The entire failure, which is usually exactly that state |
| Nothing during first-time onboarding, because no Azure resources exist yet | The onboarding script log, `kva.log`, proxy settings and endpoint reachability |
| No custom resource bodies | `status.state`, the current phase, `taskInfo` and `conditions` - where the verbatim vCenter error lives |

Everything in the right-hand column is on the customer's machine, their resource bridge, or their
network, and this script is how it reaches the engineer.

## Where to run it

On the **same machine the resource bridge was deployed from**. `az arcappliance logs` needs the SSH
key written to `$HOME/.kva/.ssh` (`logkey`, `logkey.pub`) during deployment, and the appliance
kubeconfig, both of which exist only on that machine.

`az arcappliance` commands are not supported over remote PowerShell. Use a console session or RDP.

### Prerequisites

| Tool | Needed for |
|---|---|
| PowerShell 5.1 or PowerShell 7+ | the script itself |
| Azure CLI, signed in (`az login`) | the Azure resource state and the appliance log bundle |
| `az` extensions `connectedvmware`, `arcappliance`, `k8s-extension`, `customlocation` | the same |
| `kubectl` | the resource bridge cluster dump |
| The appliance kubeconfig | the cluster dump and the appliance log bundle |

Anything missing is skipped and recorded in `SUMMARY.md` as missing, rather than failing the run.

## The two scenarios

### 1. First-time onboarding of a vCenter

Nothing exists in Azure yet, so there is no telemetry at all. The evidence is the workstation: tool
versions, proxy configuration, endpoint reachability, `kva.log`, the onboarding script log and the
appliance YAML configs.

```powershell
.\arcvmware-collect-logs.ps1 -Scenario Onboarding `
    -SubscriptionId 00000000-0000-0000-0000-000000000000 `
    -ResourceGroup rg-arc `
    -ApplianceName my-bridge `
    -VCenterAddress vcenter.contoso.com `
    -ApplianceVmIp 10.0.0.50
```

Run it **from the directory the onboarding script was run in**, so it finds
`arcvmware-output.log`, `<appliance>-appliance.yaml`, `<appliance>-infra.yaml`,
`<appliance>-resource.yaml` and the kubeconfig.

### 2. Already onboarded, something is failing

```powershell
.\arcvmware-collect-logs.ps1 -Scenario Onboarded `
    -VCenterId "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.ConnectedVMwarevSphere/VCenters/<name>" `
    -KubeConfig .\my-bridge-appliance.kubeconfig `
    -VmName "app-server-01" `
    -SinceHours 48 `
    -IncidentId 123456789
```

`-VCenterId` is the one input worth supplying: the script follows it to the custom location, the
resource bridge, the cluster extension and the region, including when they are in a different
resource group or subscription.

Run this **early**. Kubernetes events expire after about an hour, and the previous container log is
lost as soon as the container restarts again.

## What it collects

```
01-workstation/   Host, OS and PowerShell version; Windows time service status; proxy environment;
                  az / kubectl / helm presence and versions; az extension versions;
                  DNS and TCP 443 reachability for the required Azure endpoints and, when the
                  region is known, the regional ones; vCenter and appliance VM reachability.

02-azure/         Signed-in account; resource provider registration; resource group contents;
                  activity log; the vCenter resource with provisioningState and connectionStatus;
                  inventory items with moRefId and managedResourceId; the custom location and its
                  enabled resource types; the resource bridge; the cluster extensions; and per-VM,
                  the Arc machine, its virtualMachineInstances/default and its extensions.

03-appliance/     kva.log; the arcvmware-setup onboarding script log; the appliance YAML configs;
                  and the 'az arcappliance logs' bundle from the appliance VM.

04-cluster/       Cluster version, nodes and node conditions; all pods; Kubernetes events;
                  Secret names and types only; the operator deployment (its image tag is the
                  deployed operator version); describe of the operator pod; the operator log for
                  every container; the PREVIOUS container log; the azure-arc agent pods and logs;
                  and every vsphere.vmware.microsoft.com custom resource, in full.

SUMMARY.md        What was collected, what was missing and why, the identifiers an IcM needs, and
                  the questions only the customer can answer.
manifest.json     The same results, machine-readable.
```

The custom resource kinds are discovered with `kubectl api-resources` rather than hard-coded, so
the dump stays correct as the operator's CRD set changes.

## Privacy and redaction

Before anything is written to disk:

- Kubernetes Secret **bodies are never collected** - only names, types and ages.
- Values of keys named `password`, `secret`, `clientSecret`, `token`, `apiKey`, `credential`,
  `privateKey`, `sharedKey`, `connectionString` and similar are replaced with `<redacted>`.
- Credentials embedded in proxy or repository URLs are masked.
- `Authorization: Bearer` values and raw JWTs are replaced.
- PEM private key blocks are replaced with `<redacted-private-key>`.

The archive still contains infrastructure detail - host names, IP addresses, VM names, vCenter
FQDN, resource IDs and the vCenter service account **user name**. Review `SUMMARY.md` and the
folder before sending.

## Useful switches

| Switch | Effect |
|---|---|
| `-SinceHours <n>` | Look-back window for pod logs, events and the activity log. Default 24. |
| `-SkipAzure` | No Azure calls at all - for a disconnected workstation. |
| `-SkipApplianceLogs` | Skip `az arcappliance logs`, which is the slowest step. |
| `-SkipClusterDump` | Skip everything that needs `kubectl`. |
| `-NoArchive` | Leave the folder uncompressed. |
| `-OutDir <path>` | Write somewhere other than the current directory. |

## What the script cannot collect

`SUMMARY.md` ends with these, because they decide how fast the case moves:

- **When** it happened and **what the customer was doing**.
- The **verbatim** error text, as plain text rather than a screenshot - including the full
  "Action Needed" message on a VM.
- Whether the vCenter, custom location, resource bridge or VMs were previously deleted, turned off
  or modified, and what "migration" meant if it was mentioned.
- vCenter-side facts read from the vSphere client: vCenter and ESXi versions, the privileges held
  by the account the bridge uses, and the affected VM's folder, resource pool, power state and
  VMware Tools status.
- **Guest agent logs, which live inside the guest VM.** On the affected VM run `azcmagent logs`, or
  collect `%ProgramData%\AzureConnectedMachineAgent\Log\himds.log` on Windows and
  `/var/opt/azcmagent/log/` on Linux.
