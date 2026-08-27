# Abstract Security — Azure Event Hub Onboarding

Production-ready Azure infrastructure for the **Abstract Security "Azure Event Hub" integration**: an Event Hubs namespace, one hub per log source, a consumer group, the **checkpoint Storage Account + private blob container Abstract requires for offset/lease tracking**, SAS and/or Entra ID (RBAC) auth, networking guardrails, and optional log-export plumbing — deployable from the portal (Deploy to Azure button with a guided wizard), the CLI, or a menu-driven PowerShell script.

> **Status:** templates are syntax-validated but **not yet runtime-tested against a live tenant**. Run `az deployment group what-if` (or the script's `-Preview`) before the first production deployment, and rebuild `azuredeploy.json` from `main.bicep` with `az bicep build` if you modify the Bicep.

---

## Deploy to Azure

| What | Deploy | Notes |
| --- | --- | --- |
| **Main stack** (namespace, hubs, storage, auth, networking) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAbstract-Security%2Fazure-eventhub-onboarding%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAbstract-Security%2Fazure-eventhub-onboarding%2Fmain%2FcreateUiDefinition.json) | Guided 6-step wizard (basics → hubs → auth → networking → storage → monitoring) |
| Main stack, **Azure Government** | [![Deploy to Azure Gov](https://aka.ms/deploytoazuregovbutton)](https://portal.azure.us/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAbstract-Security%2Fazure-eventhub-onboarding%2Fmain%2Fazuredeploy.json/createUIDefinitionUri/https%3A%2F%2Fraw.githubusercontent.com%2FAbstract-Security%2Fazure-eventhub-onboarding%2Fmain%2FcreateUiDefinition.json) | Same wizard, Gov portal |
| **Activity Log export** (subscription scope, run after the main stack) | [![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FAbstract-Security%2Fazure-eventhub-onboarding%2Fmain%2Ftemplates%2Fsubscription%2Factivitylog.azuredeploy.json) | Streams the subscription's Activity Log to the hub. Deploy once per subscription. |

> **Before the buttons work:** push this repo to GitHub and replace `Abstract-Security/azure-eventhub-onboarding` in the three URLs above with your actual `org/repo`. The button URL format is `https://portal.azure.com/#create/Microsoft.Template/uri/<URL-encoded raw azuredeploy.json>/createUIDefinitionUri/<URL-encoded raw createUiDefinition.json>` — URL-encode the raw.githubusercontent.com link (`:` → `%3A`, `/` → `%2F`). The repo (or at least the two JSON files) must be publicly readable.
>
> Test the wizard without deploying anything at the [CreateUiDef sandbox](https://portal.azure.com/#blade/Microsoft_Azure_CreateUIDef/SandboxBlade) — paste `createUiDefinition.json` in.

---

## What gets deployed

| Resource | Purpose | Default |
| --- | --- | --- |
| Event Hubs **namespace** | Container for hubs; Standard or Premium ([Abstract requires Standard+](#sizing)) | `Standard`, 2 TU, TLS 1.2 |
| **Event hub(s)** | One per log source, auto-named `<prefix>[-<env>]-<source>` | `evh-abstract-activity`, `-entra`, `-defender` · 4 partitions · 7-day retention |
| **Consumer group** | Dedicated group for Abstract's readers (don't share with other consumers) | `abstract` |
| **Storage Account** + private **blob container** | **Required by Abstract** — checkpoint/lease store for the consumer | auto-named `abs<hash>` · container `abstract-checkpoints` · TLS 1.2, no public blob access |
| **SAS rule** (optional) | Connection-string auth, **Listen-only** by default | `abstract-access` |
| **RBAC roles** (optional) | Entra service-principal auth: `Azure Event Hubs Data Receiver` on the namespace + `Storage Blob Data Contributor` on the storage account | off until you supply a principal |
| Diagnostics SAS rule | Send-only rule for *log producers* (Activity/Entra/Defender exports) | `abstract-diagnostics-send` |
| Network rule sets | Safe Mode / IP allowlist / private endpoints, optionally mirrored to storage | Safe Mode ON |
| Diagnostic settings | Namespace logs+metrics → Log Analytics (optional) | off |

### Repo layout

```
.
├── main.bicep                     # source of truth (resource-group scope)
├── azuredeploy.json               # compiled ARM (what the button deploys)
├── createUiDefinition.json        # portal wizard definition
├── parameters/                    # ready-made profiles (see matrix below)
│   ├── abstract-recommended.parameters.json
│   ├── safe-mode.parameters.json
│   ├── ip-allowlist.parameters.json
│   ├── private-only.parameters.json
│   └── hybrid.parameters.json
├── scripts/
│   └── Deploy-AbstractEventHub.ps1  # guided deploy / credentials / delete
├── templates/subscription/
│   ├── activitylog.bicep            # Activity Log → hub (subscription scope)
│   └── activitylog.azuredeploy.json
└── .github/workflows/validate.yml   # CI: JSON + arm-ttk validation
```

---

## Quick starts

**Portal** — click the Deploy to Azure button and follow the wizard.

**PowerShell (guided)** — works in Cloud Shell or locally (PS 7+):

```powershell
./scripts/Deploy-AbstractEventHub.ps1
```

**PowerShell (one-liner, recommended happy path)** — Safe Mode, checkpoint storage, SPN created for you, Activity Log wired up:

```powershell
./scripts/Deploy-AbstractEventHub.ps1 -Action Deploy -ResourceGroup rg-abstract `
    -NamespaceName abs-eh001 -SecurityProfile SafeMode `
    -CreateServicePrincipal -ExportActivityLogs
```

**Azure CLI**:

```bash
az deployment group create -g rg-abstract \
  --template-file azuredeploy.json \
  --parameters parameters/abstract-recommended.parameters.json \
  --parameters namespaceName=abs-eh001 principalId=<spn-object-id>

# preview first (recommended):
az deployment group what-if -g rg-abstract --template-file azuredeploy.json \
  --parameters parameters/abstract-recommended.parameters.json namespaceName=abs-eh001
```

**Activity Log export** (subscription scope — separate by design, since subscription diagnostic settings can't be created from a resource-group deployment):

```bash
az deployment sub create --location eastus \
  --template-file templates/subscription/activitylog.azuredeploy.json \
  --parameters eventHubAuthorizationRuleId=<abstractDiagnosticsAuthRuleId output> \
               eventHubName=evh-abstract-activity
```

---

## Connectivity / security profiles

| Profile | safeMode | Public access | Firewall | Private endpoints | Abstract can connect? |
| --- | --- | --- | --- | --- | --- |
| `safe-mode` (default) | **true** | forced **Enabled** | forced Allow | no | **Always** — guardrails win |
| `ip-allowlist` | false | Enabled | **Deny** + your CIDRs | no | Only from allowlisted CIDRs — **include Abstract's egress IPs** |
| `hybrid` | false | Enabled | Deny + CIDRs | namespace + storage | Via allowlist; internal consumers go private |
| `private-only` | false | **Disabled** | n/a | namespace + storage | **No** (by design) — internal-only or in-VNet collectors |

Safe Mode exists so a hardened parameter file can never silently break ingestion during onboarding: when `safeMode=true` the template forces public access on and ignores the allowlist (on the storage account too). Flip it off when you're ready to harden.

`storageApplyIpRules=true` mirrors your namespace allowlist to the checkpoint Storage Account. Note Azure Storage rejects `/31` and `/32` CIDR entries — use individual IPs without a suffix or wider ranges.

---

## <a name="sizing"></a>Sizing (from the Abstract docs)

Abstract requires **Standard tier or above** and recommends **≥ 4 partitions** per hub. Throughput sizing:

| Expected ingress | Throughput units | Partitions |
| --- | --- | --- |
| 1 MB/s | 1 | 4 (default) |
| 2 MB/s | 2 | 4 |
| 10 MB/s | 10 | 10+ |
| 32 MB/s (max) | 32 (max 40) | 32 (max) |

Set `capacity` (TUs) and `defaultPartitionCount` accordingly; `autoInflate` + `maxThroughputUnits` lets Standard namespaces scale TUs automatically. **Partition count cannot be changed after hub creation** (Standard tier) — size it for peak.

---

## Onboarding in Abstract

In Abstract: **Data Flow Management → Streams → Add Stream → Azure Event Hub**. The deployment's `abstractOnboarding` output (and the script's `Credentials` action) gives you every field. Two auth methods:

**Method 1 — Connection String**

| Abstract modal field | Where it comes from |
| --- | --- |
| Event Hub Connection String | namespace SAS rule `abstract-access` primary connection string + `;EntityPath=<hub>` — the script prints it, or Portal → namespace → Shared access policies |
| Consumer Group | `abstract` (template output `consumerGroup`) |
| Storage Account Connection String | Portal → storage account → Access keys, or the script prints it |

**Method 2 — Service Principal** (no shared keys; the template grants the roles)

| Abstract modal field | Where it comes from |
| --- | --- |
| Event Hub Name | e.g. `evh-abstract-activity` (output `eventHubs`) |
| Consumer Group | `abstract` |
| Blob Container Name | `abstract-checkpoints` |
| Fully Qualified Namespace | `<namespace>.servicebus.windows.net` (output `namespaceFqdn`) |
| Storage Account URL | `https://<account>.blob.core.windows.net` (output `storageAccountBlobUrl`) |
| Tenant ID / Client ID / Client Secret | the app registration — `-CreateServicePrincipal` makes `abstract-eventhub-ingestion` and prints all three (secret shown **once**) |

The service principal needs **`Azure Event Hubs Data Receiver`** on the namespace and **`Storage Blob Data Contributor`** on the storage account — both are assigned by the template when you pass `principalId` (the SPN's **object ID**, not the app ID).

**Then point log sources at the hubs:** the Activity Log template above; Entra ID → Diagnostic settings → SignInLogs + AuditLogs → stream to event hub (or the script's `-ExportEntraLogs`, needs Entra P1/P2); Defender XDR Streaming API; any resource's diagnostic settings using the Send-only `abstract-diagnostics-send` rule.

---

## Notable template behaviors (and the bugs they fix)

v1 fixed ten issues found in a hand-written draft, all still guarded here: correct **Event Hubs** role GUIDs (not Service Bus), no conditional-loop syntax, `networkRuleSets` as a child resource, `maximumThroughputUnits` omitted when auto-inflate is off, Basic-SKU feature guards (now moot — Basic removed per Abstract docs), `principalType` set to avoid `PrincipalNotFound` races, `allLogs` category group, and **no secrets in outputs** (the `abstractOnboarding` output points you to where each secret lives instead of echoing it).

v2 adds per the official Abstract documentation: the **checkpoint storage stack** (account + private container + Storage Blob Data Contributor + optional blob private endpoint + firewall mirroring), **Listen-only** default SAS rights, default hub sources `activity/entra/defender`, `defaultPartitionCount`/`defaultRetentionDays`, Standard-minimum SKU, input trimming/filtering so CSV-driven portal inputs can't produce empty hub names, and the portal wizard + subscription Activity Log template.

Caveats worth knowing:

- **Hand-compiled ARM**: `azuredeploy.json` was written to match `main.bicep`, not generated by the Bicep compiler. If you change the Bicep, regenerate with `az bicep build -f main.bicep --outfile azuredeploy.json`.
- **Premium** ignores auto-inflate (capacity = PUs: 1/2/4/8/16) and `zoneRedundant` behavior differs by region.
- Deleting the namespace does **not** delete the storage account, private endpoints, diagnostic settings, or the app registration — the script's `Delete` action reminds you.
- The Entra log export uses the legacy `microsoft.aadiam` API (best effort) and needs Entra P1/P2 plus Security Administrator.

## License

MIT — see [LICENSE](LICENSE).
