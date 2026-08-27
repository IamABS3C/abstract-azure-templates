# Azure log streams → Abstract, at scale

Everything Microsoft can emit, how each stream actually reaches an Event Hub, and
which ones Azure Policy can onboard for you automatically.

Verified against a live Azure tenant and the live Azure Policy built-in catalogue
on **2026-08-03**. Where a claim was tested rather than read, the evidence is quoted.

---

## 1. The short answer

| Question | Answer |
|---|---|
| Is there an ARM template for the Event Hub and everything around it? | Yes — `azuredeploy.json` (+ guided wizard), with Bicep sources. Nothing is provisioned by hand. |
| Do diagnostic settings have to be configured per subscription? | **No.** Assign the policy pack once at a management group. Every subscription in it — today's and every one added later — onboards itself. |
| Does that cover *everything*? | No, and no product's does. Three streams are **tenant**-level and have no per-subscription object for policy to evaluate. They are one-time setups; two of them ship as templates here. |

---

## 2. Coverage matrix

**Legend** — 🟢 Azure Policy onboards it automatically, current *and* future subscriptions · 🔵 one-time tenant setup, templated here · 🟡 one-time tenant setup, not templatable (portal/Graph) · ⚪️ different collection path entirely

| Stream | Scope | Mechanism to Event Hub | Automatable? | Where it lives here |
|---|---|---|---|---|
| **Azure Activity Log** — control plane: who created/changed/deleted what, plus Security, Policy, ServiceHealth | Subscription | Subscription diagnostic setting | 🟢 **Custom** `DeployIfNotExists` — Microsoft ships **no built-in** for the Event Hub destination (only Log Analytics, `2465583e-…`) | `templates/policy/` (definition is authored inline) |
| **Azure resource logs** — ~140 types: Key Vault, NSG, Firewall, Front Door, AKS, Cosmos DB, SQL DB, App Service Env, APIM, Automation… | Resource | Resource diagnostic setting | 🟢 Built-in initiative, **one assignment per region** — `85175a36-…` (allLogs) / `1020d527-…` (audit) | `templates/policy/` |
| **Azure platform metrics** | Resource | Same diagnostic setting (`AllMetrics`) | 🟢 Rides along with resource logs | `templates/policy/` |
| **Azure SQL auditing** — statement-level data plane (who ran which query) | Resource | SQL *auditing*, **not** a diagnostic setting | 🟢 Built-in `9a04cb4d-…`, per region | `templates/policy/` (`enableSqlAuditing`) |
| **Defender for Cloud** — alerts, recommendations, secure score, regulatory compliance | Subscription | *Continuous export*, **not** a diagnostic setting | 🟢 Built-in `cdfcce10-…` (or `af9f6c70-…` trusted-service variant) | `templates/policy/` (`enableDefenderExport`) |
| **Microsoft Entra ID** — sign-ins (interactive, non-interactive, SP, MI), audit, provisioning, ID-Protection risk, **Graph activity** | **Tenant** | `microsoft.aadiam/diagnosticSettings` | 🔵 **No policy can reach it** — there is no per-subscription object. But it *is* ARM-deployable at tenant scope, so it is one command. | `templates/tenant/entra-diagnostics.bicep` |
| **Microsoft Defender XDR** — advanced hunting tables (Device*, Email*, Identity*, Cloud App) | **Tenant** | Defender XDR *Streaming API* → Event Hub | 🟡 Portal (`security.microsoft.com` → Streaming API) or Graph. No ARM, no policy. | Manual — one-time |
| **Microsoft 365 unified audit** — Exchange, SharePoint, OneDrive, Teams, Purview | **Tenant** | Office 365 Management Activity API — **does not use Event Hub at all** | ⚪️ Collected by the Abstract **Office 365** integration, not by this Event Hub path | Abstract platform integration |
| **NSG / VNet flow logs** | Resource | Flow-log resource → **Storage account** (Event Hub is not a supported destination) | ⚪️ Built-ins exist (`cd6f7aff-…` VNet, `0db34a60-…` NSG) but they target Storage — collect via the Abstract Azure **Blob Storage** path | Separate path |
| **Storage data-plane logs** (blob/queue/table/file read-write-delete) | Sub-resource | Diagnostic setting on `…/blobServices` etc. | ⚪️ Not in the built-in initiative's supported list — needs a custom policy or per-account setting | Gap, by design of the built-ins |
| **Azure AD B2C** | Tenant | `microsoft.aadiam` category `B2CRequestLogs` | 🔵 Same tenant template, add the category | `templates/tenant/entra-diagnostics.bicep` |

---

## 3. The three constraints that decide the architecture

### 3.1 The region rule — one Event Hubs namespace per region

Azure Monitor **refuses** a diagnostic setting whose Event Hub is in a different
region from the monitored resource. This is not a policy convention; it is
enforced by the Azure Monitor API. Verified by attempting it:

```
$ az monitor diagnostic-settings create --resource <eastus workspace> \
    --event-hub-rule <centralus namespace rule> --event-hub abs-prod-activity

ERROR: (BadRequest) Resources should be in the same region.
Resource '…/workspaces/abs-regiontest-eastus' is in region 'eastus' and
resource '…/namespaces/absfault-logs' is in region 'centralus'.
```

Microsoft states the same rule in the destination requirements: *"Event hubs must
be in the same region as the resource that you're monitoring if the resource is
regional."*

**Consequences**

- One Event Hubs namespace **per region** that holds regional resources.
- One assignment of the resource-log initiative per region — the initiative's
  `resourceLocation` parameter takes a single region, not a list. This is why the
  template's `regions` parameter is an array and why each entry carries its own
  authorization rule.
- **Activity Log is exempt.** A subscription is not a regional resource, so one
  hub serves every subscription in the estate. Same for Defender for Cloud and
  Entra ID.

Practically: pick the two or three regions that actually hold resources. You do
not need a namespace in all sixty.

### 3.2 `DeployIfNotExists` does not touch what you already own

Policy fires when a resource is **created or updated**. Your existing estate stays
non-compliant until a **remediation task** backfills it — one task per policy in
the initiative. Skip this and the hub looks mysteriously quiet while the compliance
blade shows green-ish numbers.

`scripts/Deploy-AbstractLogStreams.sh -a Remediate` loops through them.

### 3.3 "Future subscriptions" has a second half

A management-group assignment covers subscriptions in that group, **including ones
added later** — that part is automatic. But a brand-new subscription lands in the
**Tenant Root Group** by default, not in your group, so it silently misses the
assignment.

Set the tenant's **default management group for new subscriptions** to the group
you assigned the pack to. Without it, "current and future subscriptions" is only
half true.

---

## 4. Two more things worth knowing

**Five diagnostic settings per resource, and per subscription.** If the customer
already streams to another SIEM, Abstract's setting is an *additional* one — it
does not displace anything — but the ceiling is real. Budget for it if there are
already three or four in place.

**A `Send`-only SAS rule is sufficient.** Microsoft's destination documentation
says streaming to Event Hubs requires `Manage`, `Send` and `Listen`. Tested: a
namespace rule with **`Send` alone** creates the diagnostic setting and delivers
data, *provided the hub already exists* — the broader rights are only needed when
you let Azure Monitor auto-create a hub for you. These templates always pre-create
the hub, so they ship a least-privilege `Send` rule and the producer key never
carries `Manage`.

Verified: `abstract-diagnostics-send` (`rights: ["Send"]`) deployed the
subscription diagnostic setting successfully and the setting returned its three
enabled categories on read-back.

---

## 5. Deployment order

```
1. Event Hub estate            azuredeploy.json  (once per REGION)
                               → note the abstractDiagnosticsAuthRuleId AND
                                 eventHubNames outputs. Azure Policy never creates
                                 hubs, so every hub name you pass in step 2 must
                                 already exist. main.bicep auto-names hubs
                                 <hubPrefix>-<environment>-<source>; its defaults
                                 give abs-prod-activity / -entra / -defender, while
                                 the example parameter files override hubPrefix to
                                 "evh-abstract" and give evh-abstract-prod-activity.
                                 Add "resource" to hubSources for a resource-log hub.

2. Policy pack                 scripts/Deploy-AbstractLogStreams.sh -a Deploy
   (management group)          → starts in report-only; review compliance first

3. Grant hub access            scripts/Deploy-AbstractLogStreams.sh -a Grant
                               → Azure Event Hubs Data Owner for each assignment
                                 identity, on the namespace. The template cannot
                                 do this: the namespace usually sits outside the
                                 management group's assignment scope.

4. Backfill the estate         scripts/Deploy-AbstractLogStreams.sh -a Remediate

5. Entra ID                    az deployment tenant create \
   (tenant, one command)         --template-file templates/tenant/entra-diagnostics.bicep

6. Defender XDR                Portal: security.microsoft.com → Streaming API
   (tenant, manual)

7. Default MG for new subs     Entra admin centre → so future subscriptions land
                               in the group you assigned in step 2
```

Steps 1–4 are re-runnable and idempotent.

---

## 6. Verified identifiers

| What | Identifier |
|---|---|
| Resource logs → Event Hub, allLogs (initiative) | `85175a36-2f12-419a-96b4-18d5b0096531` |
| Resource logs → Event Hub, audit (initiative) | `1020d527-2764-4230-92cc-7035e4fcf8a7` |
| SQL auditing → Event Hub | `9a04cb4d-8b47-4533-8e8e-b7a3c7742a0c` |
| Defender for Cloud export → Event Hub | `cdfcce10-4578-4ecd-9703-530938e4abcb` |
| Defender for Cloud export → Event Hub (trusted service) | `af9f6c70-eb74-4189-8d15-e4f11a7ebfd4` |
| Activity Log → **Log Analytics** (the built-in that exists) | `2465583e-4e78-4c15-b6be-a36cbc7c8b0f` |
| Activity Log → **Event Hub** | **No built-in.** Defined by `templates/policy/abstract-logstreams-policy.bicep`. |
| Monitoring Contributor | `749f88d5-cbae-40b8-bcfc-e573ddc772fa` |
| Log Analytics Contributor | `92aaf0da-9dab-42b6-94a3-d43ce8d16293` |
| Azure Event Hubs Data Owner | `f526a384-b230-433a-b45c-95f59c4a2dec` |
| SQL Security Manager | `056cd41c-7e88-42e1-933e-88ba6a50c9c3` |

> On "no built-in for Activity Log → Event Hub": third-party policy catalogues
> still list retired GUIDs (`e128cd6e-…`, `b2215d7b-…`, `42d90820-…`). All three
> return `PolicyDefinitionNotFound` against the live catalogue. Do not build a
> customer plan on them.

---

## 7. Sources

- [Diagnostic settings in Azure Monitor — destinations and their requirements](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings)
- [Enable diagnostic settings by category group using built-in policies](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings-policy-built-in)
- [Create diagnostic settings at scale with custom Azure Policies](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/diagnostic-settings-policy)
- [How to configure Microsoft Entra diagnostic settings](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-configure-diagnostic-settings)
- [Entra ID logs available for streaming](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options)
- [`microsoft.aadiam/diagnosticSettings` template reference](https://learn.microsoft.com/en-us/azure/templates/microsoft.aadiam/2017-04-01/diagnosticsettings)
- [Remediate non-compliant resources](https://learn.microsoft.com/en-us/azure/governance/policy/how-to/remediate-resources)
- [Deploy to Azure button — deployment scope follows the template schema](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deploy-to-azure-button)
