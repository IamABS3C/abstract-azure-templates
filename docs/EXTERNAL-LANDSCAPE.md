# External landscape — what exists publicly, and what genuinely does not

**Researched 2026-08-25** against live GitHub, with commit dates and archive flags pulled
from the API rather than READMEs. Tiers: **A** production-grade and current · **B** usable
with caveats · **C** reference only · **F** dead.

This file exists so nobody re-searches for a module that does not exist, and so nobody
recommends an archived repo to a customer.

---

## The Azure policy picture (read the correction below before quoting this)

**Azure Landing Zones will not give you Event Hub fan-out at scale.** Verified by reading
the policy JSON, not the README: ALZ's `Deploy-Diagnostics-*` definitions are
**Log Analytics only** *and* **flagged deprecated**. `Deploy-Diagnostics-Firewall.json`
carries `displayName: "[Deprecated]: … to Log Analytics workspace"`,
`metadata.deprecated: true`, `version: 1.2.0-deprecated`, and its only destination parameter
is `logAnalytics`. There is no event-hub parameter. 55 such files exist; the policy *sets*
are literally named `Deploy-Diagnostics-LogAnalytics.json`.

The counterpart: Azure Verified Modules **do** support Event Hub —
`event_hub_authorization_rule_resource_id` appears ~298 times across ~40
`Azure/terraform-azurerm-avm-res-*` repos as part of the standard AVM `diagnostic_settings`
interface. But that only helps for resources *you deploy through AVM*. Retrofitting an
existing estate is a policy job.

> **CORRECTED 2026-08-25, same day.** What stood here said Event Hub at scale requires forking
> ALZ's 55 policy definitions. **That was wrong, and the error was mine, not the template's.**
> A follow-up pass against Microsoft's *Azure Monitor* policy catalogue found **140 built-in
> `DS_EH_*` Event Hub diagnostic-settings policies and two built-in initiatives** —
> `85175a36-2f12-419a-96b4-18d5b0096531` (allLogs, 140 policies) and
> `1020d527-2764-4230-92cc-7035e4fcf8a7` (audit, 69). **Do not fork 140 policies.**
>
> Both findings are true at once, and the distinction is the whole point: ALZ's
> `Deploy-Diagnostics-*` set really is Log-Analytics-only and deprecated. Microsoft's Azure
> Monitor catalogue is a *different, current* set that does target Event Hub. Searching only
> the ALZ repo produced a confident conclusion about the wrong catalogue.
>
> `abstract-logstreams-policy.bicep` was already right — it references both built-in initiative
> GUIDs directly (lines 163-164, verified by reading the file). The engineering was never
> reinventing a wheel; my write-up of it was.

**What genuinely has no built-in — the real custom surface:**

- **Activity Log → Event Hub.** No Microsoft built-in exists. Verified independently twice:
  against the live catalogue on 2026-08-03 (recorded in the template header) and again in this
  research pass. This is why the template defines its own DeployIfNotExists policy inline, and
  it is a legitimate differentiator.
- **`microsoft.web/sites` and `microsoft.storage/storageAccounts`** — absent from the built-in
  initiatives.
- **Entra tenant logs** — no policy plane exists for the tenant-scoped diagnostic setting at
  all. Simultaneously the highest-value telemetry on this path and the only part with no
  governance backstop.

**Method lesson worth keeping:** "no public module exists" is a claim about a search, not about
the world. Name the catalogue you searched, and check whether a second one exists before
concluding absence.

---

## Archived or dead — never recommend

| Repo | Status |
|---|---|
| `oracle-quickstart/oci-arch-logging-splunk` | **ARCHIVED.** Last commit 2023-04-05, message literally `doc: Archiving this project` |
| `oracle-terraform-modules/terraform-oci-logging` | Not archived but **dead** — last commit 2023-06-10 |
| `Azure/alz-monitor` | **ARCHIVED** |
| `Azure/terraform-azurerm-alz-management` | **ARCHIVED** |
| `Azure/terraform-azurerm-sec-audit-diagnostics-package` | **ARCHIVED**, 0 stars |
| `Azure/terraform-azurerm-caf-enterprise-scale` | **Soft-deprecated.** No code change in ~7.5 months; its last commit redirects users elsewhere. **This is the module most people reach for first — don't** |

## Does not exist (stop looking)

| Assumed | Reality |
|---|---|
| `terraform-aws-modules/terraform-aws-cloudtrail` | **Does not exist.** Verified against the full 61-repo org listing |
| A single CloudTrail→S3→SNS→SQS module | Does not exist anywhere. It is a composition |
| A standalone S3-event-notification→SQS repo | Not a repo — a **submodule**: `terraform-aws-s3-bucket//modules/notification` |
| `Azure/terraform-azurerm-eventhub` | Does not exist. The Azure-org module is `Azure/terraform-azurerm-avm-res-eventhub-namespace` |
| `Azure/terraform-azurerm-diagnostic-settings` | Does not exist under the Azure org. All 11 same-named repos are personal/community with **0 stars each** — recommend none |
| ALZ deploys diagnostic settings to Event Hub | **False** — ALZ's set is Log Analytics only and deprecated. But Microsoft's separate **Azure Monitor** catalogue DOES: 140 `DS_EH_*` policies + 2 initiatives. Do not confuse the two catalogues |

## Worth citing

**AWS** — the composition that works: `aws-samples/aws-security-reference-architecture-examples`
ships a real org-wide CloudTrail solution in **both** CloudFormation and Terraform
(`cloudtrail_org/` with `s3/`, `kms/`, `org/` submodules; last commit 2026-07-29), then
`terraform-aws-s3-bucket//modules/notification` for S3→SQS, then `terraform-aws-sqs` for the
queue *and its policy* — the part people get wrong. All tier A, all updated 2026-08-06.

**GCP — the cheapest win of the four clouds.** `terraform-google-modules/terraform-google-log-export`
exists exactly as named, creates sinks at project/folder/org/billing level, and
`include_children` is confirmed present in `main.tf` and `variables.tf`, so **org-level
aggregated sinks are supported**. Destination submodules include `pubsub`, `storage`,
`bigquery`, `logbucket`. Tier A−, with an honest caveat: last commit 2026-02-24 and it was a
lint chore — ~6 months without functional change.

**OCI** — `oracle-quickstart/oci-observability-and-management` is the answer: it has
`modules/sch/` (Service Connector Hub) *and* `modules/audit-logs/`, i.e. audit logs → SCH →
target as reusable modules. Last commit 2026-08-24, tier A. The provider resource name is
confirmed real: **`oci_sch_service_connector`**. This is a much better starting point for the
OCI gap than the Function-relay workaround.

**Azure** — `Azure/terraform-azurerm-avm-res-eventhub-namespace` (2026-08-25) for the
namespace itself; `Azure/terraform-azurerm-avm-ptn-alz` (2026-08-19) is the live Terraform
successor to caf-enterprise-scale. For Entra logs, `azurerm_monitor_aad_diagnostic_setting`
is the correct resource and is **separate** from `azurerm_monitor_diagnostic_setting` — but
**no Azure-org module consumes it**. All 235 code hits are the provider itself, wrappers, or
personal repos. It is ~15 lines of raw HCL you write yourself.

## Collector components — read the maintainer signal, not the commit date

All four OTel receivers are present in `opentelemetry-collector-contrib`, but the last commit
touching each path is the same monorepo-wide dependency bump. Their five most recent commits
are **all bot traffic**, which proves the monorepo is alive, not the component:

| Component | Stability | Signal |
|---|---|---|
| `azureeventhubreceiver` | beta | ⚠️ **`seeking_new: true`** — actively looking for codeowners |
| `googlecloudpubsubreceiver` | beta | ⚠️ single codeowner (bus factor 1); has real internal telemetry |
| `awss3receiver` | alpha | two codeowners |
| `awscloudwatchreceiver` | alpha | ⚠️ **`seeking_new: true`** |

By contrast **`vectordotdev/vector`'s `aws_s3` source is the healthiest component here** —
SQS-based (the directory is `mod.rs` + `sqs.rs`), with a genuine human feature commit
(`feat(s3): add request payer support`) on 2026-08-24. Tier A. Worth watching as a
differentiation input: two of the four OTel receivers we would depend on are advertising for
maintainers.

---

## What this means for the corpus

1. **Use Microsoft's built-in Event Hub initiatives for resource logs** — `85175a36-…`
   (allLogs) or `1020d527-…` (audit). The template already does. Do not fork, and do not
   repeat the claim that no built-in exists.
2. **The differentiator is narrower and therefore more defensible:** Activity Log → Event Hub
   has no built-in, `microsoft.web/sites` and `microsoft.storage/storageAccounts` are absent
   from the initiatives, and the Entra tenant setting has no policy plane at all. Say *that*,
   not "no public alternative exists."
3. **OCI is less greenfield than the Notion audit suggested.** `oci_sch_service_connector`
   plus `oci-observability-and-management`'s `sch/` + `audit-logs/` modules is a real
   starting point. Revisit the OCI recommendation before authoring that node.
4. **Never cite a repo without checking `archived` and the last *functional* commit.** Six of
   the first-choice candidates here are dead, and two are Oracle repos that a reasonable
   person would have trusted on name alone.
