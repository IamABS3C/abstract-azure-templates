# Canonical IaC sources — which copy a corpus node may reference

**Audited 2026-08-25**, read-only, with every validator actually run. This is the
authority on which file is real. `ci/validate_corpus.py` checks that an `external_path`
*resolves*; it cannot tell a stale fork from the canonical copy. That is this document's job.

**Tooling used:** cfn-lint 1.53.3 · OpenTofu v1.12.5 (no `terraform` binary present; every
`.terraform.lock.hcl` in these repos already points at `registry.opentofu.org`) · Bicep CLI
0.44.1 · pwsh. **No AWS credentials** — `aws sts get-caller-identity` returned
`NoCredentials`, so no `validate-template`, no `plan`, no `what-if` was run anywhere.
`ansible-playbook` is **not installed**; nothing Ansible was validated.

---

## Reference these. Nothing else.

| Artifact | Canonical path | Tier |
|---|---|---|
| AWS CloudFormation (7 templates) | `ABSEC-AWS-CF/templates/` | validated |
| AWS deploy/discover/publish/stackset scripts | `ABSEC-AWS-CF/scripts/` | validated |
| AWS S3→SQS routing Terraform | `abstract-cs-nexus/deploy/terraform/abstract-s3-event-routing/` | validated |
| AWS multi-dialect IaC generator | `abstract-cs-nexus/report-output/abstract-aws-launchpad/launchpad.py` | planned (partly deployed) |
| Azure Bicep (9 templates) | `Abstract-MS-Azure /solutions/templates/**/*.bicep` — **never** the `.azuredeploy.json` | validated |
| Azure portal UI definitions | `Abstract-MS-Azure /solutions/templates/**/*.{createUiDefinition,uiFormDefinition}.json` | validated |
| Azure deployment drivers | `Abstract-MS-Azure /solutions/scripts/` | validated |
| Entra app registration | `abstract-ms-provisioner/Deploy-AbstractMicrosoftApp.ps1` | deployed |
| Splunk-migrate collector IaC | `abstract-splunk-migrate/deploy/` — **never** `dist/` | validated |
| Forwarder host IaC | `abstract-forwarder-hub/fleet_deployment/iac.py` (the generator) — **never** `forwarder-deploy/*/iac/` | schema-reviewed |
| PrivateLink / TGW / VPC | `Abstract-MutliVPC Foxtrot/setup/` | **deployed** |
| Academy Azure Event Hub | `abstract-security-academy/infra/azure/eventhub.bicep` | validated |
| Academy GCP log export | `abstract-security-academy/infra/gcp/main.tf` | validated |

**Never reference:** `dist/` · `forwarder-deploy/*/iac/` · `superseded/` ·
`ABSEC-AWS-CF/ABSEC-AWS-CF/` · `abstract-security-academy/infra/aws-cf/` · any `.venv/` or
`.terraform/providers/` path.

---

## The three duplication verdicts

### 1. AWS CloudFormation — three copies, all byte-identical

`shasum -a 256` returns one hash per file across all three locations. **Zero drift.**
Canonical is `ABSEC-AWS-CF/templates/`, settled not on mtime (identical, consistent with a
mtime-preserving copy) but on git history shape: ABSEC shows the templates *evolving* across
three commits on 2026-06-03; the Academy receives all seven whole in a single "Initial
commit" on 2026-06-08. Development history beats a one-shot drop.

The Academy copy is a whole-repo vendored clone — LICENSE, docs, examples, scripts, and a
`.github/workflows/ci.yml` that is **inert**, because GitHub only reads `.github/` at repo
root. Only ABSEC actually gates these templates with cfn-lint.

**`ABSEC-AWS-CF/ABSEC-AWS-CF/` is NOT a stray duplicate — do not delete it.** It is a
separate clone of the same remote holding **20 commits that were never pushed**, and its
HEAD is 24 days *ahead* of the outer checkout. The content of those commits survives in
`abstract-forwarder-hub`; the git history does not. Push before removing.

### 2. S3-event-routing Terraform — real drift, and the fork is customer-facing

Three copies. One is genuinely dead (untracked, zero references, safe to delete). The other
two are **both live**, and they disagree on IAM:

| Copy | State |
|---|---|
| `deploy/terraform/abstract-s3-event-routing/` | **canonical** — 11/11 `tofu test` pass |
| `report-output/abstract-aws-launchpad/templates_tf/` | **shipped to customers**, 8/8 pass — but three security deltas behind |
| `report-output/s3-sqs-multisource-routing/superseded/…` | dead — untracked, zero references |

The canonical copy is strictly ahead on three security-relevant points: it adds the empty
string to the `s3:prefix` StringLike so a no-prefix connectivity check still works; it flips
`scope_list_bucket_to_prefixes` to `default = true` (the fork defaults `false`, i.e. **no
`s3:ListBucket` condition at all** — a full key inventory of the bucket); and it adds the
**sibling-prefix guard** requiring a prefix to end `/` or `*`, because `prefix = "AWSLogs"`
grants `AWSLogs*`, which also matches **`AWSLogs-secret/`**.

**The defect:** the Launchpad ships two different IAM postures from one kit. `launchpad.py`
emits the hardened form unconditionally on the CloudFormation path (5 sites), while its own
Terraform path emits no condition and has no sibling-prefix guard. Proven, not inferred:
`grep -c rejects_folder_prefix_without_trailing_slash` on the fork's test file returns **0** —
the guard is absent, not failing.

A comment in the canonical module reading *"This now matches what the Abstract AWS Launchpad
generates for the same shape"* is true of the Launchpad's CFN generator and **false** of the
Launchpad's own Terraform module.

### 3. `splunk-migrate/dist/` — a stale build artifact, not a fork

Direction proven from `cli.py`: `deploy/` is copied *into* `<release>/iac/`. It is generated
output, and it is 18 files behind by 94 minutes of commits — including a measured Splunk 9.4
TLS finding. **Regenerate; never merge.**

---

## Defects found by running the validators

Three of these produce errors *today*. None were known before this audit.

**`splunk-migrate-fargate.yaml` fails cfn-lint.** `cfn-lint` exit 2:
`E0000 Duplicate found 'Description' (line 420) / (line 421)`. YAML keeps the last key, so
the informative description is silently discarded. Introduced by the HEAD commit on
2026-08-24; the `dist/` copy is clean, so this is a fresh regression.

**`fleet_deployment/iac.py` emits Terraform that cannot parse — all three clouds.** `tofu
fmt` returns rc=2 before validation is even reached: `Invalid single-argument block
definition` on comma-separated single-line blocks (`resource "x" "y" { a = 1, b = 2 }`,
`provider "azurerm" { features {} }`). The same generator's CloudFormation and ARM output is
fine. Any customer handed the Terraform path gets a config that fails at first parse.

**`academy/infra/gcp/main.tf` is unformatted** (`tofu fmt -check` rc=3) — cosmetic, and the
only formatting outlier among canonical Terraform.

### What passed

- **ABSEC 7 CFN templates** — 49 findings, **0 errors** (all `W1030`/`W1031` regex warnings).
  The README's "0 errors" claim is verified true.
- **Foxtrot 11 templates** — 0 errors.
- **All 9 Abstract-MS-Azure Bicep** — `bicep build` exit 0, two cosmetic `use-parent-property`
  warnings.
- **ARM↔Bicep parity — `[MATCH]` × 9.** Every committed `.azuredeploy.json` is the exact
  compiled output of its Bicep source. The CI claim holds under independent reproduction.
- **Canonical S3-routing Terraform** — fmt, init, validate all clean; **11/11 tests pass**.
- **All 6 splunk-migrate Terraform roots** — validate clean.
- **5 PowerShell scripts** — parse clean.

---

## Provenance tiers, from in-repo evidence only

| Artifact | Tier | Evidence |
|---|---|---|
| Foxtrot `setup/` + Helm | **deployed** | README: built, deployed and verified end-to-end against a live tenant; forwarder enrolled `pending → online`; templates live-hosted in S3 |
| `abstract-ms-provisioner` | **deployed** | README documents tenant-observed failure modes (`AADSTS53003` device-code block in Cloud Shell; a permission skipped when the O365 Management APIs SP is absent) — those are run artifacts, not schema reading |
| `launchpad.py` generators | **planned**, partly deployed | The direct S3→SQS path, S3-notification/queue-policy/KMS statements were verified live against a real AWS account on 2026-07-30; the SNS and CloudWatch hops are explicitly marked unverified |
| Abstract-MS-Azure `solutions/` | **validated** | CI compiles every Bicep, fails on stale ARM, and checks UI↔template parameter contracts |
| ABSEC-AWS-CF | **validated** | CI runs cfn-lint on push/PR. No deploy record in-repo |
| S3-routing Terraform | **validated** | 11/11 plan-mode tests + validate. No `apply` evidence |
| splunk-migrate `deploy/` | **validated** | Its own FIX-REPORT states verbatim: *"No plan, no apply, no run. Nothing was deployed and no AWS API was called."* **Do not import the app-level "490/490 live-verified" claim — different artifact, and the repo says so itself** |
| `fleet_deployment/iac.py` | **schema-reviewed** | Docstring says recipes always generate whether or not you run that path — and its Terraform output does not parse |
| Academy `infra/azure`, `infra/gcp` | **validated by this audit only** | No CI touches `infra/`. The runs recorded here are their entire validation history |

---

## Actions, in priority order

1. **Port the IAM hardening into `templates_tf`** — it ships to customers with an unhardened
   `ListBucket` and no sibling-prefix guard. Keep its `examples/multi-source`, which the
   canonical copy lacks.
2. **Fix the duplicate `Description`** in `splunk-migrate-fargate.yaml` (blocks any cfn-lint gate).
3. **Fix the HCL emitter** in `fleet_deployment/iac.py`, then regenerate.
4. **Regenerate `splunk-migrate/dist/`** — after (2), so it picks up the fix instead of freezing the bug.
5. **Delete** `report-output/s3-sqs-multisource-routing/superseded/terraform-moved-to-deploy/` —
   untracked, zero references, breaks nothing.
6. **Push the 20 unpushed commits**, confirm the content survives in `abstract-forwarder-hub`,
   *then* remove the nested clone. Reordering these loses history irrecoverably.
7. **Replace `academy/infra/aws-cf/` with a pointer** — but do not delete outright: ~8
   documented cross-links reference it, including two sibling infra READMEs.
8. `tofu fmt` the Academy GCP module.

Items 1–3 are live defects. Item 1 is customer-facing and security-relevant.
