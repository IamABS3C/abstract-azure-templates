# Contributing

## The one rule that matters

**Label provenance honestly.** Every artifact declares how well it is evidenced, and a node
never advertises a tier higher than its weakest artifact. An unproven claim marked
`deployed` is worse than no claim at all — it sends someone into a customer's cloud with
false confidence.

| Tier | You may claim it when |
|---|---|
| `deployed` | You executed it against a real cloud organization and have the output |
| `planned` | `terraform plan`, `az deployment what-if` or a CFN changeset ran against real credentials |
| `validated` | A compiler or linter passed locally — `terraform validate`, `az bicep build`, `cfn-lint` |
| `schema-reviewed` | Written against the current provider schema, never executed |
| `cited` | Reproduced from named vendor documentation, with the URL |

`ci/validate_corpus.py` fails the build if an artifact claims `validated` or better without
recording the command that was actually run and its output. The gate exists to protect you,
not to catch you — if you did not run it, say `schema-reviewed` and move on.

## Before every commit

```bash
python3 -m pip install -r requirements.txt
python3 ci/validate_corpus.py          # must report 0 errors
python3 ci/validate_corpus.py --strict # warnings become failures
```

## Adding a node

A **node** is one deployable path: this cloud, this service, over this transport, at this
scope.

1. Copy an existing `corpus/<cloud>/*.yml`.
2. Fill in `decision` **first.** If you cannot name the forks and say which person answers
   each one, you do not yet understand the path well enough to document it. This block is
   the valuable part; the YAML around it is packaging.
3. Add artifacts. Run the real validator for each and paste the actual command and its
   output into `validation`.
4. Point `external_path` at the vendored template under `templates/`, **repo-relative**.
   Never an absolute path — those leak a local checkout onto a reader's screen.
5. Re-run the validator until clean.

## Working on templates

Each cloud keeps its native toolchain. Do not normalise them onto one tool.

```bash
# GCP
cd templates/gcp/terraform
terraform init -backend=false && terraform validate
tflint --chdir=modules/log-export

# Azure
az bicep build --file templates/azure/bicep/source/eventhub-source.bicep

# AWS
cfn-lint templates/aws/cloudformation/*.yaml
```

## Adding a GCP log category

Add an entry to `local.log_catalog` in
`templates/gcp/terraform/modules/log-export/log_catalog.tf` with a `clause` and a volume
`tier`. Constrain the clause to a specific log stream — an unconstrained `protoPayload`
match will pull in far more than intended. Then add a guard case in
`templates/gcp/terraform/tests/`.

## Style

- British spelling in prose, except where quoting a vendor string verbatim.
- Match the surrounding file's conventions rather than introducing your own.
- Prefer a table or a command over a paragraph.
- State what you verified and how. "Should work" is not a claim.
