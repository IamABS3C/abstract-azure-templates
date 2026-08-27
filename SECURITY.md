# Security

## Reporting a vulnerability

Email **security@abstract.security**. Please do not open a public issue for a
vulnerability.

## What this repository does and does not handle

**It never stores a credential.** The service-account key Abstract authenticates with is
created **out of band** and uploaded directly to Abstract:

```bash
gcloud iam service-accounts keys create abstract-key.json --iam-account="$SA"
# upload to Abstract, then
rm abstract-key.json
```

`create_service_account_key` defaults to **false** precisely because generating it in
Terraform writes a private key into state — and on the Cloud Shell path that state is a
file in a home directory.

## What to check before you deploy

| | |
|---|---|
| **State location** | Every root ships `backend.tf.example`. Configure it **before** the first apply. State for an organization-scoped sink in a Cloud Shell home directory is a real risk — Google deletes those after 120 days of inactivity |
| **Key rotation** | There is no automatic expiry unless `constraints/iam.serviceAccountKeyExpiryHours` is set. Rotate on your normal cadence |
| **Workspace delegation is domain-wide** | Not project-scoped. A leaked Workspace key reads the entire Workspace audit trail regardless of any Google Cloud IAM control. Store it accordingly |
| **`terraform.tfvars` is gitignored** | It holds your organization and project IDs. Keep it that way |

## Least privilege

- `roles/pubsub.subscriber` on **one subscription**, never project-wide
- Workspace scopes are the two `admin.reports.*.readonly` and nothing else
- Every binding is `_iam_member` (additive), never `_iam_policy` (authoritative), so nothing
  here can silently remove a grant somebody else made
- `05-audit-config` **refuses** `allServices` without explicit acknowledgement, because that
  resource is authoritative and would remove audit log types it does not list

## Known unverified items

Tracked honestly in [docs/VERIFIED.md](docs/VERIFIED.md) rather than assumed:

- Whether `roles/pubsub.subscriber` alone suffices for Abstract's connector — the role does
  not include `pubsub.subscriptions.get`
- The VPC Service Controls ingress rules in [docs/VPC-SC.md](docs/VPC-SC.md), which have not
  been executed against a protected organization
