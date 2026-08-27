# Per-subscription Entra app registrations for Abstract

Two automated paths, what each actually costs you, and the facts that were verified
rather than assumed.

Verified against a live Azure tenant and the live Microsoft Graph service principal
on **2026-08-03**. Where something was tested, the evidence is quoted.

---

## 1. Read this before choosing anything

**"Per subscription" is a narrower promise than it sounds.** Entra app registrations
and their Graph permissions are **tenant**-level objects. A Graph application
permission cannot be scoped to a subscription — `AuditLog.Read.All` reads the whole
directory's audit log regardless of which subscription the app is "for". What one app
per subscription actually gives you is:

- separate **credentials** per subscription, revocable independently
- separate **Azure RBAC**, scoped to that subscription — the only genuine boundary
- a clean audit story: one app, one owner, one blast radius for the *Azure* plane

It does **not** partition Graph or Microsoft 365 data access. If someone believes it
does, correct that before they design a compliance control around it.

**Today's Event Hub collection needs no app registration at all.** Diagnostic settings
authenticate with a `Send` SAS rule; the Abstract consumer uses a connection string or
Event Hubs Data Receiver RBAC. App registrations are for the *other* source set —
Microsoft Graph (Entra sign-in/audit/risk, alerts, incidents, advanced hunting) and
the Microsoft 365 unified audit log. See [azure-log-streams.md](azure-log-streams.md).

**One manual step exists and always will.** Both paths act through an identity holding
Graph `Application.ReadWrite.All` + `AppRoleAssignment.ReadWrite.All`, consented by a
Global Administrator. Nothing can automate that grant — an identity that can assign app
roles can grant *itself* anything in the directory, so an automated version of this step
would be a privilege-escalation hole. Treat that identity as **tier-0**.

---

## 2. Can Azure Policy do it, if ARM can't?

Asked and answered: **no, not directly — Policy *is* ARM.**

The `deployIfNotExists` `deployment` property is, per Microsoft, *"the full template
deployment as it would be passed to the `Microsoft.Resources/deployments` PUT API."*
Entra `applications` and `servicePrincipals` are not ARM resources — no
`/subscriptions/…` resource ID, no resource provider. So Policy can neither **evaluate**
them (`field('type')` and `existenceCondition` have nothing to match) nor **create** them.

The escape hatch is indirection:

> ARM cannot create an app registration.
> ARM **can** deploy a container that calls Graph.
> Policy **can** deploy that ARM.
> ⇒ Policy can do it, indirectly, through a pre-consented identity.

That is Path A. It works. It also spawns a privileged container in every subscription,
which is why Path B exists.

---

## 3. The two paths

| | **Path A** — Azure Policy | **Path B** — event-driven ⭐ |
|---|---|---|
| Template | [`templates/policy/abstract-appreg-policy.bicep`](../templates/policy/abstract-appreg-policy.bicep) | [`templates/automation/abstract-appreg-automation.bicep`](../templates/automation/abstract-appreg-automation.bicep) |
| Scope | Management group | One resource group |
| Mechanism | DINE → `deploymentScripts` → az CLI → Graph | Event Grid → Logic App → Graph over HTTP |
| Privileged identity lives | attached to a container **in every subscription** | in **one** resource group |
| Rights needed on targets | **Owner** (the container assigns RBAC) | Owner, but only the central identity holds it |
| Per-subscription cost | storage account + container instance per run | none |
| Audit trail | scattered across N deployment histories | one Logic App run history |
| Sees the Entra app? | **No** — gates on an ARM proxy that can drift | Yes, queries Graph directly |
| Extra requirement | `Microsoft.ContainerInstance` + `Microsoft.Storage` registered per subscription | none |

**Recommendation: Path B**, unless a customer's governance mandates that every control
arrive through Azure Policy. Same outcome, far smaller attack surface, and one workflow
for a security team to review instead of a policy that manufactures privileged containers
across the estate.

Both paths share the same Graph logic and the same defaults, so switching later is cheap.

---

## 4. What was verified, and what broke

Path B was deployed to a live tenant and driven end to end. Four real bugs surfaced that
review alone would not have caught.

### 4.1 `map()` and `filter()` do not exist in Logic Apps

They are **ARM template** functions. The workflow deployed cleanly and then failed at
runtime:

```
The template function 'filter' is not defined or not valid.
```

The Logic Apps equivalents are the **Query** and **Select** data operations. This
mattered because `filter()` was doing the permission mapping — the workflow would have
appeared to deploy fine and then failed on every single run.

### 4.2 The subscription GET omits `tags` for a Reader

`GET /subscriptions/{id}` returned **no `tags` property at all** when called by an
identity holding only Reader, while the identical call as Owner returns them:

```json
{ "id": "/subscriptions/…", "displayName": "…", "state": "Enabled",
  "subscriptionPolicies": { … } }        ← no "tags" key
```

Gating on `body('Get_subscription')?['tags']` therefore made **every** subscription look
untagged and silently skipped the entire estate. The worst class of bug in this design —
it fails *closed* and *quietly*. Fixed by reading
`/providers/Microsoft.Resources/tags/default`, and the skip response now reports
`tagsFound` so a mis-set tag is visible instead of mysterious.

### 4.3 A failed HTTP action returned `NoResponse` with no diagnosis

A `Response` action only existed on the success paths, so any failure gave the caller:

```json
{ "error": { "code": "NoResponse", "message": "The server did not receive a response from an upstream server." } }
```

Now a terminal failure handler returns the failing action names, the HTTP status, and the
three likely causes with the exact command to fix each.

### 4.4 The provisioner script reported consent success on total failure

In `abstract-ms-provisioner/Deploy-AbstractMicrosoftApp.ps1`, every grant was wrapped in
`try { … } catch {}` and the caller then printed `Ok "Consent granted"` unconditionally.
Insufficient privilege was indistinguishable from success — the failure surfaced later as
a 403 from Abstract, far from its cause. Both paths and the script now **read
`appRoleAssignments` back from Graph** and report a verified count, treating 409 Conflict
("already exists") as success and everything else as failure.

---

## 5. The permission catalogue

`Security.Read.All` **does not exist.** Not as an application permission, not as a
delegated scope. It was in the provisioner's catalogue and would have landed silently in
the skipped list, leaving a gap nobody noticed. Checked against all 707 Graph application
appRoles:

```
MISSING Security.Read.All          ← removed
Security.Read.All: delegated=no    ← not a delegated scope either
```

Real coverage comes from `SecurityEvents.Read.All` (alerts + secure scores) plus
`SecurityAlert.Read.All` and `SecurityIncident.Read.All` (alerts_v2 + incidents).

**Standard set (12), all verified to exist:**

| Permission | Unlocks |
|---|---|
| `AuditLog.Read.All` | Entra directory audit + sign-in logs |
| `SecurityAlert.Read.All` | `alerts_v2` |
| `SecurityEvents.Read.All` | legacy alerts, secure scores |
| `SecurityIncident.Read.All` | Defender XDR incidents |
| `Directory.Read.All` | directory objects for enrichment |
| `IdentityRiskEvent.Read.All` | ID Protection risk detections |
| `IdentityRiskyUser.Read.All` | risky users |
| `IdentityRiskyServicePrincipal.Read.All` | risky workload identities |
| `ThreatHunting.Read.All` | **Defender XDR advanced hunting** (was missing; added) |
| `User.Read.All` · `Group.Read.All` · `Device.Read.All` | identity/asset model enrichment |

**Opt-in extras (`-IncludeExtra`), all verified:** `AuditLogsQuery.Read.All` (unified audit
via Graph — the modern path, per-workload scopable), `ThreatIndicators.Read.All`,
`ThreatIntelligence.Read.All`, `Policy.Read.All` (Conditional Access posture),
`IdentityRiskyAgent.Read.All` (agent identity risk, 2026), `SecurityIdentitiesSensors.Read.All`,
`RoleManagementAlert.Read.Directory` (PIM alerts), `AttackSimulation.Read.All`.

**Office 365 Management API** (`c5393580-f805-4401-95e8-94b7a6ef2fc2`) exposes exactly 7
application appRoles. In use: `ActivityFeed.Read`, `ActivityFeed.ReadDlp`, and
`ServiceHealth.Read` (added — it was missing).

Selecting a permission the tenant doesn't license is harmless: it returns no data.

---

## 6. Deployment order

```
0. Bootstrap (ONCE per tenant, Global Administrator required)
     ./scripts/Deploy-AbstractAppReg.sh -a Bootstrap -g rg-abstract-automation
   Creates the user-assigned identity and consents Application.ReadWrite.All +
   AppRoleAssignment.ReadWrite.All. VERIFIES the consent and fails loudly if the
   signed-in account is not Global Admin — Application Administrator can create
   apps but cannot grant admin consent.

1. Deploy Path B
     ./scripts/Deploy-AbstractAppReg.sh -a DeployB -g rg-abstract-automation -k <vault>
   Event trigger is OFF deliberately.

2. Grant the identity what it needs
     ./scripts/Deploy-AbstractAppReg.sh -a Grant -g <rg> -k <vault> -s <sub-id>
   Key Vault Secrets Officer on the vault (or a get/set/list access policy —
   the script detects which model the vault uses), and Owner on each target
   subscription because the workflow assigns RBAC there.

3. Test ONE subscription
     ./scripts/Deploy-AbstractAppReg.sh -a Onboard -g <rg> -s <sub-id>
   A consent shortfall returns HTTP 500 with the exact verified/expected count
   and creates NO secret, so nothing is left half-provisioned.

4. Backfill, then automate
   Same Onboard command per existing subscription. Once a manual run succeeds,
   redeploy with enableEventTrigger=true.

5. Audit
     ./scripts/Deploy-AbstractAppReg.sh -a Status
     ./scripts/Deploy-AbstractAppReg.sh -a Verify --app-id <app-id>
   Verify names every missing permission, so "consent looks fine but Abstract
   gets 403" is a one-command diagnosis.
```

Every step is idempotent. Re-running never mints a duplicate app, and never rotates a
secret that still has more than 30 days left.

---

## 7. Sentinel destination — the same hardening

[`sentinel-destination-with-app.bicep`](../templates/destinations/sentinel-destination-with-app.bicep)
already created an app via `deploymentScripts`. Its inline 16-line script had three
problems, now fixed in
[`scripts/sentinel-app-deploymentscript.sh`](../templates/destinations/scripts/sentinel-app-deploymentscript.sh):

1. **Secret churn.** It called `az ad app credential reset --append` on *every*
   deployment. Re-running the template produced a new secret and a new Key Vault version
   while the value configured in Abstract kept working — until someone assumed the newest
   version was the right one. Now it rotates only when no secret exists or the current one
   expires within 30 days. `forceSecretRotation=true` for a deliberate rotation.
2. **Silent partial success.** Every step was unguarded, so an app created without a
   service principal still reported success and the DCR role assignment failed later with
   an opaque `PrincipalNotFound`. Now each step is checked, and the SP wait is 30s
   precisely because that race is the classic one.
3. **No verification.** Nothing read back what it created. Now app, SP and secret are all
   confirmed present before the script reports success.

This app needs **no** Graph permissions and **no** admin consent — it is purely an
identity that receives DCR RBAC (Monitoring Metrics Publisher + Monitoring Contributor).
That is why there is no consent logic in it.

---

## 8. Security posture, stated plainly

The tier-0 identity is unavoidable in any automated design. What you control is exposure:

- **One identity, one place** (Path B) instead of privileged containers estate-wide.
- **Restrict who can attach it.** It is a user-assigned identity, so only principals with
  `Managed Identity Operator` on it can use it. Grant that narrowly — it is the real
  control here.
- **Secrets are central and never logged.** The Key Vault write has `secureData` on both
  inputs and outputs, so no secret reaches run history, deployment outputs or stdout.
- **The tag gate is the opt-in.** Without it, every subscription that appears gets a
  tier-0 credential created with no explicit decision. Keep it on.
- **Rotation is a real gap.** Nothing here rotates secrets on a schedule; it only avoids
  churning them. A scheduled re-run with `forceSecretRotation` plus an Abstract-side
  credential update is the missing piece, and it is not built yet.

---

## 9. Sources

- [`deployIfNotExists` effect — what the `deployment` property contains](https://learn.microsoft.com/en-us/azure/governance/policy/concepts/effect-deploy-if-not-exists)
- [Microsoft Graph permissions reference](https://learn.microsoft.com/en-us/graph/permissions-reference)
- [Deployment scripts in ARM templates](https://learn.microsoft.com/en-us/azure/azure-resource-manager/templates/deployment-script-template)
- [Logic Apps workflow definition language — data operations](https://learn.microsoft.com/en-us/azure/logic-apps/logic-apps-workflow-definition-language)
- [Office 365 Management Activity API](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-reference)
- [Azure resource naming rules](https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/resource-name-rules)
