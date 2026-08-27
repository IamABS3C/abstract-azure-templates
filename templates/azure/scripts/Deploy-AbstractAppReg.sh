#!/usr/bin/env bash
# =============================================================================
#  Abstract Security - per-subscription Entra app registration driver
#
#  Covers the parts no template can:
#
#    Bootstrap  create the user-assigned managed identity and grant it Graph
#               Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All.
#               NEEDS GLOBAL ADMINISTRATOR. Runs ONCE per tenant. Nothing can
#               automate this - if it could, it would be a privilege-escalation
#               hole, because the identity being consented can then grant itself
#               anything in the directory.
#
#    DeployA    assign the Azure Policy path at a management group
#               (templates/policy/abstract-appreg-policy.bicep)
#    DeployB    deploy the event-driven path into one resource group
#               (templates/automation/abstract-appreg-automation.bicep)  RECOMMENDED
#
#    Grant      give the acting identity what it needs on the target
#               subscriptions and the central Key Vault
#    Onboard    onboard ONE subscription now (Path B) - also the backfill tool
#    Remediate  Path A only: backfill existing subscriptions via a remediation task
#    Status     what exists today: identity, consent, apps, secrets
#    Verify     re-check admin consent for an already-created app and say
#               precisely which permissions are missing
#
#  Usage
#    ./Deploy-AbstractAppReg.sh -a Bootstrap -g rg-abstract-automation -l eastus
#    ./Deploy-AbstractAppReg.sh -a DeployB   -g rg-abstract-automation -k kv-abstract
#    ./Deploy-AbstractAppReg.sh -a Grant     -g rg-abstract-automation -k kv-abstract -s <sub-id>
#    ./Deploy-AbstractAppReg.sh -a Onboard   -g rg-abstract-automation -s <sub-id>
#    ./Deploy-AbstractAppReg.sh -a DeployA   -m <mg-id> -g rg-abstract-automation -k kv-abstract
#    ./Deploy-AbstractAppReg.sh -a Status    -g rg-abstract-automation
#    ./Deploy-AbstractAppReg.sh -a Verify    --app-id <app-id>
#
#  Never prints or stores a client secret. Secrets live only in Key Vault.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
POLICY_TEMPLATE="${SCRIPT_DIR}/../templates/policy/abstract-appreg-policy.bicep"
AUTOMATION_TEMPLATE="${SCRIPT_DIR}/../templates/automation/abstract-appreg-automation.bicep"

GRAPH="https://graph.microsoft.com/v1.0"
GRAPH_APP_ID="00000003-0000-0000-c000-000000000000"

# Graph application permissions the ACTING identity needs. Nothing more: it must
# create apps and grant them roles, and that is all.
BOOTSTRAP_PERMS=("Application.ReadWrite.All" "AppRoleAssignment.ReadWrite.All")

ACTION=""; MG_ID=""; RG=""; LOCATION="eastus"; KV_NAME=""; SUB_ID=""
IDENTITY_NAME="id-abstract-appreg"; IDENTITY_ID=""; APP_ID=""
WORKFLOW_NAME="abstract-appreg-onboarder"; PREFIX="abs"; ASSUME_YES=false

KV_SECRETS_OFFICER="b86a8fe4-44ce-4948-aee5-eccb2c155cd6"
OWNER_ROLE="8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

say()  { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[0;32m  + %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
die()  { printf '\033[0;31m  X %s\033[0m\n' "$*" >&2; exit 1; }

usage() { sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    -a|--action)        ACTION="$2"; shift 2 ;;
    -m|--management-group) MG_ID="$2"; shift 2 ;;
    -g|--resource-group) RG="$2"; shift 2 ;;
    -l|--location)      LOCATION="$2"; shift 2 ;;
    -k|--key-vault)     KV_NAME="$2"; shift 2 ;;
    -s|--subscription)  SUB_ID="$2"; shift 2 ;;
    -i|--identity)      IDENTITY_ID="$2"; shift 2 ;;
    -n|--identity-name) IDENTITY_NAME="$2"; shift 2 ;;
    -w|--workflow)      WORKFLOW_NAME="$2"; shift 2 ;;
    -x|--prefix)        PREFIX="$2"; shift 2 ;;
    --app-id)           APP_ID="$2"; shift 2 ;;
    -y|--yes)           ASSUME_YES=true; shift ;;
    -h|--help)          usage ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ -z "$ACTION" ]] && usage
command -v az >/dev/null || die "az CLI not found."
az account show >/dev/null 2>&1 || die "not logged in. Run 'az login'."

confirm() {
  $ASSUME_YES && return 0
  read -r -p "$1 [y/N] " r; [[ "$r" =~ ^[Yy]$ ]]
}

# ---------------------------------------------------------------------------
# Resolve the acting identity's Graph appRole IDs. An unresolved name is fatal:
# skipping it silently is how a permission gap reaches production.
# ---------------------------------------------------------------------------
resolve_graph_roles() {
  local sp
  sp=$(az rest --method GET \
    --url "${GRAPH}/servicePrincipals(appId='${GRAPH_APP_ID}')?\$select=id,appRoles" \
    --headers "Content-Type=application/json")
  GRAPH_SP_ID=$(echo "$sp" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  ROLE_PAIRS=$(echo "$sp" | PERMS="${BOOTSTRAP_PERMS[*]}" python3 - <<'PY'
import json, os, sys
roles = {r['value']: r['id'] for r in json.load(sys.stdin).get('appRoles', [])
         if 'Application' in r.get('allowedMemberTypes', [])}
want = os.environ['PERMS'].split()
missing = [w for w in want if w not in roles]
if missing:
    sys.stderr.write("Unresolved: %s\n" % ', '.join(missing)); sys.exit(1)
print(' '.join('%s=%s' % (w, roles[w]) for w in want))
PY
  ) || die "could not resolve the bootstrap permissions against Graph"
}

# ---------------------------------------------------------------------------
# Bootstrap - the one manual step
# ---------------------------------------------------------------------------
do_bootstrap() {
  [[ -z "$RG" ]] && die "-g <resource-group> is required for Bootstrap."

  say "What this does, and why it cannot be automated"
  cat <<'EOF'
  Creates a user-assigned managed identity and grants it two Microsoft Graph
  application permissions:

    Application.ReadWrite.All        create and modify app registrations
    AppRoleAssignment.ReadWrite.All  grant admin consent to those apps

  The second one is the reason this step needs a Global Administrator and can
  never be automated: an identity that can assign app roles can grant ITSELF any
  permission in the directory. It is a tier-0 credential. Both onboarding paths
  need it; neither can create it for you.

  Restrict who can use it: it is a user-assigned identity, so only principals
  with 'Managed Identity Operator' on it can attach it to a resource. Grant that
  narrowly.
EOF
  confirm "Proceed?" || { warn "aborted"; exit 0; }

  az group create -n "$RG" -l "$LOCATION" -o none
  say "Creating managed identity '$IDENTITY_NAME'"
  az identity create -g "$RG" -n "$IDENTITY_NAME" -l "$LOCATION" -o none 2>/dev/null || ok "already exists"
  local principal_id client_id resource_id
  principal_id=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query principalId -o tsv)
  client_id=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query clientId -o tsv)
  resource_id=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query id -o tsv)
  ok "principalId $principal_id"
  ok "clientId    $client_id"

  say "Waiting for directory replication"
  sleep 20

  resolve_graph_roles
  say "Granting Graph permissions (requires Global Administrator)"
  local granted=0 already=0 failed=0
  for pair in $ROLE_PAIRS; do
    local pname="${pair%%=*}" rid="${pair##*=}"
    if az rest --method POST \
        --url "${GRAPH}/servicePrincipals/${principal_id}/appRoleAssignments" \
        --headers "Content-Type=application/json" \
        --body "{\"principalId\":\"${principal_id}\",\"resourceId\":\"${GRAPH_SP_ID}\",\"appRoleId\":\"${rid}\"}" \
        -o none 2>/tmp/bs-err; then
      ok "granted $pname"; granted=$((granted+1))
    elif grep -qiE 'already exists|Conflict' /tmp/bs-err; then
      ok "$pname already granted"; already=$((already+1))
    else
      warn "$pname FAILED: $(tr -d '\n' < /tmp/bs-err | head -c 300)"; failed=$((failed+1))
    fi
  done

  # Verify by reading back, never by trusting the POSTs.
  say "Verifying against Graph"
  sleep 10
  local verified
  verified=$(az rest --method GET \
    --url "${GRAPH}/servicePrincipals/${principal_id}/appRoleAssignments" \
    --headers "Content-Type=application/json" | ROLE_PAIRS="$ROLE_PAIRS" python3 - <<'PY'
import json, os, sys
have = {a['appRoleId'] for a in json.load(sys.stdin).get('value', [])}
want = [p.split('=')[1] for p in os.environ['ROLE_PAIRS'].split()]
print(sum(1 for w in want if w in have))
PY
  )
  if [[ "$verified" -ne "${#BOOTSTRAP_PERMS[@]}" ]]; then
    warn "CONSENT INCOMPLETE: ${verified}/${#BOOTSTRAP_PERMS[@]} verified."
    warn "You are almost certainly not Global Administrator or Privileged Role Administrator."
    warn "Application Administrator can create apps but CANNOT grant admin consent."
    die "bootstrap incomplete - neither onboarding path will work until this is fixed"
  fi
  ok "consent VERIFIED: ${verified}/${#BOOTSTRAP_PERMS[@]}"

  say "Bootstrap complete - use these values"
  cat <<EOF
  managedIdentityResourceId = $resource_id
  managedIdentityClientId   = $client_id
  identity principalId      = $principal_id   (grant this KV + subscription RBAC)

  Next:  ./Deploy-AbstractAppReg.sh -a DeployB -g $RG -k <key-vault-name>
EOF
}

# ---------------------------------------------------------------------------
# DeployB - event-driven path (recommended)
# ---------------------------------------------------------------------------
do_deploy_b() {
  [[ -z "$RG" ]] && die "-g <resource-group> is required."
  [[ -z "$KV_NAME" ]] && die "-k <key-vault-name> is required."
  [[ -f "$AUTOMATION_TEMPLATE" ]] || die "template not found: $AUTOMATION_TEMPLATE"

  local resource_id client_id
  if [[ -n "$IDENTITY_ID" ]]; then
    resource_id="$IDENTITY_ID"
    client_id=$(az identity show --ids "$IDENTITY_ID" --query clientId -o tsv)
  else
    resource_id=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query id -o tsv 2>/dev/null) \
      || die "identity '$IDENTITY_NAME' not found in $RG - run -a Bootstrap first, or pass -i"
    client_id=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query clientId -o tsv)
  fi

  say "Validating"
  az deployment group validate -g "$RG" --template-file "$AUTOMATION_TEMPLATE" \
    --parameters managedIdentityResourceId="$resource_id" \
                 managedIdentityClientId="$client_id" \
                 keyVaultName="$KV_NAME" \
                 workflowName="$WORKFLOW_NAME" \
    --output none
  ok "validates"

  say "Deploying the workflow (event trigger OFF - prove it with one subscription first)"
  az deployment group create -g "$RG" --template-file "$AUTOMATION_TEMPLATE" \
    --parameters managedIdentityResourceId="$resource_id" \
                 managedIdentityClientId="$client_id" \
                 keyVaultName="$KV_NAME" \
                 workflowName="$WORKFLOW_NAME" \
                 enableEventTrigger=false \
    --query "properties.outputs.nextSteps.value" -o json
  ok "deployed"
  warn "Now: -a Grant (KV + subscription RBAC), then -a Onboard -s <sub-id> to test."
}

# ---------------------------------------------------------------------------
# DeployA - policy path
# ---------------------------------------------------------------------------
do_deploy_a() {
  [[ -z "$MG_ID" ]] && die "-m <management-group-id> is required."
  [[ -z "$KV_NAME" ]] && die "-k <key-vault-name> is required."
  [[ -z "$RG" ]] && die "-g <resource-group holding the identity> is required."

  warn "Path A spawns a privileged deploymentScript CONTAINER in every target subscription."
  warn "Path B (-a DeployB) achieves the same thing with one central identity and no per-subscription compute."
  confirm "Continue with the policy path anyway?" || { warn "aborted"; exit 0; }

  local resource_id client_id kv_rg kv_sub
  resource_id=${IDENTITY_ID:-$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query id -o tsv)}
  client_id=$(az identity show --ids "$resource_id" --query clientId -o tsv)
  kv_rg=$(az keyvault show -n "$KV_NAME" --query resourceGroup -o tsv)
  kv_sub=$(az keyvault show -n "$KV_NAME" --query id -o tsv | cut -d/ -f3)

  say "Deploying policy definition + assignment at $MG_ID (AuditIfNotExists, DoNotEnforce)"
  az deployment mg create --management-group-id "$MG_ID" --location "$LOCATION" \
    --name "abstract-appreg" --template-file "$POLICY_TEMPLATE" \
    --parameters managedIdentityResourceId="$resource_id" \
                 managedIdentityClientId="$client_id" \
                 centralKeyVaultName="$KV_NAME" \
                 centralKeyVaultResourceGroup="$kv_rg" \
                 centralKeyVaultSubscriptionId="$kv_sub" \
                 namePrefix="$PREFIX" \
                 effect=AuditIfNotExists \
                 enforcementMode=DoNotEnforce \
    --query "properties.outputs" -o json
  ok "assigned in report-only mode"
  warn "Read Policy > Compliance, then re-run with effect=DeployIfNotExists enforcementMode=Default."
}

# ---------------------------------------------------------------------------
# Grant - RBAC the acting identity needs
# ---------------------------------------------------------------------------
do_grant() {
  local principal_id resource_id
  resource_id=${IDENTITY_ID:-$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query id -o tsv)}
  principal_id=$(az identity show --ids "$resource_id" --query principalId -o tsv)
  ok "identity principalId $principal_id"

  if [[ -n "$KV_NAME" ]]; then
    say "Key Vault Secrets Officer on $KV_NAME"
    local kv_id
    kv_id=$(az keyvault show -n "$KV_NAME" --query id -o tsv)
    if [[ "$(az keyvault show -n "$KV_NAME" --query properties.enableRbacAuthorization -o tsv)" == "true" ]]; then
      az role assignment create --assignee-object-id "$principal_id" \
        --assignee-principal-type ServicePrincipal \
        --role "$KV_SECRETS_OFFICER" --scope "$kv_id" -o none 2>/dev/null \
        && ok "granted" || ok "already present"
    else
      warn "vault uses ACCESS POLICIES, not RBAC - setting a set/get policy instead"
      az keyvault set-policy -n "$KV_NAME" --object-id "$principal_id" \
        --secret-permissions get set list -o none && ok "access policy set"
    fi
  fi

  if [[ -n "$SUB_ID" ]]; then
    say "Owner on subscription $SUB_ID"
    warn "Owner is needed because the workflow assigns RBAC. Contributor + User Access Administrator is the narrower equivalent."
    az role assignment create --assignee-object-id "$principal_id" \
      --assignee-principal-type ServicePrincipal \
      --role "$OWNER_ROLE" --scope "/subscriptions/${SUB_ID}" -o none 2>/dev/null \
      && ok "granted" || ok "already present"
  fi

  [[ -z "$KV_NAME" && -z "$SUB_ID" ]] && warn "nothing to do - pass -k and/or -s"
}

# ---------------------------------------------------------------------------
# Onboard - one subscription, now (Path B). Also the backfill tool.
# ---------------------------------------------------------------------------
do_onboard() {
  [[ -z "$RG" ]] && die "-g <resource-group> is required."
  [[ -z "$SUB_ID" ]] && die "-s <subscription-id> is required."

  say "Fetching the workflow callback URL"
  local url
  url=$(az rest --method POST \
    --url "https://management.azure.com$(az logic workflow show -g "$RG" -n "$WORKFLOW_NAME" --query id -o tsv)/triggers/manual/listCallbackUrl?api-version=2016-06-01" \
    --query value -o tsv) || die "could not fetch the callback URL - is the workflow deployed?"
  ok "resolved (URL contains a SAS signature and is NOT printed)"

  say "Onboarding subscription $SUB_ID"
  local resp
  resp=$(curl -s -X POST "$url" -H "Content-Type: application/json" \
    -d "{\"subscriptionId\":\"${SUB_ID}\"}")
  echo "$resp" | python3 -m json.tool 2>/dev/null || echo "$resp"

  if echo "$resp" | grep -q '"status": *"onboarded"'; then
    ok "onboarded - secret is in Key Vault, never in this output"
  elif echo "$resp" | grep -q 'consent-incomplete'; then
    die "consent shortfall - the identity is missing AppRoleAssignment.ReadWrite.All consent. Nothing was half-provisioned; no secret was created."
  elif echo "$resp" | grep -q 'skipped-not-tagged'; then
    warn "subscription is not tagged for onboarding - tag it, or deploy with tagName='' to disable the gate"
  else
    warn "unexpected response - check the Logic App run history for the Graph error body"
  fi
}

# ---------------------------------------------------------------------------
# Remediate - Path A backfill
# ---------------------------------------------------------------------------
do_remediate() {
  [[ -z "$MG_ID" ]] && die "-m <management-group-id> is required."
  local scope="/providers/Microsoft.Management/managementGroups/${MG_ID}"
  local aid
  aid=$(az policy assignment list --scope "$scope" \
    --query "[?name=='${PREFIX}-appreg'].id | [0]" -o tsv)
  [[ -z "$aid" || "$aid" == "None" ]] && die "assignment '${PREFIX}-appreg' not found - run -a DeployA first"

  say "Creating a remediation task"
  az policy remediation create --name "rem-${PREFIX}-appreg" \
    --policy-assignment "$aid" --management-group "$MG_ID" \
    --resource-discovery-mode ReEvaluateCompliance -o none \
    && ok "created" || warn "not created (may already exist)"
  warn "Remediation is asynchronous. Track it under Policy > Remediation."
  warn "Each remediated subscription runs a privileged container - watch the first one closely."
}

# ---------------------------------------------------------------------------
# Verify - re-check consent for an existing app
# ---------------------------------------------------------------------------
do_verify() {
  [[ -z "$APP_ID" ]] && die "--app-id <app-id> is required."
  local sp_id
  sp_id=$(az ad sp show --id "$APP_ID" --query id -o tsv) || die "no service principal for app $APP_ID"

  say "Comparing requested permissions with granted app-role assignments"
  local requested granted
  requested=$(az ad app show --id "$APP_ID" --query "requiredResourceAccess[?resourceAppId=='${GRAPH_APP_ID}'].resourceAccess[].id" -o json)
  granted=$(az rest --method GET --url "${GRAPH}/servicePrincipals/${sp_id}/appRoleAssignments" \
    --headers "Content-Type=application/json" --query "value[].appRoleId" -o json)
  local rolemap
  rolemap=$(az rest --method GET \
    --url "${GRAPH}/servicePrincipals(appId='${GRAPH_APP_ID}')?\$select=appRoles" \
    --headers "Content-Type=application/json")

  # `set -e` would abort on the python exit(1) before we could branch on it, so
  # capture the status explicitly instead of reading $? after the fact.
  local rc=0
  REQ="$requested" GRA="$granted" MAP="$rolemap" python3 - <<'PY' || rc=$?
import json, os, sys
req = set(json.loads(os.environ['REQ']))
gra = set(json.loads(os.environ['GRA']))
names = {r['id']: r['value'] for r in json.loads(os.environ['MAP']).get('appRoles', [])}
missing = sorted(names.get(i, i) for i in req - gra)
have = sorted(names.get(i, i) for i in req & gra)
extra = sorted(names.get(i, i) for i in gra - req)
print("  granted   : %d/%d" % (len(have), len(req)))
for h in have: print("    + " + h)
if missing:
    print("\n  MISSING (Abstract will get 403 for these):")
    for m in missing: print("    - " + m)
if extra:
    print("\n  granted but not requested (review - possible over-permission):")
    for e in extra: print("    ? " + e)
sys.exit(1 if missing else 0)
PY
  if [[ $rc -eq 0 ]]; then ok "consent COMPLETE"; else die "consent INCOMPLETE - grant the missing permissions"; fi
}

# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------
do_status() {
  if [[ -n "$RG" ]]; then
    say "Managed identity"
    az identity show -g "$RG" -n "$IDENTITY_NAME" \
      --query "{name:name, clientId:clientId, principalId:principalId}" -o table 2>/dev/null \
      || warn "identity '$IDENTITY_NAME' not found in $RG"

    local pid
    if pid=$(az identity show -g "$RG" -n "$IDENTITY_NAME" --query principalId -o tsv 2>/dev/null); then
      say "Its Graph consent"
      az rest --method GET --url "${GRAPH}/servicePrincipals/${pid}/appRoleAssignments" \
        --headers "Content-Type=application/json" --query "length(value)" -o tsv 2>/dev/null \
        | xargs -I{} echo "  app-role assignments: {} (expect ${#BOOTSTRAP_PERMS[@]})"
    fi

    say "Workflow"
    az logic workflow show -g "$RG" -n "$WORKFLOW_NAME" \
      --query "{name:name, state:state, location:location}" -o table 2>/dev/null \
      || warn "workflow '$WORKFLOW_NAME' not deployed"
  fi

  say "Abstract app registrations"
  az ad app list --filter "startswith(displayName,'Abstract-')" \
    --query "[].{displayName:displayName, appId:appId}" -o table 2>/dev/null | head -30

  if [[ -n "$KV_NAME" ]]; then
    say "Secrets in $KV_NAME (names + expiry only)"
    az keyvault secret list --vault-name "$KV_NAME" \
      --query "[?starts_with(name,'abstract-')].{name:name, expires:attributes.expires}" -o table 2>/dev/null \
      || warn "cannot list secrets - check your access to the vault"
  fi

  if [[ -n "$MG_ID" ]]; then
    say "Policy assignment (Path A)"
    az policy assignment list --scope "/providers/Microsoft.Management/managementGroups/${MG_ID}" \
      --query "[?name=='${PREFIX}-appreg'].{name:name, enforcement:enforcementMode}" -o table
  fi
}

case "$ACTION" in
  Bootstrap|bootstrap) do_bootstrap ;;
  DeployA|deploya)     do_deploy_a ;;
  DeployB|deployb)     do_deploy_b ;;
  Grant|grant)         do_grant ;;
  Onboard|onboard)     do_onboard ;;
  Remediate|remediate) do_remediate ;;
  Verify|verify)       do_verify ;;
  Status|status)       do_status ;;
  *) die "unknown action '$ACTION'" ;;
esac
