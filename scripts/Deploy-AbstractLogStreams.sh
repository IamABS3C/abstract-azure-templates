#!/usr/bin/env bash
# =============================================================================
#  Abstract Security - Azure log streams at scale
#  Deploy / grant / remediate driver for templates/policy/abstract-logstreams-policy.bicep
#
#  Three things have to happen for at-scale onboarding to actually work, and
#  only the first is a template. This script does all three.
#
#    Deploy     assign the policies at a management group
#    Grant      give each assignment identity Azure Event Hubs Data Owner on the
#               namespace - the template cannot do this because the namespace
#               normally sits outside the management group's assignment scope
#    Remediate  backfill EXISTING resources. DeployIfNotExists fires on create
#               or update only; without a remediation task your current estate
#               stays non-compliant forever and the hub looks mysteriously quiet
#    Status     compliance summary - how many subscriptions and resources are on
#
#  Usage
#    ./Deploy-AbstractLogStreams.sh -a Deploy    -m <mg-id> -p params.json [-l eastus]
#    ./Deploy-AbstractLogStreams.sh -a Grant     -m <mg-id> -n <eh-namespace-resource-id>
#    ./Deploy-AbstractLogStreams.sh -a Remediate -m <mg-id>
#    ./Deploy-AbstractLogStreams.sh -a Status    -m <mg-id>
#    ./Deploy-AbstractLogStreams.sh -a All       -m <mg-id> -p params.json -n <ns-id>
#
#  Requires: az CLI, logged in, with Owner (or Resource Policy Contributor +
#  User Access Administrator) on the target management group.
#  Reads no secrets and writes none.
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEMPLATE="${SCRIPT_DIR}/../templates/policy/abstract-logstreams-policy.bicep"

ACTION=""
MG_ID=""
PARAM_FILE=""
NAMESPACE_ID=""
LOCATION="eastus"
PREFIX="abs"
DEPLOYMENT_NAME="abstract-logstreams"

EH_DATA_OWNER="f526a384-b230-433a-b45c-95f59c4a2dec"   # Azure Event Hubs Data Owner

usage() { sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }

while getopts "a:m:p:n:l:x:d:h" opt; do
  case "$opt" in
    a) ACTION="$OPTARG" ;;
    m) MG_ID="$OPTARG" ;;
    p) PARAM_FILE="$OPTARG" ;;
    n) NAMESPACE_ID="$OPTARG" ;;
    l) LOCATION="$OPTARG" ;;
    x) PREFIX="$OPTARG" ;;
    d) DEPLOYMENT_NAME="$OPTARG" ;;
    h|*) usage ;;
  esac
done

[[ -z "$ACTION" || -z "$MG_ID" ]] && usage
command -v az >/dev/null || { echo "ERROR: az CLI not found." >&2; exit 1; }
az account show >/dev/null 2>&1 || { echo "ERROR: not logged in. Run 'az login'." >&2; exit 1; }

say()  { printf '\n\033[1;35m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m  ! %s\033[0m\n' "$*"; }
ok()   { printf '\033[0;32m  + %s\033[0m\n' "$*"; }

# -----------------------------------------------------------------------------
# Deploy - assign the policies at the management group
# -----------------------------------------------------------------------------
do_deploy() {
  [[ -z "$PARAM_FILE" ]] && { echo "ERROR: -p <parameters.json> is required for Deploy." >&2; exit 1; }
  [[ -f "$PARAM_FILE" ]] || { echo "ERROR: parameter file not found: $PARAM_FILE" >&2; exit 1; }

  say "Validating against management group $MG_ID"
  az deployment mg validate \
    --management-group-id "$MG_ID" \
    --location "$LOCATION" \
    --name "$DEPLOYMENT_NAME" \
    --template-file "$TEMPLATE" \
    --parameters "@$PARAM_FILE" \
    --output none
  ok "template validates"

  say "Previewing changes (what-if)"
  az deployment mg what-if \
    --management-group-id "$MG_ID" \
    --location "$LOCATION" \
    --name "$DEPLOYMENT_NAME" \
    --template-file "$TEMPLATE" \
    --parameters "@$PARAM_FILE" || warn "what-if unavailable at this scope; continuing"

  read -r -p "Proceed with the deployment? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]] || { warn "aborted by user"; exit 0; }

  say "Deploying"
  az deployment mg create \
    --management-group-id "$MG_ID" \
    --location "$LOCATION" \
    --name "$DEPLOYMENT_NAME" \
    --template-file "$TEMPLATE" \
    --parameters "@$PARAM_FILE" \
    --query "properties.outputs" -o json
  ok "policies assigned at $MG_ID"
  warn "Not finished: run -a Grant, then -a Remediate."
}

# -----------------------------------------------------------------------------
# Grant - Azure Event Hubs Data Owner for every assignment identity
# -----------------------------------------------------------------------------
do_grant() {
  [[ -z "$NAMESPACE_ID" ]] && { echo "ERROR: -n <event-hubs-namespace-resource-id> is required for Grant." >&2; exit 1; }

  say "Collecting policy assignment identities under $MG_ID"
  local scope="/providers/Microsoft.Management/managementGroups/${MG_ID}"
  local principals
  principals=$(az policy assignment list --scope "$scope" \
    --query "[?starts_with(name, '${PREFIX}-')].{name:name, pid:identity.principalId}" -o json)

  local count
  count=$(echo "$principals" | python3 -c 'import json,sys; print(len(json.load(sys.stdin)))')
  [[ "$count" == "0" ]] && { warn "no assignments found with prefix '${PREFIX}-' - did Deploy run?"; exit 1; }
  ok "found $count assignment(s)"

  echo "$principals" | python3 -c 'import json,sys
for a in json.load(sys.stdin):
    if a.get("pid"): print(a["name"], a["pid"])' | while read -r name pid; do
    say "Granting Azure Event Hubs Data Owner to $name ($pid)"
    if az role assignment create \
        --assignee-object-id "$pid" \
        --assignee-principal-type ServicePrincipal \
        --role "$EH_DATA_OWNER" \
        --scope "$NAMESPACE_ID" \
        --output none 2>/dev/null; then
      ok "granted"
    else
      warn "already present or insufficient rights - verify manually"
    fi
  done
}

# -----------------------------------------------------------------------------
# Remediate - backfill existing resources
# -----------------------------------------------------------------------------
do_remediate() {
  local scope="/providers/Microsoft.Management/managementGroups/${MG_ID}"

  # NOTE: 'az policy state trigger-scan' has no management-group scope - it scans the
  # CURRENT subscription only. Remediation below uses --resource-discovery-mode
  # ReEvaluateCompliance, which re-evaluates in scope on its own, so this is a
  # convenience for the logged-in subscription rather than an estate-wide scan.
  say "Triggering a compliance scan for the current subscription (estate-wide re-evaluation is handled by ReEvaluateCompliance below)"
  az policy state trigger-scan --no-wait 2>/dev/null || warn "scan trigger skipped; continuing"

  say "Creating remediation tasks"
  local assignments
  assignments=$(az policy assignment list --scope "$scope" \
    --query "[?starts_with(name, '${PREFIX}-')].{name:name, id:id, def:policyDefinitionId}" -o json)

  echo "$assignments" | python3 -c 'import json,sys
for a in json.load(sys.stdin): print(a["name"], a["id"], a["def"])' | while read -r name aid defid; do
    if [[ "$defid" == *"policySetDefinitions"* ]]; then
      # Initiative: one remediation task per child policy, keyed by policyDefinitionReferenceId
      refs=$(az policy set-definition show --name "$(basename "$defid")" \
        --query "policyDefinitions[].policyDefinitionReferenceId" -o tsv 2>/dev/null || true)
      if [[ -z "$refs" ]]; then
        warn "$name: could not enumerate initiative members; remediate from the portal"
        continue
      fi
      n=0
      while read -r ref; do
        [[ -z "$ref" ]] && continue
        az policy remediation create \
          --name "rem-${name}-${ref:0:40}" \
          --policy-assignment "$aid" \
          --definition-reference-id "$ref" \
          --management-group "$MG_ID" \
          --resource-discovery-mode ReEvaluateCompliance \
          --output none 2>/dev/null && n=$((n+1)) || true
      done <<< "$refs"
      ok "$name: $n remediation task(s) created"
    else
      az policy remediation create \
        --name "rem-${name}" \
        --policy-assignment "$aid" \
        --management-group "$MG_ID" \
        --resource-discovery-mode ReEvaluateCompliance \
        --output none 2>/dev/null && ok "$name: remediation task created" \
        || warn "$name: remediation task not created (may already exist)"
    fi
  done

  warn "Remediation runs asynchronously. Track it under Policy > Remediation in the portal."
}

# -----------------------------------------------------------------------------
# Status - what is actually onboarded
# -----------------------------------------------------------------------------
do_status() {
  local scope="/providers/Microsoft.Management/managementGroups/${MG_ID}"

  say "Assignments under $MG_ID"
  az policy assignment list --scope "$scope" \
    --query "[?starts_with(name, '${PREFIX}-')].{name:name, displayName:displayName, enforcement:enforcementMode, identity:identity.principalId}" \
    -o table

  say "Subscriptions in scope"
  az account management-group show --name "$MG_ID" --expand --recurse \
    --query "children[?type=='/subscriptions'].{name:displayName, id:name}" -o table 2>/dev/null \
    || warn "could not enumerate child subscriptions"

  say "Compliance summary"
  az policy state summarize --management-group "$MG_ID" \
    --query "value[0].results.{nonCompliantResources:nonCompliantResources, nonCompliantPolicies:nonCompliantPolicies}" \
    -o json 2>/dev/null || warn "compliance data not yet available - allow ~30 minutes after assignment"
}

case "$ACTION" in
  Deploy|deploy)       do_deploy ;;
  Grant|grant)         do_grant ;;
  Remediate|remediate) do_remediate ;;
  Status|status)       do_status ;;
  All|all)             do_deploy; do_grant; do_remediate; do_status ;;
  *) echo "ERROR: unknown action '$ACTION'." >&2; usage ;;
esac
