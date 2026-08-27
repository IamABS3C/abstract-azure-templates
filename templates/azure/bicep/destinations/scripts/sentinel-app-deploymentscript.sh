#!/usr/bin/env bash
# =============================================================================
#  Abstract Security - Sentinel destination identity, hardened deploymentScript
#
#  Runs inside Microsoft.Resources/deploymentScripts (AzureCLI) as a
#  user-assigned managed identity holding Application.ReadWrite.All.
#
#  Replaces the original 16-line inline script in
#  templates/destinations/sentinel-destination-with-app.bicep. Same job, but it
#  survives the three failure modes the inline version did not:
#
#    1. SECRET CHURN. The original called `az ad app credential reset --append`
#       on EVERY deployment. Re-run the template and you got a brand-new secret
#       and a new Key Vault version while the value already configured in
#       Abstract kept working - until someone assumed the newest version was
#       correct. Now: only mint a secret when the vault holds none with more than
#       30 days left.
#    2. SILENT PARTIAL SUCCESS. Every step was unguarded, so an app created
#       without a service principal still reported success and the DCR role
#       assignment failed later with an opaque PrincipalNotFound.
#    3. NO OUTPUT VERIFICATION. Nothing read back what it had created.
#
#  Note this app needs NO Graph API permissions and NO admin consent - unlike the
#  per-subscription collection apps. It is purely an identity that receives DCR
#  RBAC (Monitoring Metrics Publisher + Monitoring Contributor), which the
#  template assigns. That is why there is no consent logic here.
#
#  Environment (set by the template):
#    APP_NAME       app display name - ALSO the idempotency key
#    KV_NAME        Key Vault that receives the secret
#    VAULT_URI      vault URI, for the returned secret reference
#    SECRET_NAME    secret name in the vault
#    SECRET_YEARS   secret lifetime in years
#    FORCE_ROTATE   'true' to mint a new secret regardless of the existing one
# =============================================================================
set -euo pipefail

log()  { printf '==> %s\n' "$*"; }
ok()   { printf '    + %s\n' "$*"; }
warn() { printf '    ! %s\n' "$*"; }
die()  { printf '    X %s\n' "$*" >&2; exit 1; }

: "${APP_NAME:?APP_NAME not set}"
: "${KV_NAME:?KV_NAME not set}"
: "${SECRET_NAME:?SECRET_NAME not set}"
: "${SECRET_YEARS:=1}"
: "${FORCE_ROTATE:=false}"

TENANT_ID=$(az account show --query tenantId -o tsv) || die "cannot read tenant - is the script identity attached?"
ok "tenant $TENANT_ID"

# --- App registration (idempotent by display name) ------------------------
log "Ensuring app registration '$APP_NAME'"
APP_ID=$(az ad app list --filter "displayName eq '${APP_NAME}'" --query '[0].appId' -o tsv 2>/dev/null || true)
if [ -z "$APP_ID" ] || [ "$APP_ID" = "None" ]; then
  APP_ID=$(az ad app create --display-name "$APP_NAME" --sign-in-audience AzureADMyOrg --query appId -o tsv) \
    || die "app creation failed - does the script identity hold Application.ReadWrite.All with admin consent?"
  ok "created app $APP_ID"
  sleep 15   # directory replication before the SP create
else
  ok "reusing existing app $APP_ID"
fi
[ -z "$APP_ID" ] && die "app id resolved empty"
APP_OBJ_ID=$(az ad app show --id "$APP_ID" --query id -o tsv) || die "cannot read app object id for $APP_ID"

# --- Service principal ----------------------------------------------------
# The DCR role assignments target the SP object id, so if this is skipped the
# template's own roleAssignments fail with PrincipalNotFound.
log "Ensuring service principal"
SP_ID=$(az ad sp show --id "$APP_ID" --query id -o tsv 2>/dev/null || true)
if [ -z "$SP_ID" ] || [ "$SP_ID" = "None" ]; then
  SP_ID=$(az ad sp create --id "$APP_ID" --query id -o tsv) || die "service principal creation failed"
  ok "created SP $SP_ID"
  # Longer wait here on purpose: the template assigns DCR RBAC to this object id
  # immediately afterwards, and RBAC on a freshly created SP is the classic
  # PrincipalNotFound race.
  sleep 30
else
  ok "reusing SP $SP_ID"
fi
[ -z "$SP_ID" ] && die "service principal id resolved empty"

# --- Secret: rotate only when necessary ----------------------------------
log "Checking for a usable secret in $KV_NAME"
NEED_SECRET=true
if [ "$FORCE_ROTATE" = "true" ]; then
  warn "FORCE_ROTATE=true - minting a new secret. Update Abstract with the new value."
else
  if EXP=$(az keyvault secret show --vault-name "$KV_NAME" --name "$SECRET_NAME" \
             --query 'attributes.expires' -o tsv 2>/dev/null); then
    if [ -n "$EXP" ] && [ "$EXP" != "None" ]; then
      if python3 -c "
import sys, datetime
exp = datetime.datetime.fromisoformat('$EXP'.replace('Z', '+00:00'))
now = datetime.datetime.now(datetime.timezone.utc)
sys.exit(0 if (exp - now).days > 30 else 1)"; then
        NEED_SECRET=false
        ok "existing secret valid for >30 days - NOT rotating (re-running this template is safe)"
      else
        warn "existing secret expires within 30 days - rotating"
      fi
    fi
  else
    ok "no existing secret in the vault"
  fi
fi

if [ "$NEED_SECRET" = true ]; then
  log "Generating a client secret (${SECRET_YEARS} year(s))"
  SECRET=$(az ad app credential reset --id "$APP_ID" --append \
    --display-name "$SECRET_NAME" --years "$SECRET_YEARS" --query password -o tsv) \
    || die "secret generation failed"
  [ -z "$SECRET" ] && die "secret generation returned empty"
  END=$(python3 -c "
import datetime
print((datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365*int('$SECRET_YEARS'))).strftime('%Y-%m-%dT%H:%M:%SZ'))")
  az keyvault secret set --vault-name "$KV_NAME" --name "$SECRET_NAME" \
    --value "$SECRET" --expires "$END" -o none \
    || die "could not write the secret to $KV_NAME - is Key Vault Secrets Officer granted to the script identity?"
  unset SECRET
  ok "secret stored at ${KV_NAME}/${SECRET_NAME}, expires ${END}"
  ok "never emitted to deployment outputs or logs"
fi

# --- Verify what we actually created -------------------------------------
log "Verifying"
az ad app show --id "$APP_ID" --query displayName -o tsv >/dev/null || die "app not readable after creation"
az ad sp show --id "$APP_ID" --query id -o tsv >/dev/null || die "service principal not readable after creation"
az keyvault secret show --vault-name "$KV_NAME" --name "$SECRET_NAME" --query id -o tsv >/dev/null \
  || die "secret not present in $KV_NAME after creation"
ok "app, service principal and secret all verified"

cat > "$AZ_SCRIPTS_OUTPUT_PATH" <<JSON
{
  "appId": "${APP_ID}",
  "appObjectId": "${APP_OBJ_ID}",
  "spObjectId": "${SP_ID}",
  "tenantId": "${TENANT_ID}",
  "keyVaultSecretUri": "${VAULT_URI:-https://${KV_NAME}.vault.azure.net/}secrets/${SECRET_NAME}",
  "secretRotated": ${NEED_SECRET},
  "verified": true
}
JSON
ok "done"
