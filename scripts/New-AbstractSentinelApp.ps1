#Requires -Version 7.0
<#
.SYNOPSIS
    Abstract Security - Azure Sentinel Destination: Entra app registration + DCR RBAC.
    Standalone operator script (PowerShell 7+ / Az modules). Runs in Azure Cloud
    Shell or locally / VS Code.

.DESCRIPTION
    ARM/Bicep cannot create Entra app registrations, so this script does the
    identity half that templates/destinations/sentinel-destination.* cannot:

      1. Creates (or reuses) a single-tenant Entra app registration for Abstract
         and its service principal.
      2. Generates a client secret - shown ONCE, or pushed to Key Vault with
         -KeyVault. The secret is NEVER written to disk or a transcript.
      3. With -Deploy, deploys the Sentinel Destination stack (Log Analytics
         workspace + Microsoft Sentinel + Data Collection Endpoint + custom _CL
         table + Data Collection Rule) and grants the SP BOTH
         "Monitoring Metrics Publisher" AND "Monitoring Contributor" on the DCR
         (exactly what the Abstract docs require), then prints the values for the
         Abstract "Azure Sentinel Destination" modal.

    The Abstract app needs NO Graph API permissions or admin consent - it is
    purely an identity that receives DCR RBAC. You need rights to register an app
    in the tenant, and (to deploy) Contributor + User Access Administrator or
    Owner on the target resource group.

    All Azure work goes through the Az modules (Az.Accounts, Az.Resources, and
    Az.KeyVault when -KeyVault is used).

.PARAMETER AppName          Entra app display name. Default 'Abstract-Sentinel-App'.
.PARAMETER SubscriptionId   Subscription to use. Prompted/among current if omitted.
.PARAMETER Deploy           Switch. Also deploy the ingestion stack and grant DCR RBAC.
.PARAMETER ResourceGroup    Target RG (created if missing). Required with -Deploy.
.PARAMETER Location         Region for a new RG / new workspace. Default 'eastus'.
.PARAMETER TableName        Custom _CL table. Default 'AbstractEventLogs_CL'.
.PARAMETER DceName          Data Collection Endpoint name. Default 'abstract-dce'.
.PARAMETER DcrName          Data Collection Rule name. Default 'abstract-dcr'.
.PARAMETER KeyVault         If set, store the client secret here instead of printing it.
.PARAMETER SecretYears      Client-secret validity in years. Default 1.
.PARAMETER Force            Skip the confirmation prompt.

.EXAMPLE
    ./New-AbstractSentinelApp.ps1 -AppName Abstract-Sentinel-App
    # Identity only - creates app + SP + secret, prints the auth values.

.EXAMPLE
    ./New-AbstractSentinelApp.ps1 -AppName Abstract-Sentinel-App `
        -Deploy -ResourceGroup rg-abstract-sentinel -Location eastus
    # One-shot: identity + full ingestion stack + both DCR roles + modal values.

.NOTES
    Secrets: shown once or stored in Key Vault; never logged. If you lose the
    value, re-run to generate a new one (existing secrets are preserved).
#>
[CmdletBinding()]
param(
    [string]$AppName = 'Abstract-Sentinel-App',
    [string]$SubscriptionId,
    [switch]$Deploy,
    [string]$ResourceGroup,
    [string]$Location = 'eastus',
    [string]$TableName = 'AbstractEventLogs_CL',
    [string]$DceName = 'abstract-dce',
    [string]$DcrName = 'abstract-dcr',
    [string]$KeyVault,
    [int]$SecretYears = 1,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }
function Warn($m) { Write-Host $m -ForegroundColor Yellow }

# Template lives one directory up from this script.
$Template = Join-Path $PSScriptRoot '..' 'templates' 'destinations' 'sentinel-destination.azuredeploy.json'

# ---- prerequisites ----------------------------------------------------------
foreach ($m in 'Az.Accounts', 'Az.Resources') {
    if (-not (Get-Module -ListAvailable -Name $m)) {
        throw "Required module '$m' is not installed. Run: Install-Module $m -Scope CurrentUser"
    }
}
$ctx = Get-AzContext
if (-not $ctx) { Info 'Not connected - launching Connect-AzAccount…'; Connect-AzAccount | Out-Null; $ctx = Get-AzContext }
if ($SubscriptionId) { Set-AzContext -Subscription $SubscriptionId | Out-Null; $ctx = Get-AzContext }

$TenantId = $ctx.Tenant.Id
$SubId    = $ctx.Subscription.Id
Info "Tenant : $TenantId"
Info "Sub    : $($ctx.Subscription.Name) ($SubId)"
Info "App    : $AppName"
if ($Deploy) {
    if (-not $ResourceGroup) { throw '-Deploy requires -ResourceGroup.' }
    if (-not (Test-Path $Template)) { throw "Template not found: $Template" }
    Info "Deploy : $ResourceGroup ($Location) using $(Split-Path $Template -Leaf)"
}

if (-not $Force) {
    $ans = Read-Host 'Proceed against the tenant/subscription above? [y/N]'
    if ($ans -notmatch '^[Yy]$') { throw 'Aborted.' }
}

# ---- 1. app registration (idempotent by display name) -----------------------
$app = Get-AzADApplication -DisplayName $AppName -ErrorAction SilentlyContinue | Select-Object -First 1
if ($app) {
    Info "Reusing existing app registration '$AppName' (appId $($app.AppId))."
} else {
    Info "Creating app registration '$AppName' (single-tenant)…"
    $app = New-AzADApplication -DisplayName $AppName -SignInAudience AzureADMyOrg
    Ok "Created app (appId $($app.AppId))."
}
$AppId = $app.AppId

# ---- 2. service principal (idempotent) --------------------------------------
$sp = Get-AzADServicePrincipal -ApplicationId $AppId -ErrorAction SilentlyContinue
if (-not $sp) {
    Info 'Creating service principal for the app…'
    $sp = New-AzADServicePrincipal -ApplicationId $AppId
    Start-Sleep -Seconds 15   # allow directory replication before role assignment
}
$SpObjectId = $sp.Id
Ok "Service principal object id: $SpObjectId"

# ---- 3. client secret -------------------------------------------------------
Info "Generating client secret (valid ${SecretYears}y)…"
$cred = New-AzADAppCredential -ApplicationId $AppId -EndDate (Get-Date).AddYears($SecretYears)
$SecretValue = $cred.SecretText
$SecretSink  = 'printed below (copy it now - it cannot be retrieved again)'

if ($KeyVault) {
    if (-not (Get-Module -ListAvailable -Name Az.KeyVault)) { throw "Az.KeyVault not installed (needed for -KeyVault)." }
    Info "Storing secret in Key Vault '$KeyVault'…"
    $secure = ConvertTo-SecureString $SecretValue -AsPlainText -Force
    $kv = Set-AzKeyVaultSecret -VaultName $KeyVault -Name 'abstract-sentinel-client-secret' -SecretValue $secure
    $SecretSink  = "stored in Key Vault: $($kv.Id)"
    $SecretValue = '(stored in Key Vault - not shown)'
}

# ---- 4. optional deployment (grants BOTH DCR roles to the SP) ---------------
$DcrImmutableId = ''; $DceUrl = ''; $StreamName = "Custom-$TableName"
if ($Deploy) {
    if (-not (Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue)) {
        New-AzResourceGroup -Name $ResourceGroup -Location $Location | Out-Null
    }
    Info 'Deploying the Sentinel Destination stack (workspace + Sentinel + DCE + table + DCR + RBAC)…'
    $dep = New-AzResourceGroupDeployment `
        -Name "abstract-sentinel-$([DateTimeOffset]::UtcNow.ToUnixTimeSeconds())" `
        -ResourceGroupName $ResourceGroup `
        -TemplateFile $Template `
        -createWorkspace $true -location $Location `
        -customTableName $TableName -dataCollectionEndpointName $DceName `
        -dataCollectionRuleName $DcrName `
        -principalId $SpObjectId -principalType 'ServicePrincipal'
    $DcrImmutableId = $dep.Outputs.dataCollectionRuleImmutableId.Value
    $DceUrl         = $dep.Outputs.dataCollectionEndpointUrl.Value
    $StreamName     = $dep.Outputs.logStreamName.Value
    Ok 'Deployment complete.'
}

# ---- 5. summary → the Abstract modal ---------------------------------------
Write-Host ''
Write-Host '============================================================================'
Write-Host ' Abstract "Azure Sentinel Destination" - configuration values'
Write-Host '============================================================================'
Write-Host ' Authentication'
Write-Host "   Client ID (Application ID)   : $AppId"
Write-Host "   Application Tenant ID        : $TenantId"
Write-Host "   Client Secret Value          : $SecretValue"
Write-Host "     -> $SecretSink"
Write-Host "   Service principal object id  : $SpObjectId   (used for DCR RBAC)"
if ($Deploy) {
    Write-Host ''
    Write-Host ' Azure Monitor Details'
    Write-Host "   Data Collection Rule ID      : $DcrImmutableId"
    Write-Host "   Data Collection Endpoint     : $DceUrl"
    Write-Host "   Log Stream Name              : $StreamName"
    Write-Host ''
    Write-Host ' RBAC granted on the DCR: Monitoring Metrics Publisher + Monitoring Contributor'
} else {
    Write-Host ''
    Warn ' Next: deploy the ingestion stack and grant RBAC to this SP, e.g.'
    Write-Host "   New-AzResourceGroupDeployment -ResourceGroupName <rg> ``"
    Write-Host "     -TemplateFile templates/destinations/sentinel-destination.azuredeploy.json ``"
    Write-Host "     -principalId $SpObjectId"
    Write-Host '   …or re-run with -Deploy -ResourceGroup <rg>. Then read DCR ID / DCE URL /'
    Write-Host '   stream name from the deployment Outputs.'
}
Write-Host '============================================================================'
Ok 'Done.'
