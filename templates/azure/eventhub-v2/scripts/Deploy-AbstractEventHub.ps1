#Requires -Version 7.0
<#
.SYNOPSIS
    Abstract Security - Azure Event Hub provisioner (v2.0).
    One menu-driven script to Deploy, fetch Credentials for, or Delete the
    Azure infrastructure the Abstract Security "Azure Event Hub" integration
    consumes from: Event Hubs namespace, one or more hubs (auto-named per log
    source), consumer group, checkpoint Storage Account + blob container,
    SAS and/or Entra RBAC auth (optionally creating the service principal),
    networking guardrails, and diagnostic-setting log exports.
    Runs in Azure Cloud Shell or locally / VS Code (PowerShell 7+).

.DESCRIPTION
    The script is a thin, guided wrapper around the universal template that
    ships alongside it (azuredeploy.json / main.bicep, one directory up).
    All Azure work goes through the Az modules.

      Action (-Action)            : Deploy | Credentials | Delete
      Auth    (-AuthMethod)       : ConnectionString | ServicePrincipal | Both
      Profile (-SecurityProfile)  : SafeMode (default) | IpAllowlist |
                                    PrivateOnly | Hybrid | Custom
      Storage                     : checkpoint Storage Account + private blob
                                    container (REQUIRED by Abstract for
                                    consumer offset/lease tracking)
      Exports                     : -ExportActivityLogs (subscription scope),
                                    -ExportEntraLogs (tenant scope, best
                                    effort via microsoft.aadiam)
      Logging (-LogPath)          : transcript to a timestamped log;
                                    connection strings / keys / client
                                    secrets are NOT logged

    The Credentials action prints, for each hub, exactly the fields the
    Abstract integration modal asks for - for BOTH auth methods:
      Connection String method : Event Hub namespace connection string
                                 (with EntityPath), consumer group, and the
                                 checkpoint Storage Account connection string.
      Service Principal method : Event Hub name, consumer group, blob
                                 container name, namespace FQDN, storage
                                 account blob URL, tenant ID, client ID
                                 (client secret shown only at creation time).

    Connectivity profiles map onto the template like this:
      SafeMode    -> safeMode=true. Public access forced ON, allowlist
                     ignored, firewall default Allow. Abstract can always
                     connect. Recommended for onboarding.
      IpAllowlist -> safeMode=false + allowedIpRanges. Default-Deny firewall
                     with your CIDRs (include Abstract egress IPs!).
      PrivateOnly -> safeMode=false + private endpoint + public DISABLED.
                     Internal-only; external SaaS cannot connect (expected).
      Hybrid      -> safeMode=false + private endpoint + IP allowlist.
                     Private for internal consumers, scoped public for SaaS.
      Custom      -> you are prompted for each toggle individually.

.PARAMETER Action            Deploy | Credentials | Delete. Prompted if omitted.
.PARAMETER SubscriptionId    Subscription to deploy into. Prompted if multiple.
.PARAMETER ResourceGroup     Target resource group (created if missing).
.PARAMETER Location          Region for a NEW resource group. Default eastus.
.PARAMETER NamespaceName     Event Hubs namespace (globally unique).
.PARAMETER SecurityProfile   SafeMode | IpAllowlist | PrivateOnly | Hybrid | Custom.
.PARAMETER Sku               Standard | Premium. Default Standard (Abstract
                             requires Standard or above; Basic is not offered).
.PARAMETER Capacity          TUs (Standard) or PUs (Premium). Default 2.
.PARAMETER HubSources        Log sources; one hub per entry. Default activity,entra,defender.
.PARAMETER HubPrefix         Prefix for generated hub names. Default evh-abstract.
.PARAMETER Environment       Environment token in hub names ('' to omit). Default ''.
.PARAMETER PartitionCount    Partitions per generated hub (Abstract recommends >= 4). Default 4.
.PARAMETER RetentionDays     Message retention per generated hub. Default 7.
.PARAMETER ConsumerGroup     Consumer group for Abstract. Default abstract.
.PARAMETER AuthMethod        ConnectionString | ServicePrincipal | Both. Default Both.
.PARAMETER SasRuleName       Namespace SAS rule name (Listen). Default abstract-access.
.PARAMETER PrincipalId       Existing Entra object ID to grant Data Receiver +
                             Storage Blob Data Contributor (SPN method).
.PARAMETER CreateServicePrincipal  Create app registration 'abstract-eventhub-ingestion'
                             + client secret + service principal, and use its
                             object ID as -PrincipalId automatically.
.PARAMETER CreateStorageAccount    Create the checkpoint Storage Account (default ON;
                             pass -CreateStorageAccount:$false to skip).
.PARAMETER StorageAccountName     Checkpoint Storage Account name. Empty = auto-generated.
.PARAMETER BlobContainerName      Checkpoint blob container. Default abstract-checkpoints.
.PARAMETER ExportActivityLogs     Also deploy the subscription-scope diagnostic
                             setting that streams the Azure Activity Log to the hub.
.PARAMETER ExportEntraLogs        Also create the Entra ID (AAD) tenant diagnostic
                             setting (SignInLogs + AuditLogs) - requires Entra P1/P2
                             and Security Administrator / Global Administrator.
.PARAMETER AllowedIpRanges   CIDRs for IpAllowlist / Hybrid / Custom profiles.
.PARAMETER SubnetId          Subnet resource ID for the private endpoint(s).
.PARAMETER PrivateDnsZoneId  privatelink.servicebus.windows.net zone resource ID.
.PARAMETER StorageDnsZoneId  privatelink.blob.core.windows.net zone resource ID.
.PARAMETER LogAnalyticsWorkspaceId  Workspace ID to enable namespace diagnostics.
.PARAMETER TemplateFile      Override template path. Default: ../azuredeploy.json
                             (then ../main.bicep) relative to this script.
.PARAMETER OutFile           Optional path to save the credential block as JSON
                             (contains connection strings - protect or delete).
.PARAMETER LogPath           Transcript path. Default ./AbstractEventHub-<timestamp>.log.
.PARAMETER Preview           Run the deployment as a what-if only (no changes).
.PARAMETER ReAuth            Force a fresh Connect-AzAccount even if a context exists.
.PARAMETER Force             Skip confirmation prompts (e.g. Delete).

.NOTES
    Author : Abstract Security - Solutions Engineering
    Version: 2.0
    Connection strings, account keys, and client secrets are shown once in
    the console and are intentionally excluded from the transcript log.
    Not yet runtime-tested against a live tenant.

.EXAMPLE
    ./Deploy-AbstractEventHub.ps1
.EXAMPLE
    # Fastest happy path: SafeMode, storage + SPN + activity log export
    ./Deploy-AbstractEventHub.ps1 -Action Deploy -ResourceGroup rg-abstract `
        -NamespaceName abs-prod-eh001 -SecurityProfile SafeMode `
        -CreateServicePrincipal -ExportActivityLogs
.EXAMPLE
    # Hardened: default-deny firewall scoped to Abstract egress IPs
    ./Deploy-AbstractEventHub.ps1 -Action Deploy -ResourceGroup rg-abstract `
        -NamespaceName abs-prod-eh001 -SecurityProfile IpAllowlist `
        -AllowedIpRanges '20.10.0.0/24','52.0.1.2/32'
.EXAMPLE
    # Re-print the Abstract onboarding details for an existing deployment
    ./Deploy-AbstractEventHub.ps1 -Action Credentials -ResourceGroup rg-abstract -NamespaceName abs-prod-eh001
.EXAMPLE
    ./Deploy-AbstractEventHub.ps1 -Action Delete -ResourceGroup rg-abstract -NamespaceName abs-prod-eh001
#>
[CmdletBinding()]
param(
    [ValidateSet("Deploy","Credentials","Delete")] [string]$Action,
    [string]$SubscriptionId,
    [string]$ResourceGroup,
    [string]$Location = "eastus",
    [string]$NamespaceName,
    [ValidateSet("SafeMode","IpAllowlist","PrivateOnly","Hybrid","Custom")] [string]$SecurityProfile,
    [ValidateSet("Standard","Premium")] [string]$Sku = "Standard",
    [ValidateRange(1,40)] [int]$Capacity = 2,
    [string[]]$HubSources = @("activity","entra","defender"),
    [string]$HubPrefix = "evh-abstract",
    [string]$Environment = "",
    [ValidateRange(1,1024)] [int]$PartitionCount = 4,
    [ValidateRange(1,90)] [int]$RetentionDays = 7,
    [string]$ConsumerGroup = "abstract",
    [ValidateSet("ConnectionString","ServicePrincipal","Both")] [string]$AuthMethod = "Both",
    [string]$SasRuleName = "abstract-access",
    [string]$PrincipalId,
    [switch]$CreateServicePrincipal,
    [bool]$CreateStorageAccount = $true,
    [string]$StorageAccountName = "",
    [string]$BlobContainerName = "abstract-checkpoints",
    [switch]$ExportActivityLogs,
    [switch]$ExportEntraLogs,
    [string[]]$AllowedIpRanges = @(),
    [string]$SubnetId,
    [string]$PrivateDnsZoneId,
    [string]$StorageDnsZoneId,
    [string]$LogAnalyticsWorkspaceId,
    [string]$TemplateFile,
    [string]$OutFile,
    [string]$LogPath = "./AbstractEventHub-$(Get-Date -Format yyyyMMdd-HHmmss).log",
    [switch]$Preview,
    [switch]$ReAuth,
    [switch]$Force
)
$ErrorActionPreference = "Stop"
$Brand = "Cyan"; $Brand2 = "DarkCyan"

function Show-Banner {
    $art = @(
'    _    ____  ____ _____ ____      _    ____ _____',
'   / \  | __ )/ ___|_   _|  _ \    / \  / ___|_   _|',
'  / _ \ |  _ \ \___ \ | | | |_) |  / _ \| |     | |',
' / ___ \| |_) |___) || | |  _ <  / ___ \ |___  | |',
'/_/   \_\____/|____/ |_| |_| \_\/_/   \_\____| |_|'
    )
    Write-Host ""
    foreach ($l in $art) { Write-Host $l -ForegroundColor $Brand }
    Write-Host "                          S E C U R I T Y" -ForegroundColor $Brand2
    Write-Host "  Azure Event Hub provisioner - namespace, hubs, checkpoint storage, auth" -ForegroundColor White
    Write-Host "  Author: Abstract Security - Solutions Engineering          v2.0" -ForegroundColor DarkGray
    Write-Host ""
}
function Info { param($m) Write-Host "==> $m" -ForegroundColor $Brand }
function Ok   { param($m) Write-Host "    $m" -ForegroundColor Green }
function Warn { param($m) Write-Host "    $m" -ForegroundColor Yellow }
function Choose { param([string]$Prompt,[string[]]$Options,[string]$Default)
    while ($true) {
        $shown = ($Options | ForEach-Object { if ($_ -ieq $Default) { "[$_]" } else { $_ } }) -join " / "
        $a = Read-Host "$Prompt  ($shown)"
        if ([string]::IsNullOrWhiteSpace($a) -and $Default) { return $Default }
        $m = $Options | Where-Object { $_ -ieq $a }
        if ($m) { return $m }
        Warn "Please enter one of: $($Options -join ', ')"
    }
}
$script:Interacted = $false
function Select-Option {
    # Numbered menu. $Items are @{Key=...;Desc=...} (or plain strings). Returns the chosen Key.
    param([string]$Title,[object[]]$Items,[int]$DefaultIndex = 0)
    $script:Interacted = $true
    Write-Host ""
    Write-Host "  $Title" -ForegroundColor $Brand
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $it = $Items[$i]
        $label = if ($it -is [hashtable]) { "{0,-16} {1}" -f $it.Key, $it.Desc } else { "$it" }
        $star  = if ($i -eq $DefaultIndex) { "*" } else { " " }
        Write-Host ("   {0} {1}. {2}" -f $star, ($i + 1), $label) -ForegroundColor White
    }
    while ($true) {
        $a = Read-Host "  Choose 1-$($Items.Count)  [default $($DefaultIndex + 1)]"
        if ([string]::IsNullOrWhiteSpace($a)) { $sel = $DefaultIndex }
        elseif ($a -match '^\d+$' -and [int]$a -ge 1 -and [int]$a -le $Items.Count) { $sel = [int]$a - 1 }
        else {
            $byKey = for ($j = 0; $j -lt $Items.Count; $j++) { if (($Items[$j] -is [hashtable] -and $Items[$j].Key -ieq $a) -or ($Items[$j] -ieq $a)) { $j } }
            if ($byKey -ne $null -and $byKey -ne "") { $sel = [int]$byKey } else { Warn "Enter a number 1-$($Items.Count) (or the name)."; continue }
        }
        $chosen = $Items[$sel]
        if ($chosen -is [hashtable]) { return $chosen.Key } else { return $chosen }
    }
}
function Ask { param([string]$Prompt,[string]$Default)
    $script:Interacted = $true
    if ($Default) { $a = Read-Host "$Prompt [$Default]"; if ([string]::IsNullOrWhiteSpace($a)) { return $Default } else { return $a.Trim() } }
    while ($true) { $a = Read-Host $Prompt; if (-not [string]::IsNullOrWhiteSpace($a)) { return $a.Trim() }; Warn "A value is required." }
}
function Test-CloudShell {
    return (($env:AZUREPS_HOST_ENVIRONMENT -like 'cloud-shell*') -or ($null -ne $env:ACC_CLOUD) -or ($null -ne $env:ACC_TID))
}
function Stop-Clean { param([int]$Code = 1)
    if ($script:logging) { try { Stop-Transcript | Out-Null } catch {} }
    exit $Code
}

# ---- Start logging + banner ----
try { Start-Transcript -Path $LogPath | Out-Null; $logging = $true } catch { $logging = $false }
Show-Banner
if ($logging) { Info "Transcript: $LogPath  (connection strings / keys / client secrets are NOT written here)" }
$inCloudShell = Test-CloudShell
if ($inCloudShell) { Info "Environment: Azure Cloud Shell - will reuse your existing sign-in (no new prompt)." }
else               { Info "Environment: local PowerShell - will use interactive browser sign-in if needed." }

# ---- Modules ----
$mods = @("Az.Accounts","Az.Resources","Az.EventHub","Az.Storage")
Info "Checking Az modules ($($mods -join ', ')) - first run may take a minute..."
foreach ($mod in $mods) {
    if (Get-Module -Name $mod) { continue }
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Warn "$mod not installed - fetching from PSGallery (CurrentUser)."
        $installed = $false
        if (Get-Command Install-PSResource -ErrorAction SilentlyContinue) {
            try { Install-PSResource $mod -Scope CurrentUser -TrustRepository -ErrorAction Stop; $installed = $true }
            catch { Warn "Install-PSResource failed ($($_.Exception.Message)); falling back to Install-Module." }
        }
        if (-not $installed) {
            try { if ((Get-PSRepository -Name PSGallery -ErrorAction Stop).InstallationPolicy -ne 'Trusted') { Set-PSRepository -Name PSGallery -InstallationPolicy Trusted } } catch {}
            Install-Module $mod -Scope CurrentUser -Force -AllowClobber -Confirm:$false
        }
    }
    Import-Module $mod -ErrorAction Stop
}
Ok "Az modules ready."

# ---- Sign-in (reuse Cloud Shell / existing context; otherwise browser) ----
$ctx = $null; try { $ctx = Get-AzContext } catch {}
if (-not $ctx -or $ReAuth) {
    if ($inCloudShell -and -not $ReAuth) { throw "No Azure context found in Cloud Shell - restart the shell and try again." }
    Info "Interactive browser sign-in - complete MFA in the window that opens."
    Connect-AzAccount -ErrorAction Stop | Out-Null
    $ctx = Get-AzContext
} else {
    Info "Reusing existing Azure session ($($ctx.Account.Id)). Pass -ReAuth to force a new sign-in."
}

# ---- Subscription ----
if ($SubscriptionId) {
    Set-AzContext -SubscriptionId $SubscriptionId | Out-Null
} else {
    $subs = @(Get-AzSubscription -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Enabled' })
    if ($subs.Count -gt 1) {
        $items = @(); foreach ($s in $subs) { $items += @{Key=$s.Id; Desc=$s.Name} }
        $pick = Select-Option "Which subscription?" $items 0
        Set-AzContext -SubscriptionId $pick | Out-Null
    }
}
$ctx = Get-AzContext
Ok "Subscription: $($ctx.Subscription.Name) ($($ctx.Subscription.Id))  as  $($ctx.Account.Id)"

# ---- Guided menu (each step is skipped when the matching parameter is supplied) ----
if (-not $Action) {
    $Action = Select-Option "What do you want to do?" @(
        @{Key="Deploy";Desc="Deploy the Event Hub + checkpoint storage stack for Abstract"},
        @{Key="Credentials";Desc="Print the Abstract onboarding details for an existing deployment"},
        @{Key="Delete";Desc="Remove an Event Hubs namespace (and optionally its storage)"}
    ) 0
}
if (-not $ResourceGroup) { $ResourceGroup = Ask "Resource group" }
if (-not $NamespaceName) {
    $suggest = ("abs-eh{0:000}" -f (Get-Random -Maximum 999))
    $NamespaceName = Ask "Event Hubs namespace name (globally unique)" $suggest
}

# ---- SPN creation helper (used by Deploy) ----
$script:SpnSecret = $null; $script:SpnAppId = $null; $script:SpnTenant = $null
function New-AbstractSpn {
    $appName = "abstract-eventhub-ingestion"
    Info "Creating app registration '$appName' + client secret + service principal..."
    $existing = Get-AzADApplication -DisplayName $appName -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($existing) {
        Warn "App registration '$appName' already exists (appId $($existing.AppId)) - reusing it and adding a NEW client secret."
        $app = $existing
    } else {
        $app = New-AzADApplication -DisplayName $appName
    }
    $sp = Get-AzADServicePrincipal -ApplicationId $app.AppId -ErrorAction SilentlyContinue
    if (-not $sp) { $sp = New-AzADServicePrincipal -ApplicationId $app.AppId }
    $cred = New-AzADAppCredential -ObjectId $app.Id -EndDate (Get-Date).AddMonths(12)
    $script:SpnSecret = $cred.SecretText
    $script:SpnAppId  = $app.AppId
    $script:SpnTenant = (Get-AzContext).Tenant.Id
    Ok "Service principal ready. objectId=$($sp.Id) appId=$($app.AppId) (secret valid 12 months)"
    return $sp.Id
}

if ($Action -eq "Deploy") {
    if (-not $SecurityProfile) {
        $SecurityProfile = Select-Option "Connectivity / security profile" @(
            @{Key="SafeMode";Desc="Guardrails ON - public access guaranteed, ingestion can't break (onboarding)"},
            @{Key="IpAllowlist";Desc="Default-deny firewall + CIDR allowlist (include Abstract egress IPs)"},
            @{Key="PrivateOnly";Desc="Private endpoint only, public DISABLED (breaks external SaaS - intentional)"},
            @{Key="Hybrid";Desc="Private endpoint + scoped public IP allowlist (best hardened pattern)"},
            @{Key="Custom";Desc="Pick every toggle yourself"}
        ) 0
    }
    if (-not $PSBoundParameters.ContainsKey("Sku") -and $script:Interacted) {
        $Sku = Select-Option "Namespace SKU (Abstract requires Standard or above)" @(
            @{Key="Standard";Desc="Recommended - auto-inflate, consumer groups, firewall, PE"},
            @{Key="Premium";Desc="Dedicated PUs (1/2/4/8/16), highest throughput/isolation"}
        ) 0
    }
    if (-not $PSBoundParameters.ContainsKey("HubSources") -and $script:Interacted) {
        $srcRaw = Ask "Log sources (comma-separated; one hub per source)" ($HubSources -join ",")
        $HubSources = @($srcRaw -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
        $HubPrefix = Ask "Hub name prefix" $HubPrefix
    }
    if (-not $PSBoundParameters.ContainsKey("AuthMethod") -and $script:Interacted) {
        $AuthMethod = Select-Option "Authentication method for Abstract" @(
            @{Key="Both";Desc="SAS rule AND Entra RBAC - decide in the Abstract modal later"},
            @{Key="ConnectionString";Desc="SAS rule (Listen) - simplest; paste two connection strings"},
            @{Key="ServicePrincipal";Desc="Entra app + RBAC - no shared keys; best for hardened tenants"}
        ) 0
    }
    $wantSpn = $AuthMethod -in @("ServicePrincipal","Both")
    if ($wantSpn -and -not $PrincipalId) {
        if ($CreateServicePrincipal) {
            $PrincipalId = New-AbstractSpn
        } elseif ($script:Interacted) {
            $mk = Select-Option "Service principal for the RBAC grants" @(
                @{Key="Create";Desc="Create 'abstract-eventhub-ingestion' app + secret now (recommended)"},
                @{Key="Existing";Desc="I have one - paste its Entra OBJECT ID"},
                @{Key="Skip";Desc="Grant roles later myself (template skips role assignments)"}
            ) 0
            if ($mk -eq "Create")    { $PrincipalId = New-AbstractSpn }
            if ($mk -eq "Existing")  { $PrincipalId = Ask "Service principal OBJECT ID (not the appId)" }
        } else {
            Warn "AuthMethod=$AuthMethod but no -PrincipalId / -CreateServicePrincipal - RBAC role assignments will be skipped."
        }
    }
    if ($script:Interacted -and -not $PSBoundParameters.ContainsKey("CreateStorageAccount")) {
        $cs = Select-Option "Checkpoint Storage Account (REQUIRED by Abstract for offset tracking)" @(
            @{Key="Create";Desc="Create one + private container '$BlobContainerName' (recommended)"},
            @{Key="Skip";Desc="I already have one and will wire it up myself"}
        ) 0
        $CreateStorageAccount = ($cs -eq "Create")
    }

    # Profile-specific prompts
    $needIps = $SecurityProfile -in @("IpAllowlist","Hybrid")
    $needPe  = $SecurityProfile -in @("PrivateOnly","Hybrid")
    $disablePublic = $SecurityProfile -eq "PrivateOnly"
    $enablePe = $needPe
    if ($SecurityProfile -eq "Custom") {
        $disablePublic = (Select-Option "Disable ALL public network access?" @(
            @{Key="No";Desc="Keep a public endpoint (required for Abstract unless via allowlist)"},
            @{Key="Yes";Desc="Private endpoint only - external SaaS cannot connect"}) 0) -eq "Yes"
        $needIps = (-not $disablePublic) -and ((Select-Option "Restrict public access to an IP allowlist?" @(
            @{Key="No";Desc="Public endpoint open (auth still required)"},
            @{Key="Yes";Desc="Default-deny firewall + CIDR allowlist"}) 0) -eq "Yes")
        $enablePe = (Select-Option "Create private endpoints as well?" @(
            @{Key="No";Desc="Public connectivity only"},
            @{Key="Yes";Desc="Add private endpoints (needs subnet ID)"}) 0) -eq "Yes"
    }
    if ($needIps -and -not $AllowedIpRanges) {
        $ipRaw = Ask "Allowed CIDR ranges, comma-separated (REMEMBER Abstract's egress IPs)"
        $AllowedIpRanges = @($ipRaw -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    }
    if ($enablePe -and -not $SubnetId) {
        $SubnetId = Ask "Subnet resource ID for the private endpoint(s)"
        if (-not $PrivateDnsZoneId) {
            $PrivateDnsZoneId = Read-Host "Private DNS zone ID (privatelink.servicebus.windows.net) [skip]"
            if ($PrivateDnsZoneId) { $PrivateDnsZoneId = $PrivateDnsZoneId.Trim() }
        }
        if ($CreateStorageAccount -and -not $StorageDnsZoneId) {
            $StorageDnsZoneId = Read-Host "Private DNS zone ID (privatelink.blob.core.windows.net) [skip]"
            if ($StorageDnsZoneId) { $StorageDnsZoneId = $StorageDnsZoneId.Trim() }
        }
    }
    if (-not $LogAnalyticsWorkspaceId -and $script:Interacted) {
        $diag = Select-Option "Send namespace diagnostics to Log Analytics?" @(
            @{Key="No";Desc="Skip diagnostics"},
            @{Key="Yes";Desc="Enable allLogs + AllMetrics to a workspace"}) 0
        if ($diag -eq "Yes") { $LogAnalyticsWorkspaceId = Ask "Log Analytics workspace resource ID" }
    }
    if ($script:Interacted -and -not $ExportActivityLogs) {
        $ea = Select-Option "Stream this subscription's Activity Log to the hub?" @(
            @{Key="Yes";Desc="Create the subscription diagnostic setting (recommended)"},
            @{Key="No";Desc="Skip - configure log sources later"}) 0
        if ($ea -eq "Yes") { $ExportActivityLogs = $true }
    }
    if ($script:Interacted -and -not $ExportEntraLogs) {
        $ee = Select-Option "Stream Entra ID sign-in + audit logs to the hub? (needs Entra P1/P2 + admin)" @(
            @{Key="No";Desc="Skip / not licensed / do it in the portal later"},
            @{Key="Yes";Desc="Create the tenant diagnostic setting via microsoft.aadiam (best effort)"}) 0
        if ($ee -eq "Yes") { $ExportEntraLogs = $true }
    }

    $safeMode = $SecurityProfile -eq "SafeMode"
    if (-not $safeMode -and $AllowedIpRanges.Count -eq 0 -and -not $disablePublic -and $SecurityProfile -ne "Custom") {
        Warn "No IP ranges supplied - the firewall will stay default-Allow."
    }
    if ($disablePublic) {
        Warn "PrivateOnly: public access will be DISABLED. Abstract (external SaaS) will NOT be able to connect."
        Warn "Use Hybrid or SafeMode if this namespace must feed Abstract."
    }

    $enableSas  = $AuthMethod -in @("ConnectionString","Both")
    $enableRbac = ($AuthMethod -in @("ServicePrincipal","Both")) -and [bool]$PrincipalId

    # ---- Review & confirm (interactive runs only) ----
    if ($script:Interacted -and -not $Force) {
        $hubPreview = ($HubSources | ForEach-Object { $(if ($Environment) { "$HubPrefix-$Environment-$_" } else { "$HubPrefix-$_" }).ToLower() }) -join ", "
        Write-Host ""
        Write-Host "  ----- Review -----" -ForegroundColor $Brand
        Write-Host ("   Action        : Deploy{0}" -f $(if ($Preview) { " (what-if preview only)" } else { "" })) -ForegroundColor White
        Write-Host ("   Subscription  : {0}" -f $ctx.Subscription.Name) -ForegroundColor White
        Write-Host ("   Resource group: {0}" -f $ResourceGroup) -ForegroundColor White
        Write-Host ("   Namespace     : {0}  ({1}, capacity {2})" -f $NamespaceName, $Sku, $Capacity) -ForegroundColor White
        Write-Host ("   Hubs          : {0}  ({1} partitions, {2}d retention)" -f $hubPreview, $PartitionCount, $RetentionDays) -ForegroundColor White
        Write-Host ("   Consumer group: {0}" -f $ConsumerGroup) -ForegroundColor White
        Write-Host ("   Auth method   : {0}" -f $AuthMethod) -ForegroundColor White
        if ($enableSas)  { Write-Host ("   SAS rule      : {0} (Listen)" -f $SasRuleName) -ForegroundColor White }
        if ($enableRbac) { Write-Host ("   RBAC principal: {0}" -f $PrincipalId) -ForegroundColor White }
        Write-Host ("   Checkpoint SA : {0}" -f $(if ($CreateStorageAccount) { if ($StorageAccountName) { $StorageAccountName } else { "(auto-named)" } } else { "SKIPPED - bring your own" })) -ForegroundColor White
        Write-Host ("   Profile       : {0}" -f $SecurityProfile) -ForegroundColor White
        if ($AllowedIpRanges.Count) { Write-Host ("   IP allowlist  : {0}" -f ($AllowedIpRanges -join ", ")) -ForegroundColor White }
        if ($enablePe)              { Write-Host ("   Private EP    : yes ({0})" -f $SubnetId) -ForegroundColor White }
        if ($LogAnalyticsWorkspaceId) { Write-Host  "   Diagnostics   : Log Analytics" -ForegroundColor White }
        if ($ExportActivityLogs)    { Write-Host  "   Activity Log  : exported to hub (subscription diagnostic setting)" -ForegroundColor White }
        if ($ExportEntraLogs)       { Write-Host  "   Entra logs    : exported to hub (tenant diagnostic setting, best effort)" -ForegroundColor White }
        $go = Select-Option "Proceed?" @(@{Key="Yes";Desc="Run it now"}, @{Key="No";Desc="Cancel"}) 0
        if ($go -eq "No") { Warn "Cancelled."; Stop-Clean 0 }
    }

    # ---- Resource group ----
    $rg = Get-AzResourceGroup -Name $ResourceGroup -ErrorAction SilentlyContinue
    if (-not $rg) {
        Info "Resource group '$ResourceGroup' not found - creating in $Location."
        $rg = New-AzResourceGroup -Name $ResourceGroup -Location $Location
    }

    # ---- Template (repo layout: script lives in scripts/, templates one level up) ----
    if (-not $TemplateFile) {
        $here = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
        foreach ($cand in @("../azuredeploy.json","../main.bicep","azuredeploy.json","main.bicep")) {
            $p = Join-Path $here $cand
            if (Test-Path $p) { $TemplateFile = (Resolve-Path $p).Path; break }
        }
        if (-not $TemplateFile) { throw "Could not find azuredeploy.json or main.bicep next to / above this script. Pass -TemplateFile." }
    }
    Info "Template: $TemplateFile"

    $tp = @{
        namespaceName            = $NamespaceName
        sku                      = $Sku
        capacity                 = $Capacity
        autoHubNaming            = $true
        hubPrefix                = $HubPrefix
        environment              = $Environment
        hubSources               = $HubSources
        defaultPartitionCount    = $PartitionCount
        defaultRetentionDays     = $RetentionDays
        consumerGroupName        = $ConsumerGroup
        enableSas                = $enableSas
        sasRuleName              = $SasRuleName
        enableRbac               = $enableRbac
        principalId              = if ($PrincipalId) { $PrincipalId } else { "" }
        createStorageAccount     = [bool]$CreateStorageAccount
        storageAccountName       = $StorageAccountName
        blobContainerName        = $BlobContainerName
        safeMode                 = $safeMode
        disablePublicNetwork     = [bool]$disablePublic
        allowedIpRanges          = @($AllowedIpRanges)
        enablePrivateEndpoint    = [bool]$enablePe
        createStoragePrivateEndpoint = [bool]($enablePe -and $CreateStorageAccount)
        subnetId                 = if ($SubnetId) { $SubnetId } else { "" }
        privateDnsZoneId         = if ($PrivateDnsZoneId) { $PrivateDnsZoneId } else { "" }
        storageBlobPrivateDnsZoneId = if ($StorageDnsZoneId) { $StorageDnsZoneId } else { "" }
        enableDiagnostics        = [bool]$LogAnalyticsWorkspaceId
        logAnalyticsWorkspaceId  = if ($LogAnalyticsWorkspaceId) { $LogAnalyticsWorkspaceId } else { "" }
    }
    $depName = "abstract-eh-$(Get-Date -Format yyyyMMddHHmmss)"
    $depArgs = @{ Name = $depName; ResourceGroupName = $ResourceGroup; TemplateFile = $TemplateFile; TemplateParameterObject = $tp }
    if ($Preview) {
        Info "Running what-if preview (no changes will be made)..."
        New-AzResourceGroupDeployment @depArgs -WhatIf
        Ok "Preview complete - re-run without -Preview to deploy."
        Stop-Clean 0
    }
    Info "Deploying ($depName) - this typically takes 3-6 minutes..."
    $dep = New-AzResourceGroupDeployment @depArgs
    if ($dep.ProvisioningState -ne "Succeeded") { throw "Deployment finished in state '$($dep.ProvisioningState)'." }
    Ok "Deployment succeeded."
    foreach ($k in @("publicAccess","firewallDefaultAction","safeModeEnabled","storageAccountNameOut")) {
        if ($dep.Outputs.ContainsKey($k)) { Ok ("{0,-22}: {1}" -f $k, $dep.Outputs[$k].Value) }
    }
    if ($dep.Outputs.ContainsKey("storageAccountNameOut") -and -not $StorageAccountName) {
        $StorageAccountName = $dep.Outputs["storageAccountNameOut"].Value
    }

    # ---- Optional: subscription Activity Log export ----
    if ($ExportActivityLogs) {
        Info "Creating subscription diagnostic setting for the Azure Activity Log..."
        try {
            $authRuleId = if ($dep.Outputs.ContainsKey("abstractDiagnosticsAuthRuleId")) { $dep.Outputs["abstractDiagnosticsAuthRuleId"].Value } else {
                "/subscriptions/$($ctx.Subscription.Id)/resourceGroups/$ResourceGroup/providers/Microsoft.EventHub/namespaces/$NamespaceName/authorizationRules/RootManageSharedAccessKey"
            }
            $activityHub = ($HubSources | Where-Object { $_ -match 'activity' } | Select-Object -First 1)
            if (-not $activityHub) { $activityHub = $HubSources[0] }
            $hubName = $(if ($Environment) { "$HubPrefix-$Environment-$activityHub" } else { "$HubPrefix-$activityHub" }).ToLower()
            $subTpl = Join-Path (Split-Path $TemplateFile) "templates/subscription/activitylog.azuredeploy.json"
            if (Test-Path $subTpl) {
                New-AzSubscriptionDeployment -Name "abstract-activitylog-$(Get-Date -Format yyyyMMddHHmmss)" -Location $rg.Location `
                    -TemplateFile $subTpl -TemplateParameterObject @{
                        eventHubAuthorizationRuleId = $authRuleId
                        eventHubName                = $hubName
                    } | Out-Null
            } else {
                $body = @{ properties = @{
                    eventHubAuthorizationRuleId = $authRuleId
                    eventHubName                = $hubName
                    logs = @("Administrative","Security","ServiceHealth","Alert","Recommendation","Policy","Autoscale","ResourceHealth") |
                        ForEach-Object { @{ category = $_; enabled = $true } }
                } } | ConvertTo-Json -Depth 6
                Invoke-AzRestMethod -Method PUT -Path "/subscriptions/$($ctx.Subscription.Id)/providers/Microsoft.Insights/diagnosticSettings/abstract-activity-logs?api-version=2021-05-01-preview" -Payload $body | Out-Null
            }
            Ok "Activity Log now streams to hub '$hubName'."
        } catch { Warn "Activity Log export failed: $($_.Exception.Message) - create it manually (Monitor > Activity log > Export)." }
    }

    # ---- Optional: Entra ID tenant log export (best effort) ----
    if ($ExportEntraLogs) {
        Info "Creating Entra ID tenant diagnostic setting (SignInLogs + AuditLogs)..."
        try {
            $authRuleId = if ($dep.Outputs.ContainsKey("abstractDiagnosticsAuthRuleId")) { $dep.Outputs["abstractDiagnosticsAuthRuleId"].Value } else {
                "/subscriptions/$($ctx.Subscription.Id)/resourceGroups/$ResourceGroup/providers/Microsoft.EventHub/namespaces/$NamespaceName/authorizationRules/RootManageSharedAccessKey"
            }
            $entraHub = ($HubSources | Where-Object { $_ -match 'entra|aad' } | Select-Object -First 1)
            if (-not $entraHub) { $entraHub = $HubSources[0] }
            $hubName = $(if ($Environment) { "$HubPrefix-$Environment-$entraHub" } else { "$HubPrefix-$entraHub" }).ToLower()
            $body = @{ name = "abstract-entra-logs"; properties = @{
                eventHubAuthorizationRuleId = $authRuleId
                eventHubName                = $hubName
                logs = @(
                    @{ category = "SignInLogs"; enabled = $true },
                    @{ category = "AuditLogs";  enabled = $true }
                )
            } } | ConvertTo-Json -Depth 6
            $resp = Invoke-AzRestMethod -Method PUT -Path "/providers/microsoft.aadiam/diagnosticSettings/abstract-entra-logs?api-version=2017-04-01-preview" -Payload $body
            if ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 300) { Ok "Entra ID sign-in + audit logs now stream to hub '$hubName'." }
            else { Warn "Entra export returned HTTP $($resp.StatusCode): $($resp.Content)" }
        } catch {
            Warn "Entra log export failed: $($_.Exception.Message)"
            Warn "Requires Entra ID P1/P2 + Security Administrator. Manual path: Entra ID > Diagnostic settings > Stream to an event hub."
        }
    }
}
elseif ($Action -eq "Delete") {
    $ns = Get-AzEventHubNamespace -ResourceGroupName $ResourceGroup -Name $NamespaceName -ErrorAction SilentlyContinue
    if (-not $ns) { throw "Namespace '$NamespaceName' not found in resource group '$ResourceGroup'." }
    if (-not $Force) {
        $c = Choose "Permanently delete namespace '$NamespaceName' and ALL hubs/data in it?" @("yes","no") "no"
        if ($c -ne "yes") { Warn "Delete cancelled."; Stop-Clean 0 }
    }
    Info "Deleting namespace '$NamespaceName' (this also deletes every hub and its retained events)..."
    Remove-AzEventHubNamespace -ResourceGroupName $ResourceGroup -Name $NamespaceName
    Ok "Deleted '$NamespaceName'."
    Warn "NOT deleted (remove separately if desired): checkpoint Storage Account, private endpoints,"
    Warn "diagnostic settings (subscription + Entra), and the 'abstract-eventhub-ingestion' app registration."
    Stop-Clean 0
}

# ---- Credentials: Deploy falls through here; Credentials action starts here ----
Info "Retrieving Abstract onboarding details..."
$ns = Get-AzEventHubNamespace -ResourceGroupName $ResourceGroup -Name $NamespaceName -ErrorAction SilentlyContinue
if (-not $ns) { throw "Namespace '$NamespaceName' not found in resource group '$ResourceGroup'." }
$hubList = @(Get-AzEventHub -ResourceGroupName $ResourceGroup -NamespaceName $NamespaceName)
$nsFqdn = "$NamespaceName.servicebus.windows.net"
$tenantId = (Get-AzContext).Tenant.Id

# Event Hub namespace connection string (SAS / Connection String method)
$nsConn = $null
if ($AuthMethod -in @("ConnectionString","Both")) {
    try {
        $keys = Get-AzEventHubKey -ResourceGroupName $ResourceGroup -NamespaceName $NamespaceName -Name $SasRuleName -ErrorAction Stop
        $nsConn = $keys.PrimaryConnectionString
    } catch {
        Warn "Could not read keys for SAS rule '$SasRuleName' ($($_.Exception.Message))."
        Warn "If SAS is disabled (RBAC-only), use the Service Principal method instead. Otherwise:"
        Warn "  az eventhubs namespace authorization-rule keys list -g $ResourceGroup --namespace-name $NamespaceName -n $SasRuleName"
    }
}

# Checkpoint storage account details (both methods need it)
$saConn = $null; $saUrl = $null; $saName = $StorageAccountName
if (-not $saName) {
    $sa = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -ErrorAction SilentlyContinue | Where-Object { $_.StorageAccountName -like "abs*" } | Select-Object -First 1
    if ($sa) { $saName = $sa.StorageAccountName }
}
if ($saName) {
    try {
        $saUrl = "https://$saName.blob.core.windows.net"
        $saKey = (Get-AzStorageAccountKey -ResourceGroupName $ResourceGroup -Name $saName -ErrorAction Stop)[0].Value
        $saConn = "DefaultEndpointsProtocol=https;AccountName=$saName;AccountKey=$saKey;EndpointSuffix=core.windows.net"
    } catch {
        Warn "Could not read keys for Storage Account '$saName' ($($_.Exception.Message))."
        Warn "If shared-key access is disabled, use the Service Principal method (Storage Blob Data Contributor is already granted)."
    }
} else {
    Warn "No checkpoint Storage Account found (looked for 'abs*' in $ResourceGroup). Pass -StorageAccountName if it has a different name."
}

$results = @()
foreach ($h in $hubList) {
    $results += [pscustomobject]@{
        EventHub            = $h.Name
        NamespaceFqdn       = $nsFqdn
        ConsumerGroup       = $ConsumerGroup
        BlobContainer       = $BlobContainerName
        StorageAccountUrl   = $saUrl
        EhConnectionString  = $(if ($nsConn) { "$nsConn;EntityPath=$($h.Name)" } else { $null })
        StorageConnString   = $saConn
        TenantId            = $tenantId
        ClientId            = $script:SpnAppId
    }
}

# ---- Stop logging BEFORE printing secrets so they are never captured ----
if ($logging) { Stop-Transcript | Out-Null; $logging = $false }

Write-Host ""
Write-Host "=============== ABSTRACT 'AZURE EVENT HUB' ONBOARDING DETAILS ===============" -ForegroundColor $Brand
Write-Host "  In Abstract: Data Flow Management > Streams > Add Stream > Azure Event Hub" -ForegroundColor White
Write-Host ("  Namespace FQDN : {0}" -f $nsFqdn)
Write-Host ("  Consumer Group : {0}" -f $ConsumerGroup)
Write-Host ("  Blob Container : {0}" -f $BlobContainerName)
if ($saName) { Write-Host ("  Storage Account: {0}  ({1})" -f $saName, $saUrl) }

if ($AuthMethod -in @("ConnectionString","Both")) {
    Write-Host ""
    Write-Host "  --- Method 1: Connection String (paste these into the Abstract modal) ---" -ForegroundColor $Brand2
    foreach ($r in $results) {
        Write-Host ""
        Write-Host ("  Event Hub                      : {0}" -f $r.EventHub) -ForegroundColor White
        if ($r.EhConnectionString) { Write-Host ("  Event Hub Connection String    : {0}" -f $r.EhConnectionString) -ForegroundColor Yellow }
    }
    if ($saConn) {
        Write-Host ""
        Write-Host ("  Storage Account Conn String    : {0}" -f $saConn) -ForegroundColor Yellow
    }
}
if ($AuthMethod -in @("ServicePrincipal","Both")) {
    Write-Host ""
    Write-Host "  --- Method 2: Service Principal (paste these into the Abstract modal) ---" -ForegroundColor $Brand2
    foreach ($r in $results) {
        Write-Host ""
        Write-Host ("  Event Hub Name        : {0}" -f $r.EventHub) -ForegroundColor White
        Write-Host ("  Consumer Group        : {0}" -f $r.ConsumerGroup)
        Write-Host ("  Blob Container Name   : {0}" -f $r.BlobContainer)
        Write-Host ("  Fully Qualified NS    : {0}" -f $r.NamespaceFqdn)
        if ($r.StorageAccountUrl) { Write-Host ("  Storage Account URL   : {0}" -f $r.StorageAccountUrl) }
        Write-Host ("  Tenant (Directory) ID : {0}" -f $r.TenantId)
        if ($r.ClientId) { Write-Host ("  Client (App) ID       : {0}" -f $r.ClientId) }
        else { Write-Host  "  Client (App) ID       : <your app registration's Application (client) ID>" -ForegroundColor DarkGray }
    }
    if ($script:SpnSecret) {
        Write-Host ""
        Write-Host ("  Client Secret (VALUE) : {0}" -f $script:SpnSecret) -ForegroundColor Yellow
        Write-Host  "  ^ Shown ONCE - it cannot be retrieved again. Store it in a vault now." -ForegroundColor Yellow
    } else {
        Write-Host  "  Client Secret         : <create/retrieve in Entra ID > App registrations > Certificates & secrets>" -ForegroundColor DarkGray
    }
}
Write-Host ""
Write-Host "  >> Secrets above are shown once and NOT saved to the transcript log.        <<" -ForegroundColor Yellow
Write-Host "  >> Next: confirm your log sources stream to the hub(s) - Activity Log,      <<" -ForegroundColor Yellow
Write-Host "  >> Entra ID diagnostic settings, Defender XDR Streaming API, etc.           <<" -ForegroundColor Yellow
Write-Host "==============================================================================" -ForegroundColor $Brand
if ($OutFile) {
    $results | ConvertTo-Json -Depth 4 | Out-File -FilePath $OutFile -Encoding utf8
    Warn "Credentials (incl. connection strings) written to $OutFile - protect or delete."
}
