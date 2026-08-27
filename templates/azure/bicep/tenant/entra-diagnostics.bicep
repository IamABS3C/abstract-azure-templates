// =============================================================================
//  Abstract Security - Microsoft Entra ID log streams -> Event Hub
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : TENANT
//
//  Why this is a SEPARATE template from the policy pack
//  ----------------------------------------------------
//  Entra ID activity logs (sign-ins, audit, provisioning, identity-protection
//  risk, Graph activity) are NOT Azure Monitor resource logs. They are a single
//  TENANT-level diagnostic setting on the microsoft.aadiam provider. That means:
//    * Azure Policy cannot manage them - there is nothing per-subscription to
//      evaluate, so no DeployIfNotExists can reach them.
//    * They are configured ONCE per tenant, not once per subscription. Adding a
//      new subscription changes nothing here.
//    * The deployment must target TENANT scope, so it runs from the CLI or
//      PowerShell - the portal "Deploy to Azure" button cannot do tenant scope.
//  This is a feature, not a gap: one command onboards identity telemetry for the
//  entire organisation, permanently.
//
//  Requires
//  --------
//    * Security Administrator on the Entra tenant (Attribute Log Administrator
//      as well if you enable CustomSecurityAttributeAuditLogs).
//    * The Event Hub must already exist. Azure never creates it for you here.
//    * Entra ID P1/P2 for several categories - see entraLogCategories below.
//
//  Deploy
//  ------
//    az deployment tenant create \
//      --location eastus \
//      --template-file templates/tenant/entra-diagnostics.bicep \
//      --parameters eventHubAuthorizationRuleId=<namespace-auth-rule-id> \
//                   eventHubName=abs-prod-entra
//
//  Expect up to THREE DAYS before the first Entra records land in the hub -
//  Microsoft documents this latency for Entra diagnostic settings. Do not treat
//  an empty hub in the first hour as a failure.
// =============================================================================

targetScope = 'tenant'

@description('Name of the Entra ID diagnostic setting. Multiple settings are allowed, so this can sit alongside a setting you already send to another SIEM.')
@minLength(1)
@maxLength(260)
param settingName string = 'abstract-entra-logstream'

@description('Resource ID of an Event Hubs namespace authorization rule with Send rights. Use the abstractDiagnosticsAuthRuleId output of main.bicep.')
param eventHubAuthorizationRuleId string

@description('Event Hub that receives the Entra ID stream. Give identity its own hub so it can be partitioned and scaled independently of resource logs.')
param eventHubName string = 'abs-prod-entra'

@description('''
Entra ID log categories to stream. Defaults to the security-relevant set that
every Abstract Entra detection is built on.

Licensing / availability notes (revised 2026-08-26 against Microsoft's own
licensing table - the previous note overstated the P1 requirement):
  AuditLogs, SignInLogs        - available on Entra ID FREE. Microsoft's
                                 monitoring-and-health licensing table lists
                                 both as "Yes" for Free and for P1/P2.
  NonInteractiveUserSignInLogs,
  ServicePrincipalSignInLogs,
  ManagedIdentitySignInLogs    - NO documented P1/P2 requirement exists for
                                 these as diagnostic-setting EXPORT categories.
                                 All 80 files in Microsoft's
                                 identity/monitoring-health docs were checked.
                                 The real P1/P2 gate people are thinking of is
                                 on DOWNLOADING sign-in logs via the Microsoft
                                 Graph API, which is a different operation.
                                 Treat a P1 claim here as unverified.
  ProvisioningLogs             - P1/P2 (Free = "No" in the licensing table),
                                 and only populated when you provision via Entra
  MicrosoftGraphActivityLogs   - P1/P2, explicitly stated
  RiskyUsers, UserRiskEvents,
  RiskyServicePrincipals, ServicePrincipalRiskEvents,
  RiskyAgents, AgentRiskEvents - Entra ID Protection (P2)
  ADFSSignInLogs               - only when AD FS is in use
  NetworkAccessTrafficLogs,
  EnrichedOffice365AuditLogs,
  RemoteNetworkHealthLogs      - only with Global Secure Access / Entra
                                 Internet Access + Private Access
  MicrosoftGraphActivityLogs   - high volume; the single best source for
                                 "what did this token actually do". At 100k
                                 users Microsoft publishes ~1,000 GiB/month and
                                 ~4.8M Event Hubs messages/month. Size for it.
  MicrosoftServicePrincipalSignInLogs - preview, VERY high volume, first-party
                                 service-to-service. Microsoft advises against
                                 acting on it. Off by default here.
  CustomSecurityAttributeAuditLogs - needs Attribute Log Administrator, and
                                 Microsoft recommends keeping it separate from
                                 the directory audit stream.
  B2CRequestLogs               - Azure AD B2C tenants only.

Selecting a category your tenant does not license or use is harmless - it simply
produces no records. Note the corollary, which is a silent-failure shape: a
category can be selectable and emit nothing forever because the underlying
PRODUCT is not in use (NetworkAccessTrafficLogs without Global Secure Access is
the common case), and that is indistinguishable from a broken pipeline unless
you know to expect it.

Volume: Microsoft states non-interactive and service-principal sign-ins "can be
5 to 10 times larger than the interactive user sign-ins". Per-event sizes are
~2 KB for audit and ~11.5 KB for sign-ins; a 100,000-user tenant runs about
1.5 million events per day.
''')
param entraLogCategories array = [
  'AuditLogs'
  'SignInLogs'
  'NonInteractiveUserSignInLogs'
  'ServicePrincipalSignInLogs'
  'ManagedIdentitySignInLogs'
  'ProvisioningLogs'
  'ADFSSignInLogs'
  'RiskyUsers'
  'UserRiskEvents'
  'RiskyServicePrincipals'
  'ServicePrincipalRiskEvents'
  'MicrosoftGraphActivityLogs'
]

// ---------------------------------------------------------------------------
// The tenant-level Entra diagnostic setting.
// Provider name is lower-case `microsoft.aadiam` by convention; API version
// 2017-04-01 is the current one - there has never been a newer stable version.
// ---------------------------------------------------------------------------
resource entraDiagnostics 'microsoft.aadiam/diagnosticSettings@2017-04-01' = {
  name: settingName
  properties: {
    eventHubAuthorizationRuleId: eventHubAuthorizationRuleId
    eventHubName: eventHubName
    logs: [for category in entraLogCategories: {
      category: category
      enabled: true
    }]
  }
}

output diagnosticSettingName string = entraDiagnostics.name
output eventHubName string = eventHubName
output streamedCategories array = entraLogCategories

output abstractOnboarding object = {
  scope: 'Microsoft Entra ID tenant - one setting covers the whole organisation'
  policyManaged: 'No. Entra diagnostic settings are tenant-level; Azure Policy has no per-subscription object to evaluate. This template IS the automation.'
  firstDataLatency: 'Up to 3 days for the first records, per Microsoft documentation.'
  notIncluded: 'Microsoft 365 unified audit (Exchange/SharePoint/Teams) and Defender XDR advanced hunting are separate streams - see docs/azure-log-streams.md'
}
