// =============================================================================
//  Abstract Security - Azure Sentinel DESTINATION, ONE-CLICK incl. app registration
//  Version : 1.0  (opt-in / advanced variant of sentinel-destination.bicep)
//  Author  : Abstract Security - Solutions Engineering
//
//  This variant provisions EVERYTHING the standard template does AND creates the
//  Entra app registration for you, using an Azure deploymentScript. It exists for
//  teams that want a pure portal one-click. It is deliberately heavier and has
//  real prerequisites - for most deployments prefer the standard template
//  (sentinel-destination.bicep) + scripts/new-abstract-sentinel-app.{sh,ps1},
//  which keep the client secret out of Azure entirely.
//
//  WHAT IT CREATES
//    1. Key Vault (RBAC-authorization) to hold the generated client secret.
//    2. RBAC: the supplied user-assigned identity gets Key Vault Secrets Officer
//       on that vault (so the script can write the secret).
//    3. deploymentScript (Azure CLI) running AS the supplied identity: creates
//       (or reuses) the Entra app + service principal, generates a client secret,
//       and STORES THE SECRET IN KEY VAULT. Its outputs contain the app/client id,
//       tenant id, SP object id, and the Key Vault secret URI - NEVER the raw secret.
//    4. Log Analytics workspace + Microsoft Sentinel + DCE + custom _CL table + DCR.
//    5. RBAC on the DCR for the new SP: Monitoring Metrics Publisher + Monitoring
//       Contributor (both, per the Abstract docs).
//    6. (optional) Key Vault Secrets User for an operator object id, so a human can
//       read the secret back to paste into the Abstract modal.
//
//  PREREQUISITES (cannot be bootstrapped inside ARM)
//    * A USER-ASSIGNED MANAGED IDENTITY that already holds a directory role able to
//      create app registrations (e.g. "Application Administrator" or
//      "Cloud Application Administrator"), passed as managedIdentityResourceId.
//    * The deploying principal needs Owner (or Contributor + User Access
//      Administrator) on the resource group to create the role assignments.
//
//  SECURITY NOTE: the client secret is written to Key Vault and is NOT returned in
//  any deployment output. Retrieve it from Key Vault to enter into Abstract.
//
//  Compile:  az bicep build --file sentinel-destination-with-app.bicep \
//                --outfile sentinel-destination-with-app.azuredeploy.json
// =============================================================================

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Azure region for the workspace, DCE, DCR, Key Vault and deployment script.')
param location string = resourceGroup().location

@description('Tags applied to every resource created by this template.')
param tags object = {}

// ---------------------------------------------------------------------------
// Identity that runs the app-registration script (PREREQUISITE - see header)
// ---------------------------------------------------------------------------
@description('Resource ID of a user-assigned managed identity that can create Entra app registrations (holds Application Administrator or equivalent). REQUIRED. Find it with: az identity list --query [].id -o tsv')
param managedIdentityResourceId string

@description('Display name for the Entra app registration created for Abstract.')
param appDisplayName string = 'Abstract-Sentinel-App'

@description('Client-secret validity in years.')
@minValue(1)
@maxValue(2)
param secretValidityYears int = 1

@description('Optional object ID of a user/group to grant Key Vault Secrets User (so they can read the generated secret). Leave empty to grant no reader.')
#disable-next-line secure-secrets-in-params // this is an AAD object id, not a secret
param secretReaderObjectId string = ''

@description('Azure CLI version for the deployment script container.')
param azCliVersion string = '2.60.0'

@description('Name of the Key Vault secret holding the client secret.')
param secretName string = 'abstract-sentinel-client-secret'

@description('''
Force a NEW client secret even when the vault already holds a valid one.

Leave false. The script now rotates only when no secret exists or the existing one
expires within 30 days, which makes re-running this template safe - the previous
behaviour minted a fresh secret on every deployment, so a re-run silently created a
new Key Vault version while Abstract kept using the old value.

Set true only for a deliberate rotation, and update Abstract with the new value.
''')
param forceSecretRotation bool = false

// ---------------------------------------------------------------------------
// Key Vault
// ---------------------------------------------------------------------------
@description('Key Vault name (3-24 lowercase alphanumerics/hyphens, globally unique). Leave empty to auto-generate abstract-kv-<hash>.')
param keyVaultName string = ''

// ---------------------------------------------------------------------------
// Workspace + Sentinel
// ---------------------------------------------------------------------------
@description('Create a new Log Analytics workspace. Set false to target an EXISTING workspace in THIS resource group.')
param createWorkspace bool = true

@description('Workspace name. Creating: empty auto-generates abstract-sentinel-<hash>. Existing: the exact name (in this resource group).')
param workspaceName string = ''

@description('Region of the EXISTING workspace (Existing mode only). DCE/DCR must match it. Empty = use the deployment location.')
param existingWorkspaceLocation string = ''

@allowed(['PerGB2018', 'CapacityReservation', 'Free', 'Standalone', 'PerNode'])
param workspaceSku string = 'PerGB2018'

@minValue(7)
@maxValue(730)
param workspaceRetentionDays int = 90

param enableSentinel bool = true

// ---------------------------------------------------------------------------
// DCE / DCR / custom table
// ---------------------------------------------------------------------------
param dataCollectionEndpointName string = 'abstract-dce'
param dataCollectionRuleName string = 'abstract-dcr'

@description('Custom log table name. MUST end in _CL.')
param customTableName string = 'AbstractEventLogs_CL'

@description('Schema of the custom table and DCR stream. Default is the minimal wrapped-dynamic schema; replace with all_fields-derived columns for explicit ACS columns.')
param tableColumns array = [
  { name: 'TimeGenerated', type: 'datetime' }
  { name: 'Message', type: 'string' }
  { name: 'AbstractEvent', type: 'dynamic' }
]

// ---------------------------------------------------------------------------
// Derived values + role definition IDs
// ---------------------------------------------------------------------------
var autoWorkspaceName = 'abstract-sentinel-${uniqueString(resourceGroup().id)}'
var effectiveWorkspaceName = createWorkspace ? (empty(workspaceName) ? autoWorkspaceName : workspaceName) : workspaceName
var workspaceResourceId = resourceId('Microsoft.OperationalInsights/workspaces', effectiveWorkspaceName)
var effectiveLocation = createWorkspace ? location : (empty(existingWorkspaceLocation) ? location : existingWorkspaceLocation)
var effectiveKeyVaultName = empty(keyVaultName) ? 'abstract-kv-${uniqueString(resourceGroup().id)}' : keyVaultName
var streamName = 'Custom-${customTableName}'
var logAnalyticsDestinationName = 'abstractSentinelWorkspace'
// secretName is now a PARAMETER (it was hardcoded here) so more than one Abstract
// secret can live in the same vault.

var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var monitoringContributorRoleId = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
var keyVaultSecretsOfficerRoleId = 'b86a8fe4-44ce-4948-aee5-eccb2c155cd6'
var keyVaultSecretsUserRoleId = '4633458b-17de-408a-b874-0445c86b69e6'

// Identity that runs the script (must already have app-creation directory rights).
resource runnerIdentity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: last(split(managedIdentityResourceId, '/'))
}

// ---------------------------------------------------------------------------
// Key Vault (RBAC authorization) to hold the client secret
// ---------------------------------------------------------------------------
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: effectiveKeyVaultName
  location: location
  tags: tags
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    publicNetworkAccess: 'Enabled'
  }
}

// Let the script identity write the secret.
resource kvOfficerAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, managedIdentityResourceId, keyVaultSecretsOfficerRoleId)
  scope: keyVault
  properties: {
    principalId: runnerIdentity.properties.principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsOfficerRoleId)
    principalType: 'ServicePrincipal'
  }
}

// Optional: let a human read the secret back.
resource kvReaderAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(secretReaderObjectId)) {
  name: guid(keyVault.id, secretReaderObjectId, keyVaultSecretsUserRoleId)
  scope: keyVault
  properties: {
    principalId: secretReaderObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', keyVaultSecretsUserRoleId)
  }
}

// ---------------------------------------------------------------------------
// deploymentScript: create app + SP + secret, store secret in Key Vault
// ---------------------------------------------------------------------------
resource appScript 'Microsoft.Resources/deploymentScripts@2023-08-01' = {
  name: 'abstract-create-app'
  location: location
  tags: tags
  kind: 'AzureCLI'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityResourceId}': {}
    }
  }
  properties: {
    azCliVersion: azCliVersion
    retentionInterval: 'PT1H'
    cleanupPreference: 'OnSuccess'
    timeout: 'PT30M'
    environmentVariables: [
      { name: 'APP_NAME', value: appDisplayName }
      { name: 'KV_NAME', value: effectiveKeyVaultName }
      { name: 'VAULT_URI', value: keyVault.properties.vaultUri }
      { name: 'SECRET_NAME', value: secretName }
      { name: 'SECRET_YEARS', value: string(secretValidityYears) }
      { name: 'FORCE_ROTATE', value: string(forceSecretRotation) }
    ]
    scriptContent: loadTextContent('scripts/sentinel-app-deploymentscript.sh')
  }
  dependsOn: [
    kvOfficerAssignment
  ]
}

// ---------------------------------------------------------------------------
// Log Analytics workspace + Sentinel
// ---------------------------------------------------------------------------
resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (createWorkspace) {
  name: effectiveWorkspaceName
  location: location
  tags: tags
  properties: {
    sku: {
      name: workspaceSku
    }
    retentionInDays: workspaceRetentionDays
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = if (createWorkspace && enableSentinel) {
  scope: workspace
  name: 'default'
  properties: {}
}

// ---------------------------------------------------------------------------
// Custom log table + DCE + DCR
// ---------------------------------------------------------------------------
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${effectiveWorkspaceName}/${customTableName}'
  properties: {
    schema: {
      name: customTableName
      columns: [for col in tableColumns: {
        name: col.name
        type: toLower(string(col.type)) == 'datetime' ? 'dateTime' : toLower(string(col.type))
      }]
    }
    totalRetentionInDays: workspaceRetentionDays
  }
  dependsOn: createWorkspace ? [workspace] : []
}

resource dce 'Microsoft.Insights/dataCollectionEndpoints@2023-03-11' = {
  name: dataCollectionEndpointName
  location: effectiveLocation
  tags: tags
  properties: {
    networkAcls: {
      publicNetworkAccess: 'Enabled'
    }
  }
}

resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRuleName
  location: effectiveLocation
  tags: tags
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      '${streamName}': {
        columns: [for col in tableColumns: {
          name: col.name
          type: toLower(string(col.type))
        }]
      }
    }
    destinations: {
      logAnalytics: [
        {
          workspaceResourceId: workspaceResourceId
          name: logAnalyticsDestinationName
        }
      ]
    }
    dataFlows: [
      {
        streams: [streamName]
        destinations: [logAnalyticsDestinationName]
        transformKql: 'source'
        outputStream: streamName
      }
    ]
  }
  dependsOn: [
    customTable
  ]
}

// ---------------------------------------------------------------------------
// RBAC on the DCR for the newly-created SP (both roles, per Abstract docs).
// Assignment NAME uses a static discriminator (names cannot depend on the
// script's runtime output); principalId takes the runtime SP object id.
// ---------------------------------------------------------------------------
resource metricsPublisherAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, 'abstract-app-metrics-publisher', monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    principalId: appScript.properties.outputs.spObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalType: 'ServicePrincipal'
  }
}

resource monitoringContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(dcr.id, 'abstract-app-monitoring-contributor', monitoringContributorRoleId)
  scope: dcr
  properties: {
    principalId: appScript.properties.outputs.spObjectId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringContributorRoleId)
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Outputs - everything the Abstract modal needs EXCEPT the secret (in Key Vault)
// ---------------------------------------------------------------------------
output clientId string = appScript.properties.outputs.appId
output applicationTenantId string = appScript.properties.outputs.tenantId
output servicePrincipalObjectId string = appScript.properties.outputs.spObjectId
output clientSecretKeyVaultUri string = appScript.properties.outputs.keyVaultSecretUri
output keyVaultName string = effectiveKeyVaultName
output workspaceName string = effectiveWorkspaceName
output customTableName string = customTableName
output dataCollectionRuleImmutableId string = dcr.properties.immutableId
output dataCollectionEndpointUrl string = dce.properties.logsIngestion.endpoint
output logStreamName string = streamName
output abstractModalHint string = 'Client Secret Value = read secret "${secretName}" from Key Vault "${effectiveKeyVaultName}"; all other fields are in the outputs above.'
