// =============================================================================
//  Abstract Security - Azure Sentinel DESTINATION onboarding (Bicep)
//  Version : 3.0
//  Author  : Abstract Security - Solutions Engineering
//
//  Provisions the Azure side of the Abstract "Azure Sentinel Destination"
//  integration - i.e. everything needed for Abstract to deliver events into
//  Microsoft Sentinel through the Azure Monitor Logs Ingestion API
//  (docs.abstractsecurity.app -> Integrations -> Destination -> Azure Sentinel
//  Destination).
//
//  Full stack (resource-group scope):
//    1. Log Analytics workspace     (create new, or reference an existing one
//                                     in this resource group)
//    2. Microsoft Sentinel          (onboarding state enabled on the workspace)
//    3. Data Collection Endpoint    (DCE - the ingestion endpoint)
//    4. Custom log table (*_CL)     (DCR-based, with a parameterizable schema)
//    5. Data Collection Rule (DCR)  (stream declaration -> workspace table)
//    6. RBAC on the DCR             (Monitoring Metrics Publisher + Monitoring
//                                     Contributor) for the supplied service
//                                     principal, per the Abstract docs.
//
//  NOTE: an Entra app registration + client secret CANNOT be created in ARM.
//  Create the app first (or have Abstract Solutions create it), pass its
//  service principal OBJECT id as principalId, and enter the Client ID /
//  Client Secret / Tenant ID directly in the Abstract destination modal.
//
//  The deployment OUTPUTS map field-for-field to the Abstract modal:
//    Data Collection Rule ID   -> dataCollectionRuleImmutableId
//    Data Collection Endpoint  -> dataCollectionEndpointUrl
//    Log Stream Name           -> logStreamName  (Custom-<table>)
//
//  Compile to ARM:  az bicep build --file sentinel-destination.bicep \
//                       --outfile sentinel-destination.azuredeploy.json
// =============================================================================

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Azure region for the workspace, DCE and DCR. Keep these consistent (the DCE/DCR must be in the same region as the workspace).')
param location string = resourceGroup().location

@description('Tags applied to every resource created by this template.')
param tags object = {}

// ---------------------------------------------------------------------------
// Log Analytics workspace + Sentinel
// ---------------------------------------------------------------------------
@description('Create a new Log Analytics workspace. Set false to target an EXISTING workspace in THIS resource group (provide its name in workspaceName).')
param createWorkspace bool = true

@description('Workspace name. When creating: leave empty to auto-generate (abstract-sentinel-<hash>). When using an existing workspace: the exact name of that workspace (must live in this resource group).')
param workspaceName string = ''

@description('Workspace pricing tier. PerGB2018 is the standard pay-as-you-go tier.')
@allowed(['PerGB2018', 'CapacityReservation', 'Free', 'Standalone', 'PerNode'])
param workspaceSku string = 'PerGB2018'

@description('Workspace data retention in days (only applied when creating a new workspace).')
@minValue(7)
@maxValue(730)
param workspaceRetentionDays int = 90

@description('Enable Microsoft Sentinel on the workspace (only applied when creating a new workspace; assumed already enabled for existing workspaces).')
param enableSentinel bool = true

@description('Region of the EXISTING workspace (Existing mode only). The DCE and DCR MUST be created in the same region as the target workspace, so if your existing workspace is in a different region than this deployment, set it here (e.g. eastus2). Leave empty to use the deployment location.')
param existingWorkspaceLocation string = ''

// ---------------------------------------------------------------------------
// Data Collection Endpoint + Rule + custom table
// ---------------------------------------------------------------------------
@description('Name of the Data Collection Endpoint (DCE) that receives data from Abstract.')
param dataCollectionEndpointName string = 'abstract-dce'

@description('Name of the Data Collection Rule (DCR) that routes data into the workspace table.')
param dataCollectionRuleName string = 'abstract-dcr'

@description('Custom log table name. MUST end in _CL. Enter this (as the stream Custom-<table>) in the "Log Stream Name" field of the Abstract destination modal.')
param customTableName string = 'AbstractEventLogs_CL'

@description('Schema of the custom table and the DCR stream. The default is a minimal, safe schema - replace it with the columns from Abstract\'s all_fields.json to capture the full Abstract Common Schema. TimeGenerated (datetime) is REQUIRED by Log Analytics.')
param tableColumns array = [
  {
    name: 'TimeGenerated'
    type: 'datetime'
  }
  {
    name: 'Message'
    type: 'string'
  }
  {
    name: 'AbstractEvent'
    type: 'dynamic'
  }
]

// ---------------------------------------------------------------------------
// RBAC for the Abstract service principal (granted on the DCR)
// ---------------------------------------------------------------------------
@description('Object ID of the service principal Abstract authenticates as (the Enterprise Application object ID, NOT the Application/client ID). Leave empty to skip role assignments and grant them yourself later.')
param principalId string = ''

@description('Type of the principal being granted RBAC (avoids PrincipalNotFound on freshly created SPNs).')
@allowed(['ServicePrincipal', 'User', 'Group'])
param principalType string = 'ServicePrincipal'

// ---------------------------------------------------------------------------
// Derived values
// ---------------------------------------------------------------------------
var autoWorkspaceName = 'abstract-sentinel-${uniqueString(resourceGroup().id)}'
var effectiveWorkspaceName = createWorkspace ? (empty(workspaceName) ? autoWorkspaceName : workspaceName) : workspaceName
var workspaceResourceId = resourceId('Microsoft.OperationalInsights/workspaces', effectiveWorkspaceName)

// The DCE and DCR must be co-located with the destination workspace. When
// creating a new workspace they share the deployment location; for an existing
// workspace in another region, callers set existingWorkspaceLocation.
var effectiveLocation = createWorkspace ? location : (empty(existingWorkspaceLocation) ? location : existingWorkspaceLocation)

// Stream name for a DCR-based custom table is always Custom-<table>.
var streamName = 'Custom-${customTableName}'
var logAnalyticsDestinationName = 'abstractSentinelWorkspace'

// Built-in role definition IDs (per Abstract docs).
var monitoringMetricsPublisherRoleId = '3913510d-42f4-4e42-8a64-420c390055eb'
var monitoringContributorRoleId = '749f88d5-cbae-40b8-bcfc-e573ddc772fa'

// ---------------------------------------------------------------------------
// Log Analytics workspace
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

// Microsoft Sentinel onboarding (extension resource on the workspace).
resource sentinelOnboarding 'Microsoft.SecurityInsights/onboardingStates@2024-03-01' = if (createWorkspace && enableSentinel) {
  scope: workspace
  name: 'default'
  properties: {}
}

// ---------------------------------------------------------------------------
// Custom log table (DCR-based, *_CL). Created on the (new or existing) workspace.
// ---------------------------------------------------------------------------
resource customTable 'Microsoft.OperationalInsights/workspaces/tables@2022-10-01' = {
  name: '${effectiveWorkspaceName}/${customTableName}'
  properties: {
    schema: {
      name: customTableName
      // Log Analytics table columns want 'dateTime' (capital T); everything else is lower-case.
      columns: [for col in tableColumns: {
        name: col.name
        type: toLower(string(col.type)) == 'datetime' ? 'dateTime' : toLower(string(col.type))
      }]
    }
    totalRetentionInDays: workspaceRetentionDays
  }
  dependsOn: createWorkspace ? [
    workspace
  ] : []
}

// ---------------------------------------------------------------------------
// Data Collection Endpoint
// ---------------------------------------------------------------------------
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

// ---------------------------------------------------------------------------
// Data Collection Rule: Custom-<table> stream -> workspace custom table
// ---------------------------------------------------------------------------
resource dcr 'Microsoft.Insights/dataCollectionRules@2023-03-11' = {
  name: dataCollectionRuleName
  location: effectiveLocation
  tags: tags
  properties: {
    dataCollectionEndpointId: dce.id
    streamDeclarations: {
      // DCR stream column types are all lower-case (datetime, string, int, ...).
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
        streams: [
          streamName
        ]
        destinations: [
          logAnalyticsDestinationName
        ]
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
// RBAC on the DCR for the Abstract service principal (both roles per docs)
// ---------------------------------------------------------------------------
resource metricsPublisherAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(dcr.id, principalId, monitoringMetricsPublisherRoleId)
  scope: dcr
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringMetricsPublisherRoleId)
    principalType: principalType
  }
}

resource monitoringContributorAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (!empty(principalId)) {
  name: guid(dcr.id, principalId, monitoringContributorRoleId)
  scope: dcr
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', monitoringContributorRoleId)
    principalType: principalType
  }
}

// ---------------------------------------------------------------------------
// Outputs - field-for-field for the Abstract "Azure Sentinel Destination" modal
// ---------------------------------------------------------------------------
output workspaceName string = effectiveWorkspaceName
output workspaceResourceId string = workspaceResourceId
output customTableName string = customTableName
output dataCollectionRuleImmutableId string = dcr.properties.immutableId
output dataCollectionEndpointUrl string = dce.properties.logsIngestion.endpoint
output logStreamName string = streamName
output rbacAssigned bool = !empty(principalId)

output abstractSentinelOnboarding object = {
  azureMonitorDetails: {
    dataCollectionRuleId: dcr.properties.immutableId
    dataCollectionEndpoint: dce.properties.logsIngestion.endpoint
    logStreamName: streamName
  }
  authentication: {
    clientId: '(Entra ID > App registrations > your app > Application (client) ID)'
    clientSecretValue: '(Entra ID > App registrations > your app > Certificates & secrets)'
    applicationTenantId: subscription().tenantId
  }
  rbac: !empty(principalId) ? 'Monitoring Metrics Publisher + Monitoring Contributor granted on the DCR to principal ${principalId}' : '(no principalId supplied - assign both roles on the DCR yourself)'
  docs: 'https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-sentinel-destination/'
}
