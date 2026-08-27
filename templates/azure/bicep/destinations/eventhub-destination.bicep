// =============================================================================
//  Abstract Security - Azure Event Hub DESTINATION onboarding (Bicep)
//  Version : 3.0
//  Author  : Abstract Security - Solutions Engineering
//
//  Provisions the Azure side of the Abstract "Azure EventHub Destination"
//  integration - i.e. an Event Hub that Abstract WRITES processed events TO
//  (docs.abstractsecurity.app -> Integrations -> Destination -> Azure EventHub
//  Destination).
//
//  What the Abstract destination modal asks for, and where it comes from here:
//    | Abstract field             | Source                                      |
//    | EventHub Name              | the hub created below (default              |
//    |                            | 'abstract-destination-hub')                 |
//    | EventHub Connection String | primary connection string of the Send SAS   |
//    |                            | rule 'abstract-send' (namespace level)      |
//
//  Deploys:
//    1. Event Hubs namespace        (Standard minimum, per Abstract docs)
//    2. One Event Hub               (the destination hub Abstract writes to)
//    3. Send-only SAS rule          ('abstract-send' - least privilege for a
//                                     producer; keys NEVER emitted in outputs)
//    4. Optional RBAC               (Azure Event Hubs Data Sender) for a
//                                     service principal, when Abstract writes
//                                     via Entra ID instead of a connection string
//    5. Networking                  public / IP allowlist / private endpoint,
//                                     Safe Mode guardrails (Abstract egress must
//                                     be able to REACH the hub to deliver events)
//
//  Compile to ARM:  az bicep build --file eventhub-destination.bicep \
//                       --outfile eventhub-destination.azuredeploy.json
// =============================================================================

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Azure region for all resources.')
param location string = resourceGroup().location

@description('Event Hubs namespace name - globally unique, 6-50 chars, letters/numbers/hyphens, must start with a letter. Becomes <name>.servicebus.windows.net.')
@minLength(6)
@maxLength(50)
param namespaceName string

@description('Namespace pricing tier. Abstract requires Standard as the minimum tier.')
@allowed(['Standard', 'Premium'])
param sku string = 'Standard'

@description('Throughput Units (Standard, 1-40) or Processing Units (Premium: 1, 2, 4, 8, 16).')
@minValue(1)
@maxValue(40)
param capacity int = 1

@description('Enable Auto-Inflate so the namespace scales Throughput Units automatically (Standard tier only).')
param autoInflate bool = true

@description('Auto-Inflate ceiling in Throughput Units (Standard only, max 40).')
@minValue(1)
@maxValue(40)
param maxThroughputUnits int = 20

@description('Minimum TLS version the namespace accepts.')
@allowed(['1.0', '1.1', '1.2'])
param minimumTlsVersion string = '1.2'

@description('Tags applied to every resource created by this template.')
param tags object = {}

// ---------------------------------------------------------------------------
// Destination hub
// ---------------------------------------------------------------------------
@description('Name of the Event Hub that Abstract delivers events to. Enter this in the "EventHub Name" field of the Abstract destination integration.')
@minLength(1)
@maxLength(256)
param eventHubName string = 'abstract-destination-hub'

@description('Partition count for the destination hub. Abstract docs recommend at least 4. Cannot be reduced after creation; max 32 on Standard.')
@minValue(1)
@maxValue(32)
param partitionCount int = 4

@description('Message retention in days. Size this to ride out delivery delays. Standard allows 1-7.')
@minValue(1)
@maxValue(7)
param retentionDays int = 7

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------
@description('Create the Send-only SAS rule used for "EventHub Connection String" auth in the Abstract destination modal. When false, local (SAS) auth is fully DISABLED and only Entra ID / RBAC works.')
param enableSas bool = true

@description('Name of the least-privilege Send SAS rule created at namespace level. Use its primary connection string in the Abstract destination modal instead of RootManageSharedAccessKey.')
param sendRuleName string = 'abstract-send'

@description('Also assign Azure RBAC (Azure Event Hubs Data Sender) so Abstract can deliver events using a service principal / managed identity instead of a connection string.')
param enableRbac bool = false

@description('Object ID of the service principal Abstract authenticates as (the Enterprise Application object ID, NOT the app/client ID). Required only when enableRbac = true.')
param principalId string = ''

@description('Built-in Event Hubs data-plane role granted to the principal. A destination only needs to SEND, so Data Sender is the least-privilege choice.')
@allowed(['Azure Event Hubs Data Sender', 'Azure Event Hubs Data Owner'])
param roleDefinitionName string = 'Azure Event Hubs Data Sender'

@description('Type of the principal being granted RBAC (avoids PrincipalNotFound on freshly created SPNs).')
@allowed(['ServicePrincipal', 'User', 'Group'])
param principalType string = 'ServicePrincipal'

// ---------------------------------------------------------------------------
// Networking + security
// ---------------------------------------------------------------------------
@description('Public IP ranges (CIDR) allowed through the namespace firewall - Abstract egress IPs plus your admin ranges. A non-empty list flips the firewall default action to Deny (unless Safe Mode is on). Empty entries are filtered out.')
param allowedIpRanges array = []

@description('Allow trusted Microsoft services through the firewall.')
param allowAzureServices bool = true

@description('Disable ALL public network access on the namespace (Private Endpoint only). Only honored when safeMode = false. NOTE: blocks Abstract (external SaaS) unless it reaches the namespace privately.')
param disablePublicNetwork bool = false

@description('Create a Private Endpoint for the namespace.')
param enablePrivateEndpoint bool = false

@description('Resource ID of the subnet that will host the Private Endpoint NIC.')
param subnetId string = ''

@description('Resource ID of the privatelink.servicebus.windows.net Private DNS zone (recommended with the Private Endpoint).')
param privateDnsZoneId string = ''

@description('''
Safe Mode guardrails for external SaaS delivery (Abstract):
  true  -> public network access stays ON, the IP allowlist is ignored, and the
           firewall default action stays Allow so Abstract can always deliver.
  false -> disablePublicNetwork / allowedIpRanges are honored exactly as set.
Ship customers safeMode=true for onboarding; harden later.
''')
param safeMode bool = true

// ---------------------------------------------------------------------------
// Diagnostics (health of the destination pipeline itself) — parity with main.bicep
// ---------------------------------------------------------------------------
@description('Enable diagnostic settings on the destination namespace so you can monitor the health of the delivery pipeline itself.')
param enableDiagnostics bool = false

@description('Resource ID of the Log Analytics workspace for namespace diagnostics.')
param logAnalyticsWorkspaceId string = ''

@description('Optional storage account resource ID for diagnostics archive.')
param diagnosticsStorageAccountId string = ''

// ---------------------------------------------------------------------------
// Derived values
// ---------------------------------------------------------------------------
var isStandard = sku == 'Standard'

var cleanedIpRanges = filter(allowedIpRanges, ip => !empty(trim(string(ip))))

var effectivePublicAccess = safeMode ? 'Enabled' : (disablePublicNetwork ? 'Disabled' : 'Enabled')
var effectiveIpRules = safeMode ? [] : cleanedIpRanges
var lockedDown = !safeMode && (length(effectiveIpRules) > 0 || disablePublicNetwork)
var networkDefaultAction = lockedDown ? 'Deny' : 'Allow'

var roleMap = {
  'Azure Event Hubs Data Sender': '2b629674-e913-4c01-ae53-ef4638d8f975'
  'Azure Event Hubs Data Owner': 'f526a384-b230-433a-b45c-95f59c4a2dec'
}

// ---------------------------------------------------------------------------
// Event Hubs namespace
// ---------------------------------------------------------------------------
resource ehNamespace 'Microsoft.EventHub/namespaces@2024-01-01' = {
  name: namespaceName
  location: location
  tags: tags
  sku: {
    name: sku
    tier: sku
    capacity: capacity
  }
  properties: {
    minimumTlsVersion: minimumTlsVersion
    publicNetworkAccess: effectivePublicAccess
    disableLocalAuth: !enableSas
    isAutoInflateEnabled: isStandard && autoInflate
    maximumThroughputUnits: (isStandard && autoInflate) ? maxThroughputUnits : 0
  }
}

resource networkRules 'Microsoft.EventHub/namespaces/networkRuleSets@2024-01-01' = {
  parent: ehNamespace
  name: 'default'
  properties: {
    publicNetworkAccess: effectivePublicAccess
    defaultAction: networkDefaultAction
    trustedServiceAccessEnabled: allowAzureServices
    virtualNetworkRules: []
    ipRules: [for ip in effectiveIpRules: {
      ipMask: ip
      action: 'Allow'
    }]
  }
}

// ---------------------------------------------------------------------------
// Destination hub + Send SAS rule
// ---------------------------------------------------------------------------
resource hub 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = {
  parent: ehNamespace
  name: eventHubName
  properties: {
    partitionCount: partitionCount
    messageRetentionInDays: retentionDays
  }
}

resource sendRule 'Microsoft.EventHub/namespaces/authorizationRules@2024-01-01' = if (enableSas) {
  parent: ehNamespace
  name: sendRuleName
  properties: {
    rights: [
      'Send'
    ]
  }
}

// ---------------------------------------------------------------------------
// Optional RBAC (Entra ID delivery instead of a connection string)
// ---------------------------------------------------------------------------
resource roleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableRbac && !empty(principalId)) {
  name: guid(ehNamespace.id, principalId, roleMap[roleDefinitionName])
  scope: ehNamespace
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', roleMap[roleDefinitionName])
    principalType: principalType
  }
}

// ---------------------------------------------------------------------------
// Private Endpoint + Private DNS zone group
// ---------------------------------------------------------------------------
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (enablePrivateEndpoint && !empty(subnetId)) {
  name: '${namespaceName}-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'eventhub-connection'
        properties: {
          privateLinkServiceId: ehNamespace.id
          groupIds: [
            'namespace'
          ]
        }
      }
    ]
  }
}

resource privateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (enablePrivateEndpoint && !empty(subnetId) && !empty(privateDnsZoneId)) {
  parent: privateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'eventhub-dns'
        properties: {
          privateDnsZoneId: privateDnsZoneId
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Diagnostic settings (delivery-pipeline health) — parity with the source template
// ---------------------------------------------------------------------------
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableDiagnostics && (!empty(logAnalyticsWorkspaceId) || !empty(diagnosticsStorageAccountId))) {
  name: '${namespaceName}-diagnostics'
  scope: ehNamespace
  properties: {
    workspaceId: empty(logAnalyticsWorkspaceId) ? null : logAnalyticsWorkspaceId
    storageAccountId: empty(diagnosticsStorageAccountId) ? null : diagnosticsStorageAccountId
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Outputs (NO keys / connection strings - deployment outputs are readable by
// anyone with reader access. Fetch the connection string from the portal/CLI.)
// ---------------------------------------------------------------------------
output namespaceName string = ehNamespace.name
output namespaceFqdn string = '${ehNamespace.name}.servicebus.windows.net'
output eventHubName string = hub.name
output sendRuleName string = enableSas ? sendRuleName : '(local auth disabled - use RBAC delivery)'
output publicAccess string = effectivePublicAccess
output firewallDefaultAction string = networkDefaultAction
output safeModeEnabled bool = safeMode
output rbacEnabled bool = enableRbac && !empty(principalId)

// Field-for-field answers for the Abstract "Azure EventHub Destination" modal.
output abstractDestinationOnboarding object = {
  eventHubName: hub.name
  eventHubConnectionString: enableSas ? 'Portal: Event Hubs Namespace > Shared access policies > ${sendRuleName} > Connection string-primary key (this is a Send-only key)' : '(SAS disabled - deliver via Entra ID / RBAC)'
  namespaceFqdn: '${ehNamespace.name}.servicebus.windows.net'
  rbacDelivery: enableRbac && !empty(principalId) ? '${roleDefinitionName} granted on the namespace to principal ${principalId}' : '(not configured)'
  docs: 'https://docs.abstractsecurity.app/docs/integrations/destination-integrations/azure-eventhub-destination/'
}
