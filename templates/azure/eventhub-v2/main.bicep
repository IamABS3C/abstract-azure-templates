// =============================================================================
//  Abstract Security - Azure Event Hub onboarding (Bicep)
//  Version : 2.0
//  Author  : Abstract Security - Solutions Engineering
//
//  Deploys EVERYTHING the Abstract "Azure Event Hub" integration needs, per
//  the official documentation (docs.abstract.security -> Azure Event Hub):
//
//    1. Event Hubs namespace        (Standard minimum per Abstract docs)
//    2. One or many Event Hubs      (auto-named per log source, or explicit)
//    3. Consumer group              ('abstract' by default, per hub)
//    4. Checkpoint Storage Account  + private blob container - REQUIRED by the
//       Abstract consumer for checkpointing / lease management
//    5. Authentication - one or both of:
//         - Connection String : SAS rule 'abstract-access' (namespace level,
//           optional per-hub rules). Keys are NEVER emitted in outputs.
//         - Service Principal : RBAC role assignments
//             * Azure Event Hubs Data Receiver   on the namespace
//             * Storage Blob Data Contributor    on the checkpoint storage
//    6. Networking - public, IP allowlist, private endpoints (namespace +
//       storage), trusted-services bypass, and Safe Mode guardrails
//    7. Diagnostic settings -> Log Analytics / archive storage
//
//  Compile to ARM JSON:  az bicep build --file main.bicep --outfile azuredeploy.json
//  (a pre-compiled, hand-verified azuredeploy.json ships at the repo root and
//   backs the "Deploy to Azure" button together with createUiDefinition.json)
//
//  SKU constraints worth knowing:
//    - Basic    : 1-day max retention, ONLY the $Default consumer group, no IP
//                 firewall, no auto-inflate. NOT recommended - Abstract docs
//                 state Standard is the minimum tier.
//    - Standard : auto-inflate, IP rules, private endpoints, consumer groups.
//    - Premium  : capacity must be 1/2/4/8/16 PUs; no auto-inflate.
//
//  Throughput sizing (from the Abstract docs):
//    | Expected events/sec | Throughput Units (max 40) | Partitions (max 32) |
//    |   1 MB/s            |  1 TU                     |  1+                 |
//    |   2 MB/s            |  2 TU                     |  2+                 |
//    |  10 MB/s            | 10 TU                     | 10+                 |
//    |  32 MB/s            | 32 TU                     | 32                  |
// =============================================================================

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Azure region for all resources. Event Hubs must be in the same region as the resources being monitored when those resources are regional.')
param location string = resourceGroup().location

@description('Event Hubs namespace name - globally unique, 6-50 chars, letters/numbers/hyphens, must start with a letter.')
@minLength(6)
@maxLength(50)
param namespaceName string

@description('Namespace pricing tier. Abstract requires STANDARD as the minimum tier (Basic lacks custom consumer groups, IP firewall and >1 day retention; it is allowed here only for lab scenarios).')
@allowed(['Basic', 'Standard', 'Premium'])
param sku string = 'Standard'

@description('Throughput Units (Basic/Standard, 1-40) or Processing Units (Premium: 1, 2, 4, 8, 16). Sizing: ~1 TU per 1 MB/s of expected ingress - see the table in the template header.')
@minValue(1)
@maxValue(40)
param capacity int = 1

@description('Enable Auto-Inflate so the namespace scales Throughput Units automatically with load (Standard tier only; ignored on Basic/Premium).')
param autoInflate bool = true

@description('Auto-Inflate ceiling in Throughput Units (Standard only, max 40).')
@minValue(1)
@maxValue(40)
param maxThroughputUnits int = 20

@description('Minimum TLS version the namespace accepts. Leave at 1.2 unless a legacy producer forces otherwise.')
@allowed(['1.0', '1.1', '1.2'])
param minimumTlsVersion string = '1.2'

@description('Tags applied to every resource created by this template.')
param tags object = {}

// ---------------------------------------------------------------------------
// Event hubs - auto naming OR explicit definitions
// ---------------------------------------------------------------------------
@description('true = generate hub names as <hubPrefix>-<environment>-<source> from hubSources; false = use the eventHubs array verbatim.')
param autoHubNaming bool = true

@description('Prefix for auto-generated hub names (e.g. "abs" -> abs-prod-entra).')
param hubPrefix string = 'abs'

@description('Environment token used in auto-generated hub names (prod, staging, dev, ...).')
param environment string = 'prod'

@description('Log sources - one Event Hub is generated per entry when autoHubNaming = true. Typical sources: activity (Azure Activity Log), entra (Entra ID sign-in/audit), defender (Defender XDR streaming), m365, resource (Azure Resource Logs).')
param hubSources array = [
  'activity'
  'entra'
  'defender'
]

@description('Explicit hub definitions, used only when autoHubNaming = false: [{ name, partitionCount, retentionDays }].')
param eventHubs array = [
  {
    name: 'default-hub'
    partitionCount: 4
    retentionDays: 7
  }
]

@description('Partition count for auto-generated hubs. Abstract docs recommend AT LEAST 4. Partitions cannot be reduced after creation; max 32 on Standard.')
@minValue(1)
@maxValue(32)
param defaultPartitionCount int = 4

@description('Message retention in days for auto-generated hubs. Size this to ride out ingestion downtime/delay (Abstract docs). Standard allows 1-7; Basic is forced to 1.')
@minValue(1)
@maxValue(7)
param defaultRetentionDays int = 7

@description('Consumer group created on every hub for the Abstract platform. Enter this value in the "Event Hub Consumer Group" field of the Abstract integration. Ignored on Basic SKU (only $Default exists there).')
param consumerGroupName string = 'abstract'

// ---------------------------------------------------------------------------
// Authentication - Connection String (SAS) and/or Service Principal (RBAC)
// Matches the two auth methods in the Abstract integration modal.
// ---------------------------------------------------------------------------
@description('Create SAS authorization rules for Connection String authentication in Abstract. When false, local (SAS) auth is fully DISABLED on the namespace and only Entra ID / RBAC works.')
param enableSas bool = true

@description('Name of the least-privilege SAS rule created at namespace level (and per hub when perHubSasRules = true). Prefer this over RootManageSharedAccessKey when pasting a connection string into Abstract.')
param sasRuleName string = 'abstract-access'

@description('Rights for the SAS rule. Listen is all Abstract needs to consume; include Send only if log producers will share the same rule.')
param sasRights array = [
  'Listen'
]

@description('Also create a per-hub SAS rule with the same name/rights - a tighter blast radius than the namespace-level rule.')
param perHubSasRules bool = false

@description('Assign Azure RBAC roles for Service Principal (role-based) authentication in Abstract: Event Hubs role on the namespace + Storage Blob Data role on the checkpoint storage account.')
param enableRbac bool = false

@description('Object ID of the service principal (or managed identity) Abstract will authenticate as. Find it on the Enterprise Application blade - this is the SP object ID, NOT the app/client ID.')
param principalId string = ''

@description('Built-in Event Hubs data-plane role assigned on the namespace. Abstract docs specify Azure Event Hubs Data Receiver.')
@allowed(['Azure Event Hubs Data Sender', 'Azure Event Hubs Data Receiver', 'Azure Event Hubs Data Owner'])
param roleDefinitionName string = 'Azure Event Hubs Data Receiver'

@description('Built-in Storage data-plane role assigned on the checkpoint storage account. Abstract docs specify Storage Blob Data Contributor.')
@allowed(['Storage Blob Data Contributor', 'Storage Blob Data Owner'])
param storageRoleDefinitionName string = 'Storage Blob Data Contributor'

@description('Type of the principal being granted RBAC (setting this avoids PrincipalNotFound failures from directory replication delay on freshly created SPNs).')
@allowed(['ServicePrincipal', 'User', 'Group'])
param principalType string = 'ServicePrincipal'

// ---------------------------------------------------------------------------
// Checkpoint storage (required by the Abstract Event Hub consumer)
// ---------------------------------------------------------------------------
@description('Create the checkpoint Storage Account + blob container required by the Abstract integration. Set false only if you will point Abstract at an existing storage account you manage yourself.')
param createStorageAccount bool = true

@description('Checkpoint storage account name (3-24 lowercase letters/numbers, globally unique). Leave EMPTY to auto-generate a unique name (abs<hash>).')
@maxLength(24)
param storageAccountName string = ''

@description('Replication SKU for the checkpoint storage account. LRS is sufficient - checkpoints are rebuildable consumer state, not log data.')
@allowed(['Standard_LRS', 'Standard_ZRS', 'Standard_GRS', 'Standard_RAGRS'])
param storageSkuName string = 'Standard_LRS'

@description('Private blob container that stores Event Hub processing checkpoints. Enter this value in the "Storage Blob Container Name" field of the Abstract integration. Lowercase letters, numbers and dashes.')
@minLength(3)
@maxLength(63)
param blobContainerName string = 'abstract-checkpoints'

@description('Allow shared-key (connection string) access on the storage account. REQUIRED true for Connection String authentication in Abstract. Set false only for pure Service Principal deployments.')
param storageAllowSharedKeyAccess bool = true

@description('Mirror the Event Hub IP allowlist onto the storage account firewall. NOTE: the storage firewall rejects /31 and /32 prefixes - list single addresses as bare IPs.')
param storageApplyIpRules bool = true

@description('Also create a Private Endpoint (blob sub-resource) for the checkpoint storage account when private networking is used.')
param createStoragePrivateEndpoint bool = false

@description('Resource ID of the privatelink.blob.core.windows.net Private DNS zone (recommended with the storage Private Endpoint).')
param storageBlobPrivateDnsZoneId string = ''

// ---------------------------------------------------------------------------
// Networking + security
// ---------------------------------------------------------------------------
@description('Create a Private Endpoint for the Event Hubs namespace (Standard/Premium only).')
param enablePrivateEndpoint bool = false

@description('Resource ID of the subnet that will host the Private Endpoint NIC(s).')
param subnetId string = ''

@description('Resource ID of the privatelink.servicebus.windows.net Private DNS zone (recommended with the namespace Private Endpoint).')
param privateDnsZoneId string = ''

@description('Public IP ranges (CIDR) allowed through the namespace firewall - e.g. Abstract egress IPs plus your admin ranges. A non-empty list flips the firewall default action to Deny (unless Safe Mode is on). Empty entries are filtered out automatically.')
param allowedIpRanges array = []

@description('Allow trusted Microsoft services (Azure Monitor diagnostic settings, Defender streaming, ...) through the firewall. REQUIRED when the firewall is in Deny mode and Azure services stream logs into these hubs.')
param allowAzureServices bool = true

@description('Disable ALL public network access on the namespace (Private Endpoint only). Only honored when safeMode = false.')
param disablePublicNetwork bool = false

// ---------------------------------------------------------------------------
// Safe Mode
// ---------------------------------------------------------------------------
@description('''
Safe Mode guardrails for external SaaS ingestion (Abstract):
  true  -> public network access stays ON for BOTH the namespace and the
           checkpoint storage account, the IP allowlist is ignored, and the
           firewall default action stays Allow. Private Endpoints may still be
           created (hybrid connectivity), but they can never lock Abstract out.
  false -> disablePublicNetwork / allowedIpRanges are honored exactly as set.
Ship customers safeMode=true for onboarding; flip to false in a hardening phase
once Abstract egress IPs are in the allowlist or private connectivity is up.
''')
param safeMode bool = true

// ---------------------------------------------------------------------------
// Diagnostics (health of the pipeline itself)
// ---------------------------------------------------------------------------
@description('Enable diagnostic settings on the namespace so you can monitor the health of the log pipeline itself.')
param enableDiagnostics bool = false

@description('Resource ID of the Log Analytics workspace for namespace diagnostics.')
param logAnalyticsWorkspaceId string = ''

@description('Optional storage account resource ID for diagnostics archive (this is for namespace diagnostics - NOT the checkpoint storage account).')
param storageAccountId string = ''

// ---------------------------------------------------------------------------
// Derived values
// ---------------------------------------------------------------------------
var isStandard = sku == 'Standard'
var isBasic = sku == 'Basic'

var cleanedSources = filter(map(hubSources, s => trim(string(s))), s => !empty(s))

var generatedHubs = [for src in cleanedSources: {
  name: toLower('${hubPrefix}-${environment}-${src}')
  partitionCount: defaultPartitionCount
  retentionDays: isBasic ? 1 : defaultRetentionDays
}]
var effectiveHubs = autoHubNaming ? generatedHubs : eventHubs

// Drop empty/whitespace entries (a CSV-driven portal UI can produce [''])
var cleanedIpRanges = filter(allowedIpRanges, ip => !empty(trim(string(ip))))

// Safe Mode overrides: public stays reachable, allowlist is neutralized
var effectivePublicAccess = safeMode ? 'Enabled' : (disablePublicNetwork ? 'Disabled' : 'Enabled')
var effectiveIpRules = safeMode ? [] : cleanedIpRanges
var lockedDown = !safeMode && (length(effectiveIpRules) > 0 || disablePublicNetwork)
var networkDefaultAction = lockedDown ? 'Deny' : 'Allow'

// Checkpoint storage derived values
var storageNameEffective = empty(storageAccountName) ? take(toLower('abs${uniqueString(resourceGroup().id, namespaceName)}'), 24) : storageAccountName
var storageLockedDown = !safeMode && storageApplyIpRules && length(effectiveIpRules) > 0
var storagePublicAccess = safeMode ? 'Enabled' : (disablePublicNetwork && createStoragePrivateEndpoint ? 'Disabled' : 'Enabled')

// Built-in role definition IDs (data plane).
// NB: 2b629674-... is EVENT HUBS Data Sender; 69a216fc-... (seen in some
// generated templates) is actually *Service Bus* Data Sender - wrong service.
var roleMap = {
  'Azure Event Hubs Data Sender': '2b629674-e913-4c01-ae53-ef4638d8f975'
  'Azure Event Hubs Data Receiver': 'a638d3c7-ab3a-418d-83e6-5f17a39d4fde'
  'Azure Event Hubs Data Owner': 'f526a384-b230-433a-b45c-95f59c4a2dec'
}
var storageRoleMap = {
  'Storage Blob Data Contributor': 'ba92f5b4-2d11-453d-a403-e96b0029c9fe'
  'Storage Blob Data Owner': 'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
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

// ---------------------------------------------------------------------------
// Firewall / network rule set (child resource - NOT a namespace property).
// Skipped on Basic, which does not support IP filtering.
// ---------------------------------------------------------------------------
resource networkRules 'Microsoft.EventHub/namespaces/networkRuleSets@2024-01-01' = if (!isBasic) {
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
// Event hubs
// ---------------------------------------------------------------------------
resource hubs 'Microsoft.EventHub/namespaces/eventhubs@2024-01-01' = [for hub in effectiveHubs: {
  parent: ehNamespace
  name: hub.name
  properties: {
    partitionCount: hub.partitionCount
    messageRetentionInDays: hub.retentionDays
  }
}]

// Consumer group per hub for Abstract (Basic SKU only supports $Default)
resource consumerGroups 'Microsoft.EventHub/namespaces/eventhubs/consumergroups@2024-01-01' = [for (hub, i) in effectiveHubs: if (!isBasic) {
  parent: hubs[i]
  name: consumerGroupName
  properties: {}
}]

// ---------------------------------------------------------------------------
// SAS authorization rules (Connection String auth)
// ---------------------------------------------------------------------------
resource namespaceAuth 'Microsoft.EventHub/namespaces/authorizationRules@2024-01-01' = if (enableSas) {
  parent: ehNamespace
  name: sasRuleName
  properties: {
    rights: sasRights
  }
}

resource hubAuth 'Microsoft.EventHub/namespaces/eventhubs/authorizationRules@2024-01-01' = [for (hub, i) in effectiveHubs: if (enableSas && perHubSasRules) {
  parent: hubs[i]
  name: sasRuleName
  properties: {
    rights: sasRights
  }
}]

// ---------------------------------------------------------------------------
// Checkpoint Storage Account + private blob container
// Required by the Abstract consumer for checkpointing / lease management.
// ---------------------------------------------------------------------------
resource checkpointStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = if (createStorageAccount) {
  name: storageNameEffective
  location: location
  tags: tags
  kind: 'StorageV2'
  sku: {
    name: storageSkuName
  }
  properties: {
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    allowSharedKeyAccess: storageAllowSharedKeyAccess
    accessTier: 'Hot'
    publicNetworkAccess: storagePublicAccess
    networkAcls: {
      defaultAction: storageLockedDown ? 'Deny' : 'Allow'
      bypass: 'AzureServices'
      ipRules: [for ip in (storageLockedDown ? effectiveIpRules : []): {
        value: ip
        action: 'Allow'
      }]
      virtualNetworkRules: []
    }
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = if (createStorageAccount) {
  parent: checkpointStorage
  name: 'default'
}

resource checkpointContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (createStorageAccount) {
  parent: blobService
  name: blobContainerName
  properties: {
    publicAccess: 'None'
  }
}

// ---------------------------------------------------------------------------
// RBAC role assignments (Service Principal auth)
//   - Event Hubs Data Receiver  on the namespace      (read events)
//   - Storage Blob Data Contributor on checkpoint SA  (write checkpoints)
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

resource storageRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableRbac && !empty(principalId) && createStorageAccount) {
  name: guid(checkpointStorage.id, principalId, storageRoleMap[storageRoleDefinitionName])
  scope: checkpointStorage
  properties: {
    principalId: principalId
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', storageRoleMap[storageRoleDefinitionName])
    principalType: principalType
  }
}

// ---------------------------------------------------------------------------
// Private Endpoints + Private DNS zone groups
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

resource storagePrivateEndpoint 'Microsoft.Network/privateEndpoints@2023-11-01' = if (createStorageAccount && createStoragePrivateEndpoint && !empty(subnetId)) {
  name: '${storageNameEffective}-blob-pe'
  location: location
  tags: tags
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: 'blob-connection'
        properties: {
          privateLinkServiceId: checkpointStorage.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

resource storagePrivateDnsZoneGroup 'Microsoft.Network/privateEndpoints/privateDnsZoneGroups@2023-11-01' = if (createStorageAccount && createStoragePrivateEndpoint && !empty(subnetId) && !empty(storageBlobPrivateDnsZoneId)) {
  parent: storagePrivateEndpoint
  name: 'default'
  properties: {
    privateDnsZoneConfigs: [
      {
        name: 'blob-dns'
        properties: {
          privateDnsZoneId: storageBlobPrivateDnsZoneId
        }
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Diagnostic settings (pipeline health)
// ---------------------------------------------------------------------------
resource diagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (enableDiagnostics && (!empty(logAnalyticsWorkspaceId) || !empty(storageAccountId))) {
  name: '${namespaceName}-diagnostics'
  scope: ehNamespace
  properties: {
    workspaceId: empty(logAnalyticsWorkspaceId) ? null : logAnalyticsWorkspaceId
    storageAccountId: empty(storageAccountId) ? null : storageAccountId
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
// Outputs (intentionally NO keys / connection strings / secrets - deployment
// outputs are readable in deployment history by anyone with reader access.
// Fetch secrets post-deploy with the companion script, the portal, or CLI.)
// ---------------------------------------------------------------------------
output namespaceName string = ehNamespace.name
output namespaceId string = ehNamespace.id
output namespaceFqdn string = '${ehNamespace.name}.servicebus.windows.net'
output eventHubNames array = [for hub in effectiveHubs: hub.name]
output consumerGroup string = isBasic ? '$Default' : consumerGroupName
output sasRuleName string = enableSas ? sasRuleName : '(local auth disabled - use RBAC)'
output storageAccountName string = createStorageAccount ? storageNameEffective : '(not created)'
output storageAccountUrl string = createStorageAccount ? checkpointStorage.properties.primaryEndpoints.blob : '(not created)'
output blobContainerName string = createStorageAccount ? blobContainerName : '(not created)'
output publicAccess string = effectivePublicAccess
output firewallDefaultAction string = networkDefaultAction
output safeModeEnabled bool = safeMode
output privateEndpointEnabled bool = enablePrivateEndpoint

// Field-for-field answers for the Abstract integration modal
// (docs.abstract.security -> Azure Event Hub -> Event Hub Connection Details)
output abstractOnboarding object = {
  authenticationMethods: {
    connectionString: enableSas
    servicePrincipal: enableRbac
  }
  eventHubName: '(one integration per hub) ${join(map(effectiveHubs, h => string(h.name)), ', ')}'
  eventHubConsumerGroup: isBasic ? '$Default' : consumerGroupName
  storageBlobContainerName: createStorageAccount ? blobContainerName : '(bring your own)'
  eventHubNamespaceFqdn: '${ehNamespace.name}.servicebus.windows.net'
  storageAccountUrl: createStorageAccount ? checkpointStorage.properties.primaryEndpoints.blob : '(bring your own)'
  eventHubConnectionString: enableSas ? 'Portal: Event Hubs Namespace > Shared access policies > ${sasRuleName} > Connection string-primary key (or run the companion script with -Action Credentials)' : '(SAS disabled)'
  storageAccountConnectionString: createStorageAccount && storageAllowSharedKeyAccess ? 'Portal: Storage Account > Security + networking > Access keys > Connection string (or run the companion script with -Action Credentials)' : '(shared key access disabled)'
  docs: 'https://docs.abstract.security -> Integrations -> Azure Event Hub'
}
