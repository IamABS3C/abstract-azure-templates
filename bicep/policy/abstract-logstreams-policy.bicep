// =============================================================================
//  Abstract Security - Azure log streams at scale (Azure Policy governance pack)
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : MANAGEMENT GROUP
//
//  Answers "do we have to configure diagnostic settings on every subscription?"
//  with: no. Assign this once at a management group and every subscription in
//  that management group - today's and every one added later - is onboarded to
//  the Abstract Event Hub automatically, and drifts back into compliance if
//  someone removes a setting.
//
//  What it assigns
//  ---------------
//   1. Activity Log -> Event Hub                 CUSTOM DeployIfNotExists policy
//        Defined inline below. There is NO Microsoft built-in for Activity Log
//        to Event Hub (verified 2026-08-03 against the live built-in catalogue -
//        only the Log Analytics variant, 2465583e-..., exists). This definition
//        is modelled on that built-in, with the Event Hub destination swapped in.
//   2. Resource logs -> Event Hub                BUILT-IN initiative, per region
//        allLogs : 85175a36-2f12-419a-96b4-18d5b0096531
//        audit   : 1020d527-2764-4230-92cc-7035e4fcf8a7
//   3. Azure SQL auditing -> Event Hub           BUILT-IN 9a04cb4d-..., per region
//        SQL auditing is a separate feature from diagnostic settings, so the
//        resource-log initiative does NOT cover it.
//   4. Defender for Cloud alerts -> Event Hub    BUILT-IN cdfcce10-... (optional)
//        Continuous export; also a separate mechanism from diagnostic settings.
//
//  THE REGION RULE (the single most important design constraint)
//  ------------------------------------------------------------
//  Azure Monitor rejects a diagnostic setting whose Event Hub is in a different
//  region from the monitored resource. Verified empirically 2026-08-03:
//    BadRequest: "Resources should be in the same region. Resource '<eastus LAW>'
//    is in region 'eastus' and resource '<centralus EH namespace>' is in region
//    'centralus'."
//  Consequence: you need ONE Event Hubs namespace per region that holds regional
//  resources, and ONE assignment of the resource-log initiative per region. That
//  is why `regions` is an array and why each entry carries its own auth rule.
//  Activity Log is subscription-scope and NOT regional, so a single hub serves
//  every subscription regardless of region.
//
//  Deploy
//  ------
//    az deployment mg create \
//      --management-group-id <mg-id> --location eastus \
//      --template-file templates/policy/abstract-logstreams-policy.bicep \
//      --parameters @parameters/logstreams-policy.parameters.json
//
//  Hub names must match what the source stack actually created. main.bicep
//  auto-names hubs <hubPrefix>-<environment>-<source>, so the defaults here are
//  abs-prod-activity and abs-prod-resource - add 'resource' to main.bicep's
//  hubSources (default is activity/entra/defender) or the resource-log hub will
//  not exist and every diagnostic setting the policy deploys will fail.
//
//  Then run scripts/Deploy-AbstractLogStreams.sh -a Remediate to bring
//  EXISTING resources into compliance - DeployIfNotExists only fires on create
//  or update until a remediation task backfills the estate.
// =============================================================================

targetScope = 'managementGroup'

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Region the policy assignments\' managed identities are created in. Unrelated to where logs are collected - any region you operate in is fine.')
param assignmentLocation string = 'eastus'

@description('Prefix for every policy assignment name created here. Capped at 6: management-group policy assignment names have a 24-character limit (verified in the Azure resource naming rules), and the longest name built here is <prefix>-r-<13-char hash> = 22.')
@minLength(2)
@maxLength(6)
param namePrefix string = 'abs'

@description('Policy effect. Use AuditIfNotExists for a dry run that reports what WOULD be onboarded without changing anything, then switch to DeployIfNotExists.')
@allowed(['DeployIfNotExists', 'AuditIfNotExists', 'Disabled'])
param effect string = 'DeployIfNotExists'

@description('Assignments are created but not enforced when DoNotEnforce - use it to preview compliance before letting the policy deploy anything.')
@allowed(['Default', 'DoNotEnforce'])
param enforcementMode string = 'Default'

// ---------------------------------------------------------------------------
// Stream 1 - Activity Log (subscription scope, not regional)
// ---------------------------------------------------------------------------
@description('Onboard every subscription\'s Activity Log to the Abstract Event Hub.')
param enableActivityLog bool = true

@description('Resource ID of an Event Hubs namespace authorization rule with Send rights, used for the Activity Log stream. Use the abstractDiagnosticsAuthRuleId output of main.bicep. Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces/{ns}/authorizationrules/{rule}')
param activityLogAuthorizationRuleId string = ''

@description('Event Hub that receives the Activity Log stream. It must already exist - Azure Policy never creates hubs.')
param activityLogEventHubName string = 'abs-prod-activity'

@description('Activity Log categories to export. Default is all eight.')
param activityLogCategories array = [
  'Administrative'
  'Security'
  'ServiceHealth'
  'Alert'
  'Recommendation'
  'Policy'
  'Autoscale'
  'ResourceHealth'
]

// ---------------------------------------------------------------------------
// Stream 2 - resource logs (regional - one assignment per region)
// ---------------------------------------------------------------------------
@description('Onboard resource logs (Key Vault, NSG, Front Door, AKS, Cosmos DB, ~140 resource types) to the Abstract Event Hub.')
param enableResourceLogs bool = true

@description('Which category group to collect. allLogs is everything the resource emits; audit is the control-plane/data-access subset. allLogs is the Abstract default - filtering happens in the pipeline, not at the source.')
@allowed(['allLogs', 'audit'])
param categoryGroup string = 'allLogs'

@description('''
One entry per region that holds regional resources. Azure Monitor REQUIRES the
Event Hub to be in the same region as the monitored resource, so each region
needs its own namespace and its own assignment.
  [ { location: 'eastus', authorizationRuleId: '/subscriptions/.../authorizationrules/abstract-diagnostics-send', eventHubName: 'abs-prod-resource' } ]
''')
param regions array = []

@description('Restrict the resource-log initiative to specific resource types. Empty = every supported type (recommended).')
param resourceTypeList array = []

@description('Name given to the diagnostic settings the policy creates. Pick something recognisable so operators know not to delete it by hand.')
param diagnosticSettingName string = 'abstract-logstream'

// ---------------------------------------------------------------------------
// Stream 3 - Azure SQL auditing (regional, separate feature)
// ---------------------------------------------------------------------------
@description('Also enable Azure SQL server auditing to the Event Hub. SQL auditing is NOT a diagnostic setting, so the resource-log initiative does not cover it.')
param enableSqlAuditing bool = false

// ---------------------------------------------------------------------------
// Stream 4 - Microsoft Defender for Cloud continuous export
// ---------------------------------------------------------------------------
@description('Also export Defender for Cloud alerts, recommendations and secure-score data to the Event Hub. Another separate mechanism (continuous export), not a diagnostic setting.')
param enableDefenderExport bool = false

@description('Resource group the Defender continuous-export resource is created in, inside every in-scope subscription.')
param defenderExportResourceGroup string = 'rg-abstract-defender-export'

@description('HUB-level Event Hubs authorization rule for the Defender export. Unlike the other policies here this one wants a rule scoped to the hub, not the namespace: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.EventHub/namespaces/{ns}/eventhubs/{hub}/authorizationRules/{rule}. Set perHubSasRules=true in main.bicep to have one created.')
param defenderEventHubAuthorizationRuleId string = ''

@description('Defender for Cloud data types to export.')
param defenderExportedDataTypes array = [
  'Alerts'
]

@description('Alert severities exported from Defender for Cloud.')
param defenderAlertSeverities array = [
  'High'
  'Medium'
  'Low'
]

// ---------------------------------------------------------------------------
// Built-in identifiers (verified against the live built-in catalogue 2026-08-03)
// ---------------------------------------------------------------------------
var builtIn = {
  resourceLogsAllLogs: tenantResourceId('Microsoft.Authorization/policySetDefinitions', '85175a36-2f12-419a-96b4-18d5b0096531')
  resourceLogsAudit: tenantResourceId('Microsoft.Authorization/policySetDefinitions', '1020d527-2764-4230-92cc-7035e4fcf8a7')
  sqlAuditingToEventHub: tenantResourceId('Microsoft.Authorization/policyDefinitions', '9a04cb4d-8b47-4533-8e8e-b7a3c7742a0c')
  defenderExportToEventHub: tenantResourceId('Microsoft.Authorization/policyDefinitions', 'cdfcce10-4578-4ecd-9703-530938e4abcb')
}

var roles = {
  monitoringContributor: '749f88d5-cbae-40b8-bcfc-e573ddc772fa'
  logAnalyticsContributor: '92aaf0da-9dab-42b6-94a3-d43ce8d16293'
  eventHubsDataOwner: 'f526a384-b230-433a-b45c-95f59c4a2dec'
  sqlSecurityManager: '056cd41c-7e88-42e1-933e-88ba6a50c9c3'
  contributor: 'b24988ac-6180-42a0-ab88-20f7382dd24c'
}

var resourceLogsInitiativeId = categoryGroup == 'allLogs' ? builtIn.resourceLogsAllLogs : builtIn.resourceLogsAudit

// ---------------------------------------------------------------------------
// CUSTOM policy definition - Activity Log -> Event Hub
// Modelled on built-in 2465583e-4e78-4c15-b6be-a36cbc7c8b0f (the Log Analytics
// equivalent), with the Event Hub destination substituted. Subscription-scope
// DeployIfNotExists: it evaluates every subscription in the management group.
// ---------------------------------------------------------------------------
resource activityLogPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = if (enableActivityLog) {
  name: '${namePrefix}-activitylog-to-eventhub'
  properties: {
    displayName: 'Abstract Security - stream Azure Activity logs to the Abstract Event Hub'
    description: 'Deploys a subscription-scope diagnostic setting that streams the Azure Activity Log to an Abstract Security Event Hub. Microsoft ships no built-in for the Event Hub destination (only Log Analytics), so this definition fills the gap.'
    policyType: 'Custom'
    mode: 'All'
    metadata: {
      category: 'Monitoring'
      version: '1.0.0'
      vendor: 'Abstract Security'
    }
    parameters: {
      effect: {
        type: 'String'
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'DeployIfNotExists'
        metadata: {
          displayName: 'Effect'
          description: 'Enable or disable the execution of the policy.'
        }
      }
      eventHubAuthorizationRuleId: {
        type: 'String'
        metadata: {
          displayName: 'Event Hub Authorization Rule Id'
          description: 'Namespace-level authorization rule with Send rights. If the namespace sits outside the assignment scope you must grant Azure Event Hubs Data Owner to the assignment identity manually.'
          strongType: 'Microsoft.EventHub/Namespaces/AuthorizationRules'
          assignPermissions: true
        }
      }
      eventHubName: {
        type: 'String'
        metadata: {
          displayName: 'Event Hub Name'
          description: 'The Event Hub that receives the Activity Log stream. It must already exist.'
        }
      }
      logCategories: {
        type: 'Array'
        defaultValue: [
          'Administrative'
          'Security'
          'ServiceHealth'
          'Alert'
          'Recommendation'
          'Policy'
          'Autoscale'
          'ResourceHealth'
        ]
        metadata: {
          displayName: 'Activity Log categories'
          description: 'Activity Log categories to stream.'
        }
      }
      diagnosticSettingName: {
        type: 'String'
        defaultValue: 'abstract-activity-logs'
        metadata: {
          displayName: 'Diagnostic Setting Name'
          description: 'Name of the subscription diagnostic setting. Max 5 settings per subscription.'
        }
      }
    }
    policyRule: {
      if: {
        field: 'type'
        equals: 'Microsoft.Resources/subscriptions'
      }
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          type: 'Microsoft.Insights/diagnosticSettings'
          deploymentScope: 'Subscription'
          existenceScope: 'Subscription'
          existenceCondition: {
            allOf: [
              {
                field: 'Microsoft.Insights/diagnosticSettings/eventHubAuthorizationRuleId'
                equals: '[parameters(\'eventHubAuthorizationRuleId\')]'
              }
              {
                field: 'Microsoft.Insights/diagnosticSettings/eventHubName'
                equals: '[parameters(\'eventHubName\')]'
              }
            ]
          }
          roleDefinitionIds: [
            tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringContributor)
            tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.eventHubsDataOwner)
          ]
          deployment: {
            location: assignmentLocation
            properties: {
              mode: 'incremental'
              parameters: {
                eventHubAuthorizationRuleId: {
                  value: '[parameters(\'eventHubAuthorizationRuleId\')]'
                }
                eventHubName: {
                  value: '[parameters(\'eventHubName\')]'
                }
                logCategories: {
                  value: '[parameters(\'logCategories\')]'
                }
                diagnosticSettingName: {
                  value: '[parameters(\'diagnosticSettingName\')]'
                }
              }
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  eventHubAuthorizationRuleId: {
                    type: 'string'
                  }
                  eventHubName: {
                    type: 'string'
                  }
                  logCategories: {
                    type: 'array'
                  }
                  diagnosticSettingName: {
                    type: 'string'
                  }
                }
                resources: [
                  {
                    type: 'Microsoft.Insights/diagnosticSettings'
                    apiVersion: '2021-05-01-preview'
                    name: '[parameters(\'diagnosticSettingName\')]'
                    location: 'Global'
                    properties: {
                      // Property-level copy builds the `logs` array from the category list.
                      // The copy block is declared as a SIBLING of the property it produces,
                      // inside `properties` - nesting it under `logs:` fails at deploy time
                      // with "The template function 'copyIndex' is not expected at this
                      // location" (verified against a live subscription 2026-08-03).
                      copy: [
                        {
                          name: 'logs'
                          count: '[length(parameters(\'logCategories\'))]'
                          input: {
                            category: '[parameters(\'logCategories\')[copyIndex(\'logs\')]]'
                            enabled: true
                          }
                        }
                      ]
                      eventHubAuthorizationRuleId: '[parameters(\'eventHubAuthorizationRuleId\')]'
                      eventHubName: '[parameters(\'eventHubName\')]'
                    }
                  }
                ]
                outputs: {
                  policy: {
                    type: 'string'
                    value: '[concat(\'Activity Log of this subscription streams to Event Hub \', parameters(\'eventHubName\'), \' via \', parameters(\'eventHubAuthorizationRuleId\'))]'
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Assignment 1 - Activity Log
// ---------------------------------------------------------------------------
resource activityLogAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (enableActivityLog) {
  name: '${namePrefix}-activitylog'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Abstract Security - Activity Log to Event Hub'
    description: 'Streams every in-scope subscription\'s Activity Log to the Abstract Event Hub, including subscriptions added to this management group later.'
    policyDefinitionId: activityLogPolicy.id
    enforcementMode: enforcementMode
    parameters: {
      effect: {
        value: effect
      }
      eventHubAuthorizationRuleId: {
        value: activityLogAuthorizationRuleId
      }
      eventHubName: {
        value: activityLogEventHubName
      }
      logCategories: {
        value: activityLogCategories
      }
    }
  }
}

resource activityLogMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableActivityLog) {
  name: guid(managementGroup().id, '${namePrefix}-activitylog', roles.monitoringContributor)
  properties: {
    principalId: activityLogAssignment!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringContributor)
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Assignment 2 - resource logs, one per region (the region rule, in code)
// ---------------------------------------------------------------------------
resource resourceLogAssignments 'Microsoft.Authorization/policyAssignments@2024-04-01' = [for (region, i) in regions: if (enableResourceLogs) {
  name: '${namePrefix}-r-${uniqueString(string(region.location))}'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Abstract Security - resource logs (${region.location}) to Event Hub'
    description: 'Deploys ${categoryGroup} diagnostic settings on every supported resource in ${region.location} to the Abstract Event Hub in the same region. Azure Monitor requires the hub and the monitored resource to share a region.'
    policyDefinitionId: resourceLogsInitiativeId
    enforcementMode: enforcementMode
    parameters: union(
      {
        effect: {
          value: effect
        }
        eventHubAuthorizationRuleId: {
          value: region.authorizationRuleId
        }
        eventHubName: {
          value: region.eventHubName
        }
        resourceLocation: {
          value: region.location
        }
        diagnosticSettingName: {
          value: diagnosticSettingName
        }
      },
      empty(resourceTypeList) ? {} : {
        resourceTypeList: {
          value: resourceTypeList
        }
      }
    )
  }
}]

resource resourceLogMonitoringRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (region, i) in regions: if (enableResourceLogs) {
  name: guid(managementGroup().id, 'res', string(region.location), roles.monitoringContributor)
  properties: {
    principalId: resourceLogAssignments[i]!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.monitoringContributor)
    principalType: 'ServicePrincipal'
  }
}]

resource resourceLogLawRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (region, i) in regions: if (enableResourceLogs) {
  name: guid(managementGroup().id, 'res', string(region.location), roles.logAnalyticsContributor)
  properties: {
    principalId: resourceLogAssignments[i]!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.logAnalyticsContributor)
    principalType: 'ServicePrincipal'
  }
}]

// ---------------------------------------------------------------------------
// Assignment 3 - Azure SQL auditing, one per region
// ---------------------------------------------------------------------------
resource sqlAuditAssignments 'Microsoft.Authorization/policyAssignments@2024-04-01' = [for (region, i) in regions: if (enableSqlAuditing) {
  name: '${namePrefix}-s-${uniqueString(string(region.location))}'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Abstract Security - SQL auditing (${region.location}) to Event Hub'
    description: 'Azure SQL auditing is a separate feature from diagnostic settings, so the resource-log initiative does not cover it. This closes that gap.'
    policyDefinitionId: builtIn.sqlAuditingToEventHub
    enforcementMode: enforcementMode
    parameters: {
      effect: {
        value: effect
      }
      eventHubRuleId: {
        value: region.authorizationRuleId
      }
      eventHubName: {
        value: region.eventHubName
      }
      eventHubLocation: {
        value: region.location
      }
    }
  }
}]

resource sqlAuditRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (region, i) in regions: if (enableSqlAuditing) {
  name: guid(managementGroup().id, 'sql', string(region.location), roles.sqlSecurityManager)
  properties: {
    principalId: sqlAuditAssignments[i]!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.sqlSecurityManager)
    principalType: 'ServicePrincipal'
  }
}]

resource sqlAuditLawRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = [for (region, i) in regions: if (enableSqlAuditing) {
  name: guid(managementGroup().id, 'sql', string(region.location), roles.logAnalyticsContributor)
  properties: {
    principalId: sqlAuditAssignments[i]!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.logAnalyticsContributor)
    principalType: 'ServicePrincipal'
  }
}]

// ---------------------------------------------------------------------------
// Assignment 4 - Defender for Cloud continuous export
// ---------------------------------------------------------------------------
resource defenderExportAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = if (enableDefenderExport) {
  name: '${namePrefix}-defender'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Abstract Security - Defender for Cloud export to Event Hub'
    description: 'Continuous export of Defender for Cloud alerts to the Abstract Event Hub, on every in-scope subscription.'
    policyDefinitionId: builtIn.defenderExportToEventHub
    enforcementMode: enforcementMode
    parameters: {
      resourceGroupName: {
        value: defenderExportResourceGroup
      }
      resourceGroupLocation: {
        value: assignmentLocation
      }
      createResourceGroup: {
        value: true
      }
      exportedDataTypes: {
        value: defenderExportedDataTypes
      }
      alertSeverities: {
        value: defenderAlertSeverities
      }
      // NOTE the shape difference: unlike every other policy here, this one takes a
      // HUB-level authorization rule resource ID as a single string
      // (/subscriptions/.../namespaces/{ns}/eventhubs/{hub}/authorizationRules/{rule}),
      // not a namespace-level rule. Set perHubSasRules=true in main.bicep to create it.
      eventHubDetails: {
        value: defenderEventHubAuthorizationRuleId
      }
    }
  }
}

resource defenderContributorRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (enableDefenderExport) {
  name: guid(managementGroup().id, '${namePrefix}-defender', roles.contributor)
  properties: {
    principalId: defenderExportAssignment!.identity!.principalId
    roleDefinitionId: tenantResourceId('Microsoft.Authorization/roleDefinitions', roles.contributor)
    principalType: 'ServicePrincipal'
  }
}

// ---------------------------------------------------------------------------
// Outputs
// The Event Hubs namespace usually lives OUTSIDE this management group's
// assignment scope, so the Event Hubs Data Owner grant cannot be made from here.
// Feed these principal IDs to scripts/Deploy-AbstractLogStreams.sh -Action Grant,
// which assigns Azure Event Hubs Data Owner on the namespace itself.
// ---------------------------------------------------------------------------
output managementGroupId string = managementGroup().id

output eventHubsDataOwnerRoleId string = roles.eventHubsDataOwner

@description('Activity Log assignment identity. Grant it Azure Event Hubs Data Owner on the namespace.')
output activityLogPrincipalId string = enableActivityLog ? activityLogAssignment!.identity!.principalId : ''

@description('Resource-log assignment identities, one per region, in the same order as the regions parameter.')
output resourceLogPrincipalIds array = [for (region, i) in regions: enableResourceLogs ? {
  region: region.location
  assignment: '${namePrefix}-r-${uniqueString(string(region.location))}'
  principalId: resourceLogAssignments[i]!.identity!.principalId
} : {
  region: region.location
  assignment: '(not assigned)'
  principalId: ''
}]

@description('SQL-auditing assignment identities, one per region, in the same order as the regions parameter.')
output sqlAuditPrincipalIds array = [for (region, i) in regions: enableSqlAuditing ? {
  region: region.location
  assignment: '${namePrefix}-s-${uniqueString(string(region.location))}'
  principalId: sqlAuditAssignments[i]!.identity!.principalId
} : {
  region: region.location
  assignment: '(not assigned)'
  principalId: ''
}]

output onboardingSummary object = {
  activityLog: enableActivityLog ? 'assigned - every subscription in ${managementGroup().name}, now and future' : 'not assigned'
  resourceLogs: enableResourceLogs ? '${categoryGroup} assigned for ${length(regions)} region(s)' : 'not assigned'
  sqlAuditing: enableSqlAuditing ? 'assigned for ${length(regions)} region(s)' : 'not assigned'
  defenderForCloud: enableDefenderExport ? 'assigned' : 'not assigned'
  nextStep: 'Grant Azure Event Hubs Data Owner to the principals above on the Event Hubs namespace, then run a remediation task to backfill EXISTING resources.'
  notCoveredByPolicy: 'Microsoft Entra ID, Defender XDR and Microsoft 365 are tenant-level streams - see templates/tenant/entra-diagnostics.bicep and the coverage matrix in docs/azure-log-streams.md'
}
