// =============================================================================
//  Abstract Security - per-subscription Entra app registration via Azure Policy
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : MANAGEMENT GROUP
//
//  PATH A of two. Read this header before deploying - the security trade-off is
//  the whole story, and the alternative (templates/automation/) is safer for most
//  customers.
//
//  ---------------------------------------------------------------------------
//  WHY THIS IS UNUSUAL
//  ---------------------------------------------------------------------------
//  Azure Policy cannot create Entra objects. A DeployIfNotExists policy deploys
//  "the full template deployment as it would be passed to the
//  Microsoft.Resources/deployments PUT API" - and Entra applications and service
//  principals are NOT ARM resources. They have no /subscriptions/... resource ID
//  and no resource provider, so policy can neither EVALUATE nor CREATE them.
//
//  The workaround: policy deploys a Microsoft.Resources/deploymentScripts
//  resource, which runs an az-CLI container AS A USER-ASSIGNED MANAGED IDENTITY
//  that already holds Graph permissions. The container calls Graph. So:
//
//    ARM cannot create an app registration.
//    ARM CAN deploy a container that calls Graph.
//    Policy CAN deploy that ARM.
//    => Policy can do it, INDIRECTLY, through a pre-consented identity.
//
//  ---------------------------------------------------------------------------
//  READ THIS BEFORE YOU DEPLOY - the four things that will bite
//  ---------------------------------------------------------------------------
//  1. THE BOOTSTRAP CANNOT BE AUTOMATED. The identity needs Graph
//     Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All, consented by a
//     Global Administrator or Privileged Role Administrator. Policy cannot grant
//     that to itself. One manual step per tenant, forever.
//
//  2. THAT IDENTITY IS A TENANT-WIDE PRIVILEGE-ESCALATION PRIMITIVE.
//     AppRoleAssignment.ReadWrite.All lets it grant ITSELF anything in the
//     directory. Wiring it to fire automatically on every new subscription is a
//     blast radius an identity team will push back on - correctly. Expect this
//     objection; it is the real one, not a technical one.
//
//  3. NO existenceCondition IS POSSIBLE ON THE APP ITSELF. Policy cannot see
//     whether the Entra app exists, so it gates on an ARM-visible PROXY: the
//     deploymentScript resource. Get the proxy wrong and the policy re-runs
//     forever, minting duplicate apps and churning secrets. Belt and braces: the
//     script itself is idempotent (reuse-by-display-name) and only creates a new
//     secret when none is valid.
//
//  4. MECHANICS. Each run creates a storage account + container instance IN THE
//     TARGET SUBSCRIPTION - Microsoft.ContainerInstance and Microsoft.Storage
//     must be registered there, and it costs a few cents per run. DINE supports
//     NESTED but NOT LINKED templates, so the whole script is inlined below.
//
//  ---------------------------------------------------------------------------
//  RECOMMENDED ALTERNATIVE
//  ---------------------------------------------------------------------------
//  templates/automation/abstract-appreg-automation.bicep - Event Grid on
//  subscription creation -> ONE central Logic App holding the single
//  Graph-permissioned identity. Same outcome; one identity to audit instead of
//  privileged containers spawning across the estate, no per-subscription ACI
//  cost, and a real audit trail. See docs/azure-app-registrations.md.
//
//  ---------------------------------------------------------------------------
//  Deploy
//  ---------------------------------------------------------------------------
//    az deployment mg create \
//      --management-group-id <mg-id> --location eastus \
//      --template-file templates/policy/abstract-appreg-policy.bicep \
//      --parameters managedIdentityResourceId=<uami-resource-id> \
//                   centralKeyVaultName=<kv-name> \
//                   centralKeyVaultResourceGroup=<kv-rg> \
//                   centralKeyVaultSubscriptionId=<kv-sub>
//
//  Then grant the assignment identity Contributor on the target subscriptions and
//  run a remediation task - see scripts/Deploy-AbstractAppReg.sh.
// =============================================================================

targetScope = 'managementGroup'

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------
@description('Region for the policy assignment managed identity and the deploymentScript container.')
param assignmentLocation string = 'eastus'

@description('Prefix for the policy assignment name. Capped at 6 - management-group policy assignment names are limited to 24 characters.')
@minLength(2)
@maxLength(6)
param namePrefix string = 'abs'

@description('Policy effect. AuditIfNotExists reports which subscriptions LACK an Abstract app without creating anything - always start here.')
@allowed(['DeployIfNotExists', 'AuditIfNotExists', 'Disabled'])
param effect string = 'AuditIfNotExists'

@description('DoNotEnforce creates the assignment without acting. Combined with AuditIfNotExists this is a completely inert dry run.')
@allowed(['Default', 'DoNotEnforce'])
param enforcementMode string = 'DoNotEnforce'

// ---------------------------------------------------------------------------
// The pre-consented identity - the crux of the whole design
// ---------------------------------------------------------------------------
@description('''
Resource ID of a user-assigned managed identity that ALREADY holds Microsoft Graph
Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All, consented by a
Global Administrator. Policy cannot create or consent this - see scripts/
Deploy-AbstractAppReg.sh -a Bootstrap for the one-time setup.

This identity can grant itself any directory permission. Treat it as tier-0.

Find it with: az identity list --query [].id -o tsv
''')
param managedIdentityResourceId string

@description('Client ID of that same identity. The script needs it for `az login --identity --username <clientId>`; the resource ID alone is not enough. Find it with: az identity list --query [].clientId -o tsv')
param managedIdentityClientId string

// ---------------------------------------------------------------------------
// Where secrets land - always central, never in the target subscription
// ---------------------------------------------------------------------------
@description('Name of a CENTRAL Key Vault that receives every generated client secret. Deliberately central: per-subscription vaults would scatter tier-0 secrets across the estate. Find it with: az keyvault list --query [].name -o tsv')
param centralKeyVaultName string

@description('Resource group of the central Key Vault. Find it with: az group list --query [].name -o tsv')
param centralKeyVaultResourceGroup string

@description('Subscription ID of the central Key Vault. Find it with: az account list --query [].id -o tsv')
param centralKeyVaultSubscriptionId string

// ---------------------------------------------------------------------------
// App shape
// ---------------------------------------------------------------------------
@description('App display-name pattern. {sub} is replaced with the target subscription ID, giving one app per subscription. Also the idempotency key - the script reuses an app of the same name rather than creating a second one.')
param appNamePattern string = 'Abstract-{sub}'

@description('''
Microsoft Graph APPLICATION permissions granted to each created app.

VERIFIED against the live Graph service principal on 2026-08-03. Note that
"Security.Read.All" is NOT in this list and must never be added - it does not
exist as an application permission (nor as a delegated scope); the real coverage
is SecurityEvents.Read.All + SecurityAlert.Read.All + SecurityIncident.Read.All.
''')
param graphPermissions array = [
  'AuditLog.Read.All'
  'SecurityAlert.Read.All'
  'SecurityEvents.Read.All'
  'SecurityIncident.Read.All'
  'Directory.Read.All'
  'IdentityRiskEvent.Read.All'
  'IdentityRiskyUser.Read.All'
  'IdentityRiskyServicePrincipal.Read.All'
  'ThreatHunting.Read.All'
  'User.Read.All'
  'Group.Read.All'
  'Device.Read.All'
]

@description('Client-secret lifetime in months.')
@minValue(1)
@maxValue(24)
param secretMonths int = 12

@description('Azure RBAC roles granted to each created service principal ON ITS OWN SUBSCRIPTION. Default is Reader plus Azure Event Hubs Data Receiver. This - not the Graph permissions - is what makes the app per-subscription: Graph permissions are inherently tenant-wide.')
param subscriptionRoleDefinitionIds array = [
  'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader
  'a638d3c7-ab3a-418d-83e6-5f17a39d4fde' // Azure Event Hubs Data Receiver
]

@description('Resource group created in each target subscription to host the deploymentScript and its storage. Nothing sensitive lands here.')
param scriptResourceGroup string = 'rg-abstract-appreg'

@description('az CLI version for the deploymentScript container.')
param azCliVersion string = '2.60.0'

@description('Only act on subscriptions carrying this tag. STRONGLY recommended: it is the difference between "onboard what we chose" and "onboard everything the management group ever contains". Leave tagName empty to act on all in-scope subscriptions.')
param tagName string = 'abstract-onboard'

@description('Required tag value when tagName is set.')
param tagValue string = 'true'

// ---------------------------------------------------------------------------
// Derived
// ---------------------------------------------------------------------------
var scriptName = 'abstract-appreg'

// Policy is evaluated against the SUBSCRIPTION object. When a tag gate is
// configured we add it to the `if` block so untagged subscriptions are simply
// out of scope rather than non-compliant.
var subscriptionCondition = empty(tagName) ? {
  field: 'type'
  equals: 'Microsoft.Resources/subscriptions'
} : {
  allOf: [
    {
      field: 'type'
      equals: 'Microsoft.Resources/subscriptions'
    }
    {
      field: 'tags[\'${tagName}\']'
      equals: tagValue
    }
  ]
}

// ---------------------------------------------------------------------------
// The custom policy definition
// ---------------------------------------------------------------------------
resource appRegPolicy 'Microsoft.Authorization/policyDefinitions@2023-04-01' = {
  name: '${namePrefix}-appreg-per-subscription'
  properties: {
    displayName: 'Abstract Security - create a per-subscription Entra app registration for Graph collection'
    description: 'Deploys a deploymentScript that creates (or reuses) an Entra app registration + service principal per subscription, requests the Abstract Graph application permissions, grants admin consent, stores the client secret in a central Key Vault, and assigns Azure RBAC on the target subscription. Entra objects are not ARM resources, so Azure Policy reaches them only indirectly, through a pre-consented managed identity - review the security trade-off in the template header before assigning.'
    policyType: 'Custom'
    mode: 'All'
    metadata: {
      category: 'Security Center'
      version: '1.0.0'
      vendor: 'Abstract Security'
      securityNote: 'Requires a user-assigned managed identity holding Graph Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All. That identity can escalate its own directory privileges; treat it as tier-0 and prefer templates/automation/ where an identity team objects.'
    }
    parameters: {
      effect: {
        type: 'String'
        allowedValues: [
          'DeployIfNotExists'
          'AuditIfNotExists'
          'Disabled'
        ]
        defaultValue: 'AuditIfNotExists'
        metadata: {
          displayName: 'Effect'
          description: 'AuditIfNotExists reports which subscriptions lack an Abstract app without creating anything.'
        }
      }
      managedIdentityResourceId: {
        type: 'String'
        metadata: {
          displayName: 'Graph-permissioned managed identity (resource ID)'
          description: 'Must already hold Application.ReadWrite.All and AppRoleAssignment.ReadWrite.All with admin consent.'
          strongType: 'Microsoft.ManagedIdentity/userAssignedIdentities'
          assignPermissions: true
        }
      }
      managedIdentityClientId: {
        type: 'String'
        metadata: {
          displayName: 'Managed identity client ID'
          description: 'Client ID of the same identity, for az login --identity --username.'
        }
      }
      centralKeyVaultName: {
        type: 'String'
        metadata: {
          displayName: 'Central Key Vault name'
        }
      }
      centralKeyVaultResourceGroup: {
        type: 'String'
        metadata: {
          displayName: 'Central Key Vault resource group'
        }
      }
      centralKeyVaultSubscriptionId: {
        type: 'String'
        metadata: {
          displayName: 'Central Key Vault subscription ID'
        }
      }
      appNamePattern: {
        type: 'String'
        defaultValue: 'Abstract-{sub}'
        metadata: {
          displayName: 'App display-name pattern'
          description: '{sub} is replaced with the subscription ID. Also the idempotency key.'
        }
      }
      graphPermissions: {
        type: 'Array'
        metadata: {
          displayName: 'Graph application permissions'
        }
      }
      secretMonths: {
        type: 'Integer'
        defaultValue: 12
        metadata: {
          displayName: 'Client secret lifetime (months)'
        }
      }
      subscriptionRoleDefinitionIds: {
        type: 'Array'
        metadata: {
          displayName: 'Azure RBAC role IDs granted on the target subscription'
        }
      }
      scriptResourceGroup: {
        type: 'String'
        defaultValue: 'rg-abstract-appreg'
        metadata: {
          displayName: 'Resource group for the deploymentScript'
        }
      }
      azCliVersion: {
        type: 'String'
        defaultValue: '2.60.0'
        metadata: {
          displayName: 'az CLI version'
        }
      }
      scriptLocation: {
        type: 'String'
        metadata: {
          displayName: 'Region for the script container'
          strongType: 'location'
        }
      }
    }
    policyRule: {
      if: subscriptionCondition
      then: {
        effect: '[parameters(\'effect\')]'
        details: {
          // The ARM-visible PROXY for "does this subscription have an Abstract app".
          // Policy cannot see the Entra app, so it checks for a successfully
          // completed deploymentScript of a known name instead.
          type: 'Microsoft.Resources/deploymentScripts'
          name: scriptName
          resourceGroupName: '[parameters(\'scriptResourceGroup\')]'
          existenceScope: 'ResourceGroup'
          evaluationDelay: 'AfterProvisioningSuccess'
          existenceCondition: {
            field: 'Microsoft.Resources/deploymentScripts/provisioningState'
            equals: 'Succeeded'
          }
          roleDefinitionIds: [
            // Owner: the script's own deployment assigns RBAC on the subscription,
            // which Contributor cannot do. Narrow this to
            // Contributor + User Access Administrator if your governance requires it.
            tenantResourceId('Microsoft.Authorization/roleDefinitions', '8e3af657-a8ff-443c-a75c-2fe8c4bcb635')
          ]
          deploymentScope: 'Subscription'
          deployment: {
            location: assignmentLocation
            properties: {
              mode: 'incremental'
              parameters: {
                subscriptionId: {
                  value: '[field(\'name\')]'
                }
                managedIdentityResourceId: {
                  value: '[parameters(\'managedIdentityResourceId\')]'
                }
                managedIdentityClientId: {
                  value: '[parameters(\'managedIdentityClientId\')]'
                }
                centralKeyVaultName: {
                  value: '[parameters(\'centralKeyVaultName\')]'
                }
                appNamePattern: {
                  value: '[parameters(\'appNamePattern\')]'
                }
                graphPermissions: {
                  value: '[parameters(\'graphPermissions\')]'
                }
                secretMonths: {
                  value: '[parameters(\'secretMonths\')]'
                }
                subscriptionRoleDefinitionIds: {
                  value: '[parameters(\'subscriptionRoleDefinitionIds\')]'
                }
                scriptResourceGroup: {
                  value: '[parameters(\'scriptResourceGroup\')]'
                }
                azCliVersion: {
                  value: '[parameters(\'azCliVersion\')]'
                }
                scriptLocation: {
                  value: '[parameters(\'scriptLocation\')]'
                }
              }
              template: {
                '$schema': 'https://schema.management.azure.com/schemas/2018-05-01/subscriptionDeploymentTemplate.json#'
                contentVersion: '1.0.0.0'
                parameters: {
                  subscriptionId: {
                    type: 'string'
                  }
                  managedIdentityResourceId: {
                    type: 'string'
                  }
                  managedIdentityClientId: {
                    type: 'string'
                  }
                  centralKeyVaultName: {
                    type: 'string'
                  }
                  appNamePattern: {
                    type: 'string'
                  }
                  graphPermissions: {
                    type: 'array'
                  }
                  secretMonths: {
                    type: 'int'
                  }
                  subscriptionRoleDefinitionIds: {
                    type: 'array'
                  }
                  scriptResourceGroup: {
                    type: 'string'
                  }
                  azCliVersion: {
                    type: 'string'
                  }
                  scriptLocation: {
                    type: 'string'
                  }
                }
                resources: [
                  // The resource group that hosts the script + its storage.
                  {
                    type: 'Microsoft.Resources/resourceGroups'
                    apiVersion: '2021-04-01'
                    name: '[parameters(\'scriptResourceGroup\')]'
                    location: '[parameters(\'scriptLocation\')]'
                  }
                  // Nested deployment - deploymentScripts is a resource-group-scope
                  // resource, so it cannot sit directly in a subscription-scope
                  // template. DINE supports NESTED templates but NOT LINKED ones,
                  // hence inline.
                  {
                    type: 'Microsoft.Resources/deployments'
                    apiVersion: '2021-04-01'
                    name: '[concat(\'abstract-appreg-\', uniqueString(parameters(\'subscriptionId\')))]'
                    resourceGroup: '[parameters(\'scriptResourceGroup\')]'
                    dependsOn: [
                      '[resourceId(\'Microsoft.Resources/resourceGroups\', parameters(\'scriptResourceGroup\'))]'
                    ]
                    properties: {
                      mode: 'Incremental'
                      expressionEvaluationOptions: {
                        scope: 'inner'
                      }
                      parameters: {
                        subscriptionId: {
                          value: '[parameters(\'subscriptionId\')]'
                        }
                        managedIdentityResourceId: {
                          value: '[parameters(\'managedIdentityResourceId\')]'
                        }
                        managedIdentityClientId: {
                          value: '[parameters(\'managedIdentityClientId\')]'
                        }
                        centralKeyVaultName: {
                          value: '[parameters(\'centralKeyVaultName\')]'
                        }
                        appNamePattern: {
                          value: '[parameters(\'appNamePattern\')]'
                        }
                        graphPermissions: {
                          value: '[parameters(\'graphPermissions\')]'
                        }
                        secretMonths: {
                          value: '[parameters(\'secretMonths\')]'
                        }
                        subscriptionRoleDefinitionIds: {
                          value: '[parameters(\'subscriptionRoleDefinitionIds\')]'
                        }
                        azCliVersion: {
                          value: '[parameters(\'azCliVersion\')]'
                        }
                        scriptLocation: {
                          value: '[parameters(\'scriptLocation\')]'
                        }
                      }
                      template: {
                        '$schema': 'https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#'
                        contentVersion: '1.0.0.0'
                        parameters: {
                          subscriptionId: {
                            type: 'string'
                          }
                          managedIdentityResourceId: {
                            type: 'string'
                          }
                          managedIdentityClientId: {
                            type: 'string'
                          }
                          centralKeyVaultName: {
                            type: 'string'
                          }
                          appNamePattern: {
                            type: 'string'
                          }
                          graphPermissions: {
                            type: 'array'
                          }
                          secretMonths: {
                            type: 'int'
                          }
                          subscriptionRoleDefinitionIds: {
                            type: 'array'
                          }
                          azCliVersion: {
                            type: 'string'
                          }
                          scriptLocation: {
                            type: 'string'
                          }
                        }
                        resources: [
                          {
                            type: 'Microsoft.Resources/deploymentScripts'
                            apiVersion: '2023-08-01'
                            name: scriptName
                            location: '[parameters(\'scriptLocation\')]'
                            kind: 'AzureCLI'
                            // The key must be the identity RESOURCE ID, resolved in the
                            // EMBEDDED template's context - hence the escaped expression.
                            // Bicep emits '[[parameters(...)]' which ARM un-escapes to
                            // '[parameters(...)]' inside the stored policy definition.
                            identity: {
                              type: 'UserAssigned'
                              userAssignedIdentities: '[json(concat(\'{"\', parameters(\'managedIdentityResourceId\'), \'":{}}\'))]'
                            }
                            properties: {
                              azCliVersion: '[parameters(\'azCliVersion\')]'
                              retentionInterval: 'PT1H'
                              cleanupPreference: 'OnSuccess'
                              timeout: 'PT45M'
                              environmentVariables: [
                                {
                                  name: 'TARGET_SUB'
                                  value: '[parameters(\'subscriptionId\')]'
                                }
                                {
                                  name: 'MI_CLIENT_ID'
                                  value: '[parameters(\'managedIdentityClientId\')]'
                                }
                                {
                                  name: 'KV_NAME'
                                  value: '[parameters(\'centralKeyVaultName\')]'
                                }
                                {
                                  name: 'APP_NAME'
                                  value: '[replace(parameters(\'appNamePattern\'), \'{sub}\', parameters(\'subscriptionId\'))]'
                                }
                                {
                                  name: 'GRAPH_PERMS'
                                  value: '[join(parameters(\'graphPermissions\'), \' \')]'
                                }
                                {
                                  name: 'SECRET_MONTHS'
                                  value: '[string(parameters(\'secretMonths\'))]'
                                }
                                {
                                  name: 'RBAC_ROLES'
                                  value: '[join(parameters(\'subscriptionRoleDefinitionIds\'), \' \')]'
                                }
                              ]
                              scriptContent: loadTextContent('scripts/appreg-deploymentscript.sh')
                            }
                          }
                        ]
                        outputs: {
                          appId: {
                            type: 'string'
                            value: '[reference(resourceId(\'Microsoft.Resources/deploymentScripts\', \'${scriptName}\')).outputs.appId]'
                          }
                          consentVerified: {
                            type: 'string'
                            value: '[string(reference(resourceId(\'Microsoft.Resources/deploymentScripts\', \'${scriptName}\')).outputs.consentVerified)]'
                          }
                        }
                      }
                    }
                  }
                ]
              }
            }
          }
        }
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Assignment
// ---------------------------------------------------------------------------
resource appRegAssignment 'Microsoft.Authorization/policyAssignments@2024-04-01' = {
  name: '${namePrefix}-appreg'
  location: assignmentLocation
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    displayName: 'Abstract Security - per-subscription Entra app registration'
    description: empty(tagName) ? 'Applies to EVERY subscription in scope - no tag gate configured.' : 'Applies only to subscriptions tagged ${tagName}=${tagValue}.'
    policyDefinitionId: appRegPolicy.id
    enforcementMode: enforcementMode
    parameters: {
      effect: {
        value: effect
      }
      managedIdentityResourceId: {
        value: managedIdentityResourceId
      }
      managedIdentityClientId: {
        value: managedIdentityClientId
      }
      centralKeyVaultName: {
        value: centralKeyVaultName
      }
      centralKeyVaultResourceGroup: {
        value: centralKeyVaultResourceGroup
      }
      centralKeyVaultSubscriptionId: {
        value: centralKeyVaultSubscriptionId
      }
      appNamePattern: {
        value: appNamePattern
      }
      graphPermissions: {
        value: graphPermissions
      }
      secretMonths: {
        value: secretMonths
      }
      subscriptionRoleDefinitionIds: {
        value: subscriptionRoleDefinitionIds
      }
      scriptResourceGroup: {
        value: scriptResourceGroup
      }
      azCliVersion: {
        value: azCliVersion
      }
      scriptLocation: {
        value: assignmentLocation
      }
    }
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------
output policyDefinitionId string = appRegPolicy.id
output assignmentName string = appRegAssignment.name

@description('Grant this principal Owner (or Contributor + User Access Administrator) on the target subscriptions, and Key Vault Secrets Officer on the central vault.')
output assignmentPrincipalId string = appRegAssignment.identity!.principalId

output nextSteps object = {
  step1: 'Bootstrap the Graph identity if you have not: scripts/Deploy-AbstractAppReg.sh -a Bootstrap. Needs Global Administrator ONCE.'
  step2: 'Grant the assignment principal above Owner on the target subscriptions and Key Vault Secrets Officer on ${centralKeyVaultName}.'
  step3: 'Leave effect=AuditIfNotExists first and read Policy > Compliance: it lists exactly which subscriptions would be onboarded.'
  step4: 'Flip to DeployIfNotExists + enforcementMode=Default, then run a remediation task to act on EXISTING subscriptions.'
  tagGate: empty(tagName) ? 'NO TAG GATE - every in-scope subscription is targeted. Strongly consider setting tagName.' : 'Gated on ${tagName}=${tagValue}. Tag a subscription to opt it in.'
  saferAlternative: 'templates/automation/abstract-appreg-automation.bicep keeps the privileged identity in ONE place instead of running privileged containers per subscription.'
}
