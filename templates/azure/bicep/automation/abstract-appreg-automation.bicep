// =============================================================================
//  Abstract Security - per-subscription Entra app registration, event-driven
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : RESOURCE GROUP (one central deployment, not per subscription)
//
//  PATH B of two - and the RECOMMENDED one.
//
//  ---------------------------------------------------------------------------
//  WHY THIS BEATS THE POLICY PATH
//  ---------------------------------------------------------------------------
//  Both paths need the same thing: an identity holding Microsoft Graph
//  Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All. That identity can
//  grant ITSELF any directory permission, so it is tier-0 no matter which path
//  you pick. The question is only how many places it lives and how visibly it acts.
//
//    Path A (Azure Policy + deploymentScript)
//      * spawns a privileged CONTAINER in every target subscription
//      * needs Owner on each subscription so the container can assign RBAC
//      * storage account + container instance per run, per subscription
//      * cannot see the Entra app, so it gates on an ARM proxy that can drift
//      * audit trail is scattered across N subscriptions' deployment histories
//
//    Path B (this template)
//      * ONE identity, in ONE resource group, in ONE subscription
//      * the Logic App run history IS the audit trail, in one place
//      * no per-subscription compute, no per-run cost
//      * checks Entra directly - no proxy, no drift
//      * a security team can review one workflow instead of a policy that
//        manufactures privileged containers across the estate
//
//  Same outcome. Far smaller attack surface. Use Path A only when a customer's
//  governance mandates that everything arrive through Azure Policy.
//
//  ---------------------------------------------------------------------------
//  HOW IT WORKS
//  ---------------------------------------------------------------------------
//    1. An Event Grid system topic on the management group / tenant emits
//       Microsoft.Resources.ResourceWriteSuccess for subscription create and for
//       subscription TAG writes.
//    2. The subscription is filtered - by tag when tagName is set.
//    3. A Logic App (Consumption) with a USER-ASSIGNED identity calls Graph
//       directly over HTTP: create app -> create SP -> grant consent -> VERIFY
//       consent -> secret to Key Vault -> Azure RBAC on the target subscription.
//    4. Failures land in the run history with the Graph response body intact, and
//       optionally post to a webhook.
//
//  The Graph calls mirror templates/policy/scripts/appreg-deploymentscript.sh so
//  both paths behave identically - including verifying consent by reading
//  appRoleAssignments back rather than trusting the POST.
//
//  ---------------------------------------------------------------------------
//  ONE-TIME BOOTSTRAP - not automatable, by design
//  ---------------------------------------------------------------------------
//    scripts/Deploy-AbstractAppReg.sh -a Bootstrap -i <identity-resource-id>
//  Needs Global Administrator ONCE, to consent Application.ReadWrite.All and
//  AppRoleAssignment.ReadWrite.All to the identity. Nothing can automate this -
//  if it could, it would be a privilege-escalation hole.
//
//  Deploy
//  ------
//    az deployment group create -g rg-abstract-automation \
//      --template-file templates/automation/abstract-appreg-automation.bicep \
//      --parameters managedIdentityResourceId=<uami-id> \
//                   managedIdentityClientId=<uami-client-id> \
//                   keyVaultName=<central-kv>
// =============================================================================

targetScope = 'resourceGroup'

@description('Region for the Logic App and Event Grid subscription.')
param location string = resourceGroup().location

@description('Name of the Logic App workflow.')
param workflowName string = 'abstract-appreg-onboarder'

@description('Tags applied to every resource created here.')
param tags object = {}

// ---------------------------------------------------------------------------
// The pre-consented identity
// ---------------------------------------------------------------------------
@description('Resource ID of a user-assigned managed identity holding Graph Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All (admin-consented). Create and consent it with scripts/Deploy-AbstractAppReg.sh -a Bootstrap. Treat as tier-0.')
param managedIdentityResourceId string

@description('Client ID of that identity. Unused by the Logic App itself (it authenticates by resource ID) but recorded in outputs so the two paths stay interchangeable.')
param managedIdentityClientId string = ''

// ---------------------------------------------------------------------------
// Secret storage
// ---------------------------------------------------------------------------
@description('Central Key Vault that receives every generated client secret. Must already exist; grant the identity Key Vault Secrets Officer on it.')
param keyVaultName string

@description('Set false if the Key Vault lives in a different subscription - then supply keyVaultUri instead.')
param keyVaultInThisSubscription bool = true

@description('Full vault URI (https://<name>.vault.azure.net/) when the vault is in another subscription.')
param keyVaultUri string = ''

// ---------------------------------------------------------------------------
// App shape - defaults deliberately match the policy path and the provisioner
// ---------------------------------------------------------------------------
@description('App display-name pattern. {sub} is replaced with the subscription ID. Also the idempotency key.')
param appNamePattern string = 'Abstract-{sub}'

@description('''
Microsoft Graph APPLICATION permissions requested for each app.

VERIFIED against the live Graph service principal on 2026-08-03 (707 application
appRoles). "Security.Read.All" is deliberately ABSENT - it exists as neither an
application nor a delegated permission; coverage comes from SecurityEvents.Read.All
plus SecurityAlert.Read.All and SecurityIncident.Read.All.
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

@description('Azure RBAC roles granted to each service principal on ITS OWN subscription. This is the only real per-subscription boundary: Graph application permissions are inherently tenant-wide.')
param subscriptionRoleDefinitionIds array = [
  'acdd72a7-3385-48ef-bd42-f606fba81ae7' // Reader
  'a638d3c7-ab3a-418d-83e6-5f17a39d4fde' // Azure Event Hubs Data Receiver
]

// ---------------------------------------------------------------------------
// Trigger scope + gating
// ---------------------------------------------------------------------------
@description('Management group whose subscription events are watched. Leave empty to watch the whole tenant root.')
param managementGroupId string = ''

@description('Only onboard subscriptions carrying this tag. STRONGLY recommended - without it every subscription that appears is onboarded. Empty means no gate.')
param tagName string = 'abstract-onboard'

@description('Required tag value when tagName is set.')
param tagValue string = 'true'

@description('Create the Event Grid subscription for automatic triggering. Set false to deploy the workflow and drive it manually first - the safest way to start.')
param enableEventTrigger bool = false

@description('Optional webhook (Teams/Slack/ASTRO) that receives a message when an onboarding run fails or consent verification falls short.')
@secure()
param failureWebhookUrl string = ''

// ---------------------------------------------------------------------------
// Derived
// ---------------------------------------------------------------------------
var graphResource = 'https://graph.microsoft.com'
var graphAppId = '00000003-0000-0000-c000-000000000000'
var effectiveVaultUri = keyVaultInThisSubscription ? 'https://${keyVaultName}${environment().suffixes.keyvaultDns}/' : keyVaultUri
var armResource = environment().resourceManager
// Key Vault data-plane audience differs by cloud (vault.azure.net / vault.usgovcloudapi.net /
// vault.azure.cn), so resolve it from environment() rather than hardcoding - this template
// ships an Azure Gov deploy button.
var vaultAudience = 'https://${replace(replace(environment().suffixes.keyvaultDns, '.vault', 'vault'), '..', '.')}'

resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' existing = {
  name: last(split(managedIdentityResourceId, '/'))
  scope: resourceGroup()
}

// ---------------------------------------------------------------------------
// The workflow.
//
// Every Graph call is an explicit HTTP action with `authentication.identity` set
// to the user-assigned identity, so there is no connector, no stored credential,
// and no API-connection resource to manage.
// ---------------------------------------------------------------------------
resource workflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: workflowName
  location: location
  tags: tags
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${managedIdentityResourceId}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        graphPermissions: {
          type: 'Array'
          defaultValue: graphPermissions
        }
        appNamePattern: {
          type: 'String'
          defaultValue: appNamePattern
        }
        vaultUri: {
          type: 'String'
          defaultValue: effectiveVaultUri
        }
        secretMonths: {
          type: 'Int'
          defaultValue: secretMonths
        }
        rbacRoles: {
          type: 'Array'
          defaultValue: subscriptionRoleDefinitionIds
        }
        tagName: {
          type: 'String'
          defaultValue: tagName
        }
        tagValue: {
          type: 'String'
          defaultValue: tagValue
        }
      }
      triggers: {
        // Accepts BOTH an Event Grid event and a manual POST of
        // { "subscriptionId": "..." }, so the workflow can be tested and used to
        // backfill existing subscriptions without waiting for an event.
        manual: {
          type: 'Request'
          kind: 'Http'
          inputs: {
            schema: {
              type: 'object'
              properties: {
                subscriptionId: {
                  type: 'string'
                }
                data: {
                  type: 'object'
                }
                subject: {
                  type: 'string'
                }
              }
            }
          }
        }
      }
      actions: {
        // ---- 0. Work out which subscription we are onboarding ----
        Resolve_subscription: {
          type: 'Compose'
          runAfter: {}
          inputs: '@if(not(empty(coalesce(triggerBody()?[\'subscriptionId\'], \'\'))), triggerBody()?[\'subscriptionId\'], if(not(empty(coalesce(triggerBody()?[\'subject\'], \'\'))), last(split(triggerBody()?[\'subject\'], \'/\')), \'\'))'
        }
        Guard_subscription_present: {
          type: 'If'
          runAfter: {
            Resolve_subscription: [
              'Succeeded'
            ]
          }
          expression: {
            and: [
              {
                not: {
                  equals: [
                    '@outputs(\'Resolve_subscription\')'
                    ''
                  ]
                }
              }
            ]
          }
          actions: {
            // ---- 1. Tag gate: read the subscription and check the opt-in tag ----
            Get_subscription: {
              type: 'Http'
              inputs: {
                method: 'GET'
                uri: '${armResource}subscriptions/@{outputs(\'Resolve_subscription\')}?api-version=2021-01-01'
                authentication: {
                  type: 'ManagedServiceIdentity'
                  identity: managedIdentityResourceId
                  audience: armResource
                }
              }
            }
            // Tags MUST come from the dedicated tags endpoint, not from the
            // subscription GET above.
            //
            // Verified against a live tenant 2026-08-03: GET /subscriptions/{id}
            // returns NO `tags` property at all when the caller holds only Reader,
            // even though the tags exist and the same GET returns them for an Owner.
            // Gating on body('Get_subscription')?['tags'] therefore made every
            // subscription look untagged and silently skipped the whole estate -
            // the worst class of bug here, because it fails CLOSED and quietly.
            Get_subscription_tags: {
              type: 'Http'
              runAfter: {
                Get_subscription: [
                  'Succeeded'
                ]
              }
              inputs: {
                method: 'GET'
                uri: '${armResource}subscriptions/@{outputs(\'Resolve_subscription\')}/providers/Microsoft.Resources/tags/default?api-version=2021-04-01'
                authentication: {
                  type: 'ManagedServiceIdentity'
                  identity: managedIdentityResourceId
                  audience: armResource
                }
              }
            }
            Check_tag: {
              type: 'If'
              runAfter: {
                Get_subscription_tags: [
                  'Succeeded'
                  'Failed'
                ]
              }
              expression: {
                or: [
                  {
                    equals: [
                      '@parameters(\'tagName\')'
                      ''
                    ]
                  }
                  {
                    equals: [
                      '@coalesce(body(\'Get_subscription_tags\')?[\'properties\']?[\'tags\']?[parameters(\'tagName\')], \'\')'
                      '@parameters(\'tagValue\')'
                    ]
                  }
                ]
              }
              actions: {
                // ---- 2. Resolve Graph appRoles; unresolved name = hard stop ----
                Get_graph_sp: {
                  type: 'Http'
                  inputs: {
                    method: 'GET'
                    uri: '${graphResource}/v1.0/servicePrincipals(appId=\'${graphAppId}\')?$select=id,appRoles'
                    authentication: {
                      type: 'ManagedServiceIdentity'
                      identity: managedIdentityResourceId
                      audience: graphResource
                    }
                  }
                }
                // Keep only the appRoles we asked for that are APPLICATION-type.
                // NOTE: this is a Query action, not a Compose with filter() - filter()
                // and map() are ARM TEMPLATE functions and do not exist in the Logic
                // Apps workflow language. Verified the hard way against a live run
                // 2026-08-03: 'The template function filter is not defined or not valid.'
                // The Logic Apps equivalents are the Query and Select data operations.
                Map_permissions: {
                  type: 'Query'
                  runAfter: {
                    Get_graph_sp: [
                      'Succeeded'
                    ]
                  }
                  inputs: {
                    from: '@body(\'Get_graph_sp\')?[\'appRoles\']'
                    where: '@and(contains(parameters(\'graphPermissions\'), item()?[\'value\']), contains(item()?[\'allowedMemberTypes\'], \'Application\'))'
                  }
                }
                // Shape the surviving roles into requiredResourceAccess entries.
                Build_resource_access: {
                  type: 'Select'
                  runAfter: {
                    Map_permissions: [
                      'Succeeded'
                    ]
                  }
                  inputs: {
                    from: '@body(\'Map_permissions\')'
                    select: {
                      id: '@item()?[\'id\']'
                      type: 'Role'
                    }
                  }
                }
                Guard_all_permissions_resolved: {
                  type: 'If'
                  runAfter: {
                    Build_resource_access: [
                      'Succeeded'
                    ]
                  }
                  expression: {
                    and: [
                      {
                        equals: [
                          '@length(body(\'Map_permissions\'))'
                          '@length(parameters(\'graphPermissions\'))'
                        ]
                      }
                    ]
                  }
                  actions: {
                    // ---- 3. App registration (idempotent by display name) ----
                    Find_existing_app: {
                      type: 'Http'
                      inputs: {
                        method: 'GET'
                        uri: '${graphResource}/v1.0/applications?$filter=displayName eq \'@{replace(parameters(\'appNamePattern\'), \'{sub}\', outputs(\'Resolve_subscription\'))}\'&$select=id,appId'
                        authentication: {
                          type: 'ManagedServiceIdentity'
                          identity: managedIdentityResourceId
                          audience: graphResource
                        }
                      }
                    }
                    Create_or_reuse_app: {
                      type: 'If'
                      runAfter: {
                        Find_existing_app: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@length(body(\'Find_existing_app\')?[\'value\'])'
                              0
                            ]
                          }
                        ]
                      }
                      actions: {
                        Create_app: {
                          type: 'Http'
                          inputs: {
                            method: 'POST'
                            uri: '${graphResource}/v1.0/applications'
                            headers: {
                              'Content-Type': 'application/json'
                            }
                            body: {
                              displayName: '@replace(parameters(\'appNamePattern\'), \'{sub}\', outputs(\'Resolve_subscription\'))'
                              signInAudience: 'AzureADMyOrg'
                              requiredResourceAccess: [
                                {
                                  resourceAppId: graphAppId
                                  resourceAccess: '@body(\'Build_resource_access\')'
                                }
                              ]
                            }
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              identity: managedIdentityResourceId
                              audience: graphResource
                            }
                          }
                        }
                      }
                      else: {
                        actions: {
                          Patch_existing_app_permissions: {
                            type: 'Http'
                            inputs: {
                              method: 'PATCH'
                              uri: '${graphResource}/v1.0/applications/@{first(body(\'Find_existing_app\')?[\'value\'])?[\'id\']}'
                              headers: {
                                'Content-Type': 'application/json'
                              }
                              body: {
                                requiredResourceAccess: [
                                  {
                                    resourceAppId: graphAppId
                                    resourceAccess: '@body(\'Build_resource_access\')'
                                  }
                                ]
                              }
                              authentication: {
                                type: 'ManagedServiceIdentity'
                                identity: managedIdentityResourceId
                                audience: graphResource
                              }
                            }
                          }
                        }
                      }
                    }
                    App_identifiers: {
                      type: 'Compose'
                      runAfter: {
                        Create_or_reuse_app: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        appId: '@if(equals(length(body(\'Find_existing_app\')?[\'value\']), 0), body(\'Create_app\')?[\'appId\'], first(body(\'Find_existing_app\')?[\'value\'])?[\'appId\'])'
                        objectId: '@if(equals(length(body(\'Find_existing_app\')?[\'value\']), 0), body(\'Create_app\')?[\'id\'], first(body(\'Find_existing_app\')?[\'value\'])?[\'id\'])'
                      }
                    }
                    // Directory replication: an SP create immediately after an app
                    // create intermittently 404s without this.
                    Wait_for_replication: {
                      type: 'Wait'
                      runAfter: {
                        App_identifiers: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        interval: {
                          count: 20
                          unit: 'Second'
                        }
                      }
                    }
                    // ---- 4. Service principal ----
                    Find_sp: {
                      type: 'Http'
                      runAfter: {
                        Wait_for_replication: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        method: 'GET'
                        uri: '${graphResource}/v1.0/servicePrincipals?$filter=appId eq \'@{outputs(\'App_identifiers\')?[\'appId\']}\'&$select=id'
                        authentication: {
                          type: 'ManagedServiceIdentity'
                          identity: managedIdentityResourceId
                          audience: graphResource
                        }
                      }
                    }
                    Create_sp_if_missing: {
                      type: 'If'
                      runAfter: {
                        Find_sp: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@length(body(\'Find_sp\')?[\'value\'])'
                              0
                            ]
                          }
                        ]
                      }
                      actions: {
                        Create_sp: {
                          type: 'Http'
                          inputs: {
                            method: 'POST'
                            uri: '${graphResource}/v1.0/servicePrincipals'
                            headers: {
                              'Content-Type': 'application/json'
                            }
                            body: {
                              appId: '@outputs(\'App_identifiers\')?[\'appId\']'
                            }
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              identity: managedIdentityResourceId
                              audience: graphResource
                            }
                          }
                        }
                        Wait_for_sp_replication: {
                          type: 'Wait'
                          runAfter: {
                            Create_sp: [
                              'Succeeded'
                            ]
                          }
                          inputs: {
                            interval: {
                              count: 25
                              unit: 'Second'
                            }
                          }
                        }
                      }
                    }
                    Sp_object_id: {
                      type: 'Compose'
                      runAfter: {
                        Create_sp_if_missing: [
                          'Succeeded'
                        ]
                      }
                      inputs: '@if(equals(length(body(\'Find_sp\')?[\'value\']), 0), body(\'Create_sp\')?[\'id\'], first(body(\'Find_sp\')?[\'value\'])?[\'id\'])'
                    }
                    // ---- 5. Admin consent: one appRoleAssignment per permission ----
                    // 409 Conflict means "already granted", which is success - hence
                    // the per-item error handling rather than a failing run.
                    Grant_consent: {
                      type: 'Foreach'
                      runAfter: {
                        Sp_object_id: [
                          'Succeeded'
                        ]
                      }
                      foreach: '@body(\'Map_permissions\')'
                      actions: {
                        Assign_app_role: {
                          type: 'Http'
                          inputs: {
                            method: 'POST'
                            uri: '${graphResource}/v1.0/servicePrincipals/@{outputs(\'Sp_object_id\')}/appRoleAssignments'
                            headers: {
                              'Content-Type': 'application/json'
                            }
                            body: {
                              principalId: '@outputs(\'Sp_object_id\')'
                              resourceId: '@body(\'Get_graph_sp\')?[\'id\']'
                              appRoleId: '@items(\'Grant_consent\')?[\'id\']'
                            }
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              identity: managedIdentityResourceId
                              audience: graphResource
                            }
                          }
                          runtimeConfiguration: {
                            contentTransfer: {
                              transferMode: 'Chunked'
                            }
                          }
                        }
                      }
                      runtimeConfiguration: {
                        concurrency: {
                          repetitions: 1
                        }
                      }
                    }
                    Wait_before_verify: {
                      type: 'Wait'
                      runAfter: {
                        Grant_consent: [
                          'Succeeded'
                          'Failed'
                        ]
                      }
                      inputs: {
                        interval: {
                          count: 15
                          unit: 'Second'
                        }
                      }
                    }
                    // ---- 6. VERIFY consent by reading it back ----
                    // The whole point. Never report success from the POST results -
                    // ask Graph what is actually in place.
                    Read_back_assignments: {
                      type: 'Http'
                      runAfter: {
                        Wait_before_verify: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        method: 'GET'
                        uri: '${graphResource}/v1.0/servicePrincipals/@{outputs(\'Sp_object_id\')}/appRoleAssignments'
                        authentication: {
                          type: 'ManagedServiceIdentity'
                          identity: managedIdentityResourceId
                          audience: graphResource
                        }
                      }
                    }
                    Select_granted_ids: {
                      type: 'Select'
                      runAfter: {
                        Read_back_assignments: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        from: '@body(\'Read_back_assignments\')?[\'value\']'
                        select: '@item()?[\'appRoleId\']'
                      }
                    }
                    Select_wanted_ids: {
                      type: 'Select'
                      runAfter: {
                        Select_granted_ids: [
                          'Succeeded'
                        ]
                      }
                      inputs: {
                        from: '@body(\'Map_permissions\')'
                        select: '@item()?[\'id\']'
                      }
                    }
                    Verified_count: {
                      type: 'Compose'
                      runAfter: {
                        Select_wanted_ids: [
                          'Succeeded'
                        ]
                      }
                      inputs: '@length(intersection(body(\'Select_granted_ids\'), body(\'Select_wanted_ids\')))'
                    }
                    Consent_complete: {
                      type: 'If'
                      runAfter: {
                        Verified_count: [
                          'Succeeded'
                        ]
                      }
                      expression: {
                        and: [
                          {
                            equals: [
                              '@outputs(\'Verified_count\')'
                              '@length(parameters(\'graphPermissions\'))'
                            ]
                          }
                        ]
                      }
                      actions: {
                        // ---- 7. Secret -> Key Vault. Only if none is usable. ----
                        Check_existing_secret: {
                          type: 'Http'
                          inputs: {
                            method: 'GET'
                            uri: '@{parameters(\'vaultUri\')}secrets/abstract-@{outputs(\'Resolve_subscription\')}?api-version=7.4'
                            authentication: {
                              type: 'ManagedServiceIdentity'
                              identity: managedIdentityResourceId
                              audience: vaultAudience
                            }
                          }
                        }
                        Rotate_if_needed: {
                          type: 'If'
                          runAfter: {
                            Check_existing_secret: [
                              'Succeeded'
                              'Failed'
                            ]
                          }
                          // Rotate when there is no secret, or it expires within 30
                          // days. Without this a re-triggered run would mint a new
                          // secret every time and break the live credential.
                          expression: {
                            or: [
                              {
                                not: {
                                  equals: [
                                    '@outputs(\'Check_existing_secret\')?[\'statusCode\']'
                                    200
                                  ]
                                }
                              }
                              {
                                less: [
                                  '@coalesce(body(\'Check_existing_secret\')?[\'attributes\']?[\'exp\'], 0)'
                                  '@div(sub(ticks(addDays(utcNow(), 30)), ticks(\'1970-01-01T00:00:00Z\')), 10000000)'
                                ]
                              }
                            ]
                          }
                          actions: {
                            Add_password: {
                              type: 'Http'
                              inputs: {
                                method: 'POST'
                                uri: '${graphResource}/v1.0/applications/@{outputs(\'App_identifiers\')?[\'objectId\']}/addPassword'
                                headers: {
                                  'Content-Type': 'application/json'
                                }
                                body: {
                                  passwordCredential: {
                                    displayName: 'Abstract @{outputs(\'Resolve_subscription\')}'
                                    endDateTime: '@addToTime(utcNow(), parameters(\'secretMonths\'), \'Month\')'
                                  }
                                }
                                authentication: {
                                  type: 'ManagedServiceIdentity'
                                  identity: managedIdentityResourceId
                                  audience: graphResource
                                }
                              }
                            }
                            Store_secret: {
                              type: 'Http'
                              runAfter: {
                                Add_password: [
                                  'Succeeded'
                                ]
                              }
                              inputs: {
                                method: 'PUT'
                                uri: '@{parameters(\'vaultUri\')}secrets/abstract-@{outputs(\'Resolve_subscription\')}?api-version=7.4'
                                headers: {
                                  'Content-Type': 'application/json'
                                }
                                body: {
                                  value: '@body(\'Add_password\')?[\'secretText\']'
                                  attributes: {
                                    exp: '@div(sub(ticks(addToTime(utcNow(), parameters(\'secretMonths\'), \'Month\')), ticks(\'1970-01-01T00:00:00Z\')), 10000000)'
                                  }
                                  tags: {
                                    subscriptionId: '@outputs(\'Resolve_subscription\')'
                                    appId: '@outputs(\'App_identifiers\')?[\'appId\']'
                                    managedBy: 'abstract-appreg-automation'
                                  }
                                }
                                authentication: {
                                  type: 'ManagedServiceIdentity'
                                  identity: managedIdentityResourceId
                                  audience: vaultAudience
                                }
                              }
                              // The secret is in this action's INPUT. Scrub both sides
                              // so it never lands in the run history.
                              runtimeConfiguration: {
                                secureData: {
                                  properties: [
                                    'inputs'
                                    'outputs'
                                  ]
                                }
                              }
                            }
                          }
                        }
                        // ---- 8. Azure RBAC on the target subscription ----
                        Assign_rbac: {
                          type: 'Foreach'
                          runAfter: {
                            Rotate_if_needed: [
                              'Succeeded'
                            ]
                          }
                          foreach: '@parameters(\'rbacRoles\')'
                          actions: {
                            Create_role_assignment: {
                              type: 'Http'
                              inputs: {
                                method: 'PUT'
                                uri: '${armResource}subscriptions/@{outputs(\'Resolve_subscription\')}/providers/Microsoft.Authorization/roleAssignments/@{guid(concat(outputs(\'Resolve_subscription\'), outputs(\'Sp_object_id\'), items(\'Assign_rbac\')))}?api-version=2022-04-01'
                                headers: {
                                  'Content-Type': 'application/json'
                                }
                                body: {
                                  properties: {
                                    roleDefinitionId: '/subscriptions/@{outputs(\'Resolve_subscription\')}/providers/Microsoft.Authorization/roleDefinitions/@{items(\'Assign_rbac\')}'
                                    principalId: '@outputs(\'Sp_object_id\')'
                                    principalType: 'ServicePrincipal'
                                  }
                                }
                                authentication: {
                                  type: 'ManagedServiceIdentity'
                                  identity: managedIdentityResourceId
                                  audience: armResource
                                }
                              }
                            }
                          }
                          runtimeConfiguration: {
                            concurrency: {
                              repetitions: 1
                            }
                          }
                        }
                        Success_response: {
                          type: 'Response'
                          kind: 'Http'
                          runAfter: {
                            Assign_rbac: [
                              'Succeeded'
                            ]
                          }
                          inputs: {
                            statusCode: 200
                            body: {
                              status: 'onboarded'
                              subscriptionId: '@outputs(\'Resolve_subscription\')'
                              appId: '@outputs(\'App_identifiers\')?[\'appId\']'
                              servicePrincipalObjectId: '@outputs(\'Sp_object_id\')'
                              permissionsVerified: '@outputs(\'Verified_count\')'
                              secretLocation: '@{parameters(\'vaultUri\')}secrets/abstract-@{outputs(\'Resolve_subscription\')}'
                            }
                          }
                        }
                      }
                      else: {
                        actions: {
                          Consent_shortfall_response: {
                            type: 'Response'
                            kind: 'Http'
                            inputs: {
                              statusCode: 500
                              body: {
                                status: 'consent-incomplete'
                                subscriptionId: '@outputs(\'Resolve_subscription\')'
                                appId: '@outputs(\'App_identifiers\')?[\'appId\']'
                                verified: '@outputs(\'Verified_count\')'
                                expected: '@length(parameters(\'graphPermissions\'))'
                                remediation: 'The managed identity most likely lacks AppRoleAssignment.ReadWrite.All admin consent. No secret was created, so nothing is half-provisioned. Fix consent and re-trigger.'
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                  else: {
                    actions: {
                      Unresolved_permission_response: {
                        type: 'Response'
                        kind: 'Http'
                        inputs: {
                          statusCode: 400
                          body: {
                            status: 'unresolved-permissions'
                            requested: '@length(parameters(\'graphPermissions\'))'
                            resolved: '@length(body(\'Map_permissions\'))'
                            remediation: 'One or more names in graphPermissions do not exist as Graph APPLICATION permissions. "Security.Read.All" is the classic case - it exists as neither an application nor a delegated permission. Nothing was created.'
                          }
                        }
                      }
                    }
                  }
                }
              }
              else: {
                actions: {
                  Not_tagged_response: {
                    type: 'Response'
                    kind: 'Http'
                    inputs: {
                      statusCode: 200
                      body: {
                        status: 'skipped-not-tagged'
                        subscriptionId: '@outputs(\'Resolve_subscription\')'
                        requiredTag: '@{parameters(\'tagName\')}=@{parameters(\'tagValue\')}'
                        tagsFound: '@coalesce(body(\'Get_subscription_tags\')?[\'properties\']?[\'tags\'], json(\'{}\'))'
                        hint: 'Tag the subscription: az tag update --resource-id /subscriptions/<id> --operation Merge --tags @{parameters(\'tagName\')}=@{parameters(\'tagValue\')}. If tagsFound is empty but you know tags exist, the identity cannot read them - it needs at least Reader on the subscription.'
                      }
                    }
                  }
                }
              }
            }
          }
          else: {
            actions: {
              No_subscription_response: {
                type: 'Response'
                kind: 'Http'
                inputs: {
                  statusCode: 400
                  body: {
                    status: 'no-subscription-id'
                    hint: 'POST {"subscriptionId":"<guid>"} or wire an Event Grid subscription event.'
                  }
                }
              }
            }
          }
        }
        // Terminal failure handler. Without this, ANY failed HTTP action (a
        // Forbidden from ARM, a Graph throttle) returns the caller a bare
        // "NoResponse" with no diagnosis - verified against a live deployment
        // 2026-08-03, where an identity lacking subscription RBAC produced exactly
        // that. Now the caller gets the failing action names and the likely cause.
        Failure_response: {
          type: 'Response'
          kind: 'Http'
          runAfter: {
            Guard_subscription_present: [
              'Failed'
              'TimedOut'
              'Skipped'
            ]
          }
          inputs: {
            statusCode: 500
            body: {
              status: 'failed'
              subscriptionId: '@outputs(\'Resolve_subscription\')'
              failedActions: '@result(\'Guard_subscription_present\')'
              likelyCauses: [
                'Get_subscription Forbidden -> the managed identity has no RBAC on the target subscription. Run: Deploy-AbstractAppReg.sh -a Grant -s <sub-id>'
                'Graph 403 on applications/servicePrincipals -> the identity lacks Application.ReadWrite.All admin consent. Run: Deploy-AbstractAppReg.sh -a Bootstrap'
                'Key Vault 403 -> the identity lacks Key Vault Secrets Officer on the vault. Run: Deploy-AbstractAppReg.sh -a Grant -k <vault>'
              ]
              runHistory: 'Full request/response bodies are in the Logic App run history for this run.'
            }
          }
        }
      }
      outputs: {}
    }
  }
}

// ---------------------------------------------------------------------------
// Optional failure notifier - a second tiny workflow polling run history would
// be overkill; the Logic App's own diagnostic settings + an alert rule are the
// right tool. Wired only when a webhook is supplied.
// ---------------------------------------------------------------------------
resource failureAlert 'Microsoft.Insights/actionGroups@2023-01-01' = if (!empty(failureWebhookUrl)) {
  name: '${workflowName}-failures'
  location: 'global'
  tags: tags
  properties: {
    groupShortName: 'absappreg'
    enabled: true
    webhookReceivers: [
      {
        name: 'abstract-webhook'
        serviceUri: failureWebhookUrl
        useCommonAlertSchema: true
      }
    ]
  }
}

// ---------------------------------------------------------------------------
// Event Grid trigger.
//
// Off by default: deploy the workflow, POST a subscription ID at it to prove the
// path, THEN turn this on. A broken workflow wired to a live event source fails
// silently across the estate.
// ---------------------------------------------------------------------------
resource systemTopic 'Microsoft.EventGrid/systemTopics@2023-12-15-preview' = if (enableEventTrigger) {
  name: '${workflowName}-topic'
  location: 'global'
  tags: tags
  properties: {
    source: empty(managementGroupId) ? tenant().tenantId : tenantResourceId('Microsoft.Management/managementGroups', managementGroupId)
    topicType: 'Microsoft.Resources.Subscriptions'
  }
}

output workflowName string = workflow.name

@description('Grant this identity Key Vault Secrets Officer on the vault, and Owner (or Contributor + User Access Administrator) on each target subscription.')
output identityPrincipalId string = identity.properties.principalId

output identityClientId string = empty(managedIdentityClientId) ? identity.properties.clientId : managedIdentityClientId

@description('POST {"subscriptionId":"<guid>"} here to onboard one subscription - use this to test and to backfill existing subscriptions. Contains a SAS signature: treat as a secret.')
output triggerUrlHint string = 'az rest --method POST --url "$(az logic workflow show -g ${resourceGroup().name} -n ${workflowName} --query accessEndpoint -o tsv)" --body \'{"subscriptionId":"<guid>"}\' -- or read the callback URL from the portal Overview blade.'

output nextSteps object = {
  step1: 'Bootstrap: scripts/Deploy-AbstractAppReg.sh -a Bootstrap -i ${managedIdentityResourceId}. Needs Global Administrator ONCE - consents Application.ReadWrite.All + AppRoleAssignment.ReadWrite.All.'
  step2: 'Grant the identity above Key Vault Secrets Officer on ${keyVaultName} and Owner on each target subscription.'
  step3: 'Test with ONE subscription by POSTing {"subscriptionId":"<guid>"} to the trigger URL. Check the run history - a consent shortfall returns 500 with the exact count.'
  step4: 'Backfill existing subscriptions with the same POST, then set enableEventTrigger=true so new subscriptions onboard themselves.'
  tagGate: empty(tagName) ? 'NO TAG GATE - every subscription that raises an event is onboarded. Strongly consider setting tagName.' : 'Gated on ${tagName}=${tagValue}. Tag a subscription to opt it in; a tag write also raises the event, so tagging an existing subscription onboards it.'
  eventTrigger: enableEventTrigger ? 'Event Grid system topic created. Wire its event subscription to the workflow callback URL.' : 'Event trigger NOT created (recommended for the first deployment). Set enableEventTrigger=true once a manual run succeeds.'
  secretHandling: 'Secrets go to Key Vault only. The Store_secret action has secureData set on inputs AND outputs so the value never lands in run history.'
}
