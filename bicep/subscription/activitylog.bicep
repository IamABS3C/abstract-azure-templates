// ============================================================================
// Abstract Security - Azure Activity Log Export (subscription scope)
// ----------------------------------------------------------------------------
// Streams the Azure Activity Log of the target subscription to the Abstract
// Event Hub. Deploy once per subscription:
//
//   az deployment sub create \
//     --location eastus \
//     --template-file templates/subscription/activitylog.bicep \
//     --parameters eventHubAuthorizationRuleId=<auth-rule-id>
//
// This must be a separate, subscription-scope deployment: Activity Log
// diagnostic settings live at subscription scope and cannot be created from
// the resource-group-scope main template.
// ============================================================================
targetScope = 'subscription'

@description('Name of the subscription diagnostic setting (max 5 per subscription, unique name).')
@minLength(1)
@maxLength(260)
param settingName string = 'abstract-activity-logs'

@description('Full resource ID of an Event Hubs namespace authorization rule with Send rights. Use the abstractDiagnosticsAuthRuleId output of the main template.')
param eventHubAuthorizationRuleId string

@description('Event Hub that receives the Activity Log stream. main.bicep auto-names hubs <hubPrefix>-<environment>-<source>, so the default source stack creates abs-prod-activity.')
param eventHubName string = 'abs-prod-activity'

@description('Activity Log categories to export. Default = all eight (recommended by Abstract Security).')
param categories array = [
  'Administrative'
  'Security'
  'ServiceHealth'
  'Alert'
  'Recommendation'
  'Policy'
  'Autoscale'
  'ResourceHealth'
]

resource activityLogExport 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: settingName
  properties: {
    eventHubAuthorizationRuleId: eventHubAuthorizationRuleId
    eventHubName: eventHubName
    logs: [for cat in categories: {
      category: cat
      enabled: true
    }]
  }
}

output diagnosticSettingName string = activityLogExport.name
output subscriptionId string = subscription().subscriptionId
output exportedCategories array = categories
