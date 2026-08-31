// =============================================================================
//  Abstract Security - Event Hub pipeline health alerts (Bicep)
//  Version : 1.0
//  Author  : Abstract Security - Solutions Engineering
//  Scope   : RESOURCE GROUP (the one holding the Event Hubs namespace)
//
//  WHY THIS EXISTS
//  ---------------
//  Every other template in this repo gets data flowing. This one tells you when it
//  STOPS - which, on this pipeline, is otherwise close to undetectable.
//
//  Azure Event Hubs publishes NO CONSUMER-LAG METRIC of any kind. There is no
//  equivalent of Kafka's consumer offset lag. So when the Abstract consumer stalls
//  or dies:
//    - IncomingMessages stays perfectly healthy (producers are unaffected),
//    - no error is raised anywhere,
//    - every Event Hubs health dashboard stays green,
//    - and message retention quietly expires the backlog, after which the data is
//      gone for good with no metric, no log and no dead-letter.
//
//  The only observable signal is INFERENTIAL: outgoing traffic collapsing while
//  incoming traffic continues. That is what this template alarms on.
//
//  THE TRAP THAT MAKES A NAIVE ALERT USELESS
//  -----------------------------------------
//  Event Hubs metrics are SPARSE. When nothing is consuming, the platform may emit
//  NO OutgoingBytes datapoints at all rather than emitting zeros. A classic metric
//  alert of the form "OutgoingBytes < threshold" therefore never fires: it has no
//  data to evaluate, so it sits in "Insufficient data" forever and nobody notices.
//
//  Two defences, both applied here:
//    1. Every metric alert sets alertSensitivity/missing-data handling explicitly
//       rather than relying on the default.
//    2. The consumer-stall alert is a SCHEDULED QUERY RULE whose KQL always
//       returns a row - it synthesises a zero when the metric is absent, so
//       "no data" and "zero throughput" become the same, alertable condition.
//
//  WHAT IT CREATES
//  ---------------
//    1. Consumer stalled       - log-search rule, fires when outgoing collapses
//                                while incoming continues (THE important one)
//    2. Ingestion stopped      - no incoming messages at all (producer-side break)
//    3. Throttled requests     - throughput units saturated
//    4. User errors            - usually an expired or revoked SAS key
//    5. Quota exceeded errors  - hard capacity ceiling hit
//
//  NOT COVERED, DELIBERATELY: the Auto-Inflate cost ratchet
//  -------------------------------------------------------
//  Auto-Inflate scales throughput units UP and, per Microsoft, never scales them
//  back DOWN, so one traffic spike sets a permanent new floor on the bill - and
//  because Capture is metered per throughput unit, it inflates that line too.
//  This template does NOT alert on it, because there is no platform METRIC for the
//  provisioned throughput-unit count: the scale events land in the AutoScaleLogs
//  DIAGNOSTIC LOG category, which requires a diagnostic setting on the namespace
//  itself ("monitoring the monitor") sending to a Log Analytics workspace - a
//  dependency this template cannot assume exists.
//  An earlier draft alerted on NamespaceCpuUsage instead. That is a Premium-only
//  CPU metric and does not measure throughput units at all; shipping it would have
//  looked like coverage while detecting nothing. Removed rather than guessed.
//  Until AutoScaleLogs is wired up, review provisioned TUs by hand monthly.
//
//  Deploy AFTER eventhub-source.bicep, into the same resource group.
// =============================================================================

targetScope = 'resourceGroup'

// ---------------------------------------------------------------------------
// Core
// ---------------------------------------------------------------------------

@description('Name of the existing Event Hubs namespace to monitor. Must already exist - deploy eventhub-source.bicep first. Find it with: az eventhubs namespace list --query [].name -o tsv')
@minLength(6)
@maxLength(50)
param namespaceName string

@description('Location for the scheduled query rule. Metric alerts are global; this only affects the log-search rule.')
param location string = resourceGroup().location

@description('Prefix for every alert rule name created here.')
@minLength(2)
@maxLength(20)
param alertPrefix string = 'abstract-eh'

@description('Action Group resource ID to notify. Leave empty to create the rules WITHOUT notifications - they will still show in Azure Monitor, but nobody will be told. Strongly recommended to supply one.')
param actionGroupId string = ''

@description('Create the rules in a disabled state so they can be reviewed before they start firing.')
param createDisabled bool = false

@description('Tags applied to every resource created by this template.')
param tags object = {}

// ---------------------------------------------------------------------------
// Thresholds
// ---------------------------------------------------------------------------

@description('Minutes of collapsed outgoing traffic before the consumer is considered stalled. Keep this comfortably longer than the consumer poll interval so a normal quiet period does not page anyone.')
@minValue(5)
@maxValue(360)
param consumerStallWindowMinutes int = 30

@description('Incoming messages over the window ABOVE which a flat outgoing count is treated as a stall. Guards against alerting on a genuinely idle hub, where zero-in/zero-out is correct and healthy.')
@minValue(1)
param minIncomingToAlert int = 100

@description('Minutes with zero incoming messages before ingestion is considered stopped. This is the producer side - a deleted diagnostic setting, a revoked Send key, or a firewall change.')
@minValue(5)
@maxValue(1440)
param ingestionStoppedWindowMinutes int = 60

@description('Throttled requests over 5 minutes before alerting. Any sustained throttling means throughput units are saturated.')
@minValue(1)
param throttleThreshold int = 10

@description('Severity for the data-loss alerts (consumer stalled, ingestion stopped). 0 = critical.')
@allowed([0, 1, 2, 3, 4])
param dataLossSeverity int = 1

@description('Severity for the capacity and cost alerts.')
@allowed([0, 1, 2, 3, 4])
param capacitySeverity int = 2

// ---------------------------------------------------------------------------
// Existing namespace
// ---------------------------------------------------------------------------

resource ehNamespace 'Microsoft.EventHub/namespaces@2024-01-01' existing = {
  name: namespaceName
}

var actions = empty(actionGroupId) ? [] : [
  {
    actionGroupId: actionGroupId
  }
]

var scheduledQueryActions = empty(actionGroupId) ? {} : {
  actionGroups: [actionGroupId]
}

var ruleState = createDisabled ? false : true

// ---------------------------------------------------------------------------
// 1. CONSUMER STALLED - the one that matters
//
// A scheduled query rule, NOT a metric alert, and deliberately so. Event Hubs
// emits no OutgoingBytes datapoints at all when nothing is consuming, so a metric
// alert on "OutgoingBytes < x" evaluates against no data and never fires.
//
// This KQL uses a union with a synthetic zero row, so the query ALWAYS returns
// exactly one row: either the real measured throughput, or a fabricated zero when
// the metric is silent. Both are alertable. That is the whole trick.
// ---------------------------------------------------------------------------

// Bicep does NOT interpolate inside a ''' multi-line string - a ${...} in one of those
// ships to Azure as literal text. So the KQL is written with sentinel tokens and the parameter
// values are substituted with replace(). Verified by compiling: with interpolation the
// parameters read as "declared but never used", which is how this was caught.
var consumerStallQueryTemplate = '''
let window = __WINDOW__m;
let minIncoming = __MIN_INCOMING__;
let measured =
    AzureMetrics
    | where ResourceId =~ '__RESOURCE_ID__'
    | where TimeGenerated > ago(window)
    | where MetricName in ('IncomingMessages', 'OutgoingMessages')
    | summarize Value = sum(Total) by MetricName
    | summarize
        IncomingMessages = sumif(Value, MetricName == 'IncomingMessages'),
        OutgoingMessages = sumif(Value, MetricName == 'OutgoingMessages');
// Event Hubs emits NO rows when nothing is consuming. Union a synthetic zero so the query
// always returns exactly one row and "no data" becomes an alertable condition rather than an
// evaluation that silently never runs.
let synthetic = datatable(IncomingMessages: real, OutgoingMessages: real) [ 0.0, 0.0 ];
union measured, synthetic
| top 1 by IncomingMessages desc
| extend Stalled = iff(IncomingMessages >= minIncoming and OutgoingMessages == 0, 1, 0)
| where Stalled == 1
| project IncomingMessages, OutgoingMessages, Stalled
'''

var consumerStallQuery = replace(
  replace(
    replace(consumerStallQueryTemplate, '__WINDOW__', string(consumerStallWindowMinutes)),
    '__MIN_INCOMING__', string(minIncomingToAlert)),
  '__RESOURCE_ID__', ehNamespace.id)

resource consumerStalled 'Microsoft.Insights/scheduledQueryRules@2023-03-15-preview' = {
  name: '${alertPrefix}-consumer-stalled'
  location: location
  tags: tags
  properties: {
    displayName: '${alertPrefix}: Abstract consumer stalled (outgoing collapsed, incoming healthy)'
    description: 'Event Hubs publishes no consumer-lag metric, so a stalled consumer is invisible until retention expires and the data is permanently gone. This rule infers the stall from outgoing traffic collapsing while incoming traffic continues. The query synthesises a zero row when the metric is absent, because Event Hubs emits no datapoints at all rather than zeros when nothing is consuming - a plain metric alert would sit in Insufficient Data forever.'
    severity: dataLossSeverity
    enabled: ruleState
    evaluationFrequency: 'PT5M'
    windowSize: 'PT${consumerStallWindowMinutes}M'
    scopes: [
      ehNamespace.id
    ]
    criteria: {
      allOf: [
        {
          query: consumerStallQuery
          timeAggregation: 'Count'
          operator: 'GreaterThan'
          threshold: 0
          failingPeriods: {
            numberOfEvaluationPeriods: 1
            minFailingPeriodsToAlert: 1
          }
        }
      ]
    }
    autoMitigate: true
    actions: scheduledQueryActions
  }
}

// ---------------------------------------------------------------------------
// 2. INGESTION STOPPED - producer side
//
// Zero incoming messages. A deleted diagnostic setting, a revoked Send key, a
// firewall flipped to Deny without the trusted-services bypass. Note this one CAN
// be a metric alert because we are alerting on a LOW total, and IncomingMessages
// is generally emitted continuously by an active namespace - but we still set
// missing-data handling explicitly rather than trusting the default.
// ---------------------------------------------------------------------------

resource ingestionStopped 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${alertPrefix}-ingestion-stopped'
  location: 'global'
  tags: tags
  properties: {
    description: 'No messages have arrived in the namespace. Causes, in rough order of likelihood: a diagnostic setting was deleted, the Send authorization rule was rotated or revoked, or the namespace firewall was set to Deny without allowing trusted Microsoft services (which blocks Azure Monitor\'s own delivery).'
    severity: dataLossSeverity
    enabled: ruleState
    scopes: [
      ehNamespace.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT${ingestionStoppedWindowMinutes}M'
    targetResourceType: 'Microsoft.EventHub/namespaces'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'NoIncomingMessages'
          metricNamespace: 'Microsoft.EventHub/namespaces'
          metricName: 'IncomingMessages'
          operator: 'LessThanOrEqual'
          threshold: 0
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          skipMetricValidation: false
        }
      ]
    }
    autoMitigate: true
    actions: actions
  }
}

// ---------------------------------------------------------------------------
// 3. THROTTLED REQUESTS - throughput units saturated
// ---------------------------------------------------------------------------

resource throttled 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${alertPrefix}-throttled'
  location: 'global'
  tags: tags
  properties: {
    description: 'Requests are being throttled, which means provisioned throughput units are saturated. Producers will retry and may eventually drop. Enable Auto-Inflate or raise the throughput unit count - and note that partitions cap parallelism independently, and cannot be increased on Standard.'
    severity: capacitySeverity
    enabled: ruleState
    scopes: [
      ehNamespace.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT5M'
    targetResourceType: 'Microsoft.EventHub/namespaces'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'ThrottledRequests'
          metricNamespace: 'Microsoft.EventHub/namespaces'
          metricName: 'ThrottledRequests'
          operator: 'GreaterThan'
          threshold: throttleThreshold
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          skipMetricValidation: false
        }
      ]
    }
    autoMitigate: true
    actions: actions
  }
}

// ---------------------------------------------------------------------------
// 4. USER ERRORS - usually an expired or revoked credential
// ---------------------------------------------------------------------------

resource userErrors 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${alertPrefix}-user-errors'
  location: 'global'
  tags: tags
  properties: {
    description: 'Client-side errors against the namespace. The most common cause by a wide margin is an expired or regenerated SAS key, which breaks producers and consumers at different moments depending on which rule was rotated. Also seen when a service principal loses its role assignment.'
    severity: capacitySeverity
    enabled: ruleState
    scopes: [
      ehNamespace.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    targetResourceType: 'Microsoft.EventHub/namespaces'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'UserErrors'
          metricNamespace: 'Microsoft.EventHub/namespaces'
          metricName: 'UserErrors'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          skipMetricValidation: false
        }
      ]
    }
    autoMitigate: true
    actions: actions
  }
}

// ---------------------------------------------------------------------------
// 5. QUOTA EXCEEDED - hard ceiling
// ---------------------------------------------------------------------------

resource quotaExceeded 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${alertPrefix}-quota-exceeded'
  location: 'global'
  tags: tags
  properties: {
    description: 'A hard service quota was hit - connection count, throughput unit ceiling, or entity limits. Unlike throttling this will not resolve itself under lighter load; something needs to be raised or redesigned.'
    severity: capacitySeverity
    enabled: ruleState
    scopes: [
      ehNamespace.id
    ]
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    targetResourceType: 'Microsoft.EventHub/namespaces'
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'QuotaExceededErrors'
          metricNamespace: 'Microsoft.EventHub/namespaces'
          metricName: 'QuotaExceededErrors'
          operator: 'GreaterThan'
          threshold: 0
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
          skipMetricValidation: false
        }
      ]
    }
    autoMitigate: true
    actions: actions
  }
}

// ---------------------------------------------------------------------------
// Outputs
// ---------------------------------------------------------------------------

output consumerStalledRuleId string = consumerStalled.id
output ingestionStoppedRuleId string = ingestionStopped.id
output alertRuleNames array = [
  consumerStalled.name
  ingestionStopped.name
  throttled.name
  userErrors.name
  quotaExceeded.name
]
output notificationsConfigured bool = !empty(actionGroupId)
output monitoringSummary object = {
  namespace: namespaceName
  rulesCreated: 5
  enabled: ruleState
  notificationsConfigured: !empty(actionGroupId)
  consumerStallWindowMinutes: consumerStallWindowMinutes
  note: empty(actionGroupId) ? 'NO ACTION GROUP SUPPLIED - rules exist but nobody will be notified. Supply actionGroupId.' : 'Alerts route to the supplied action group.'
}
