targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('App ID to monitor for enumeration activity (leave empty to monitor all apps)')
param suspiciousAppId string = ''

@description('Threshold for number of operations to trigger alert')
param operationThreshold int = 10

@description('Lookback period in hours')
param lookbackPeriodHours int = 24

@description('Query frequency in ISO 8601 duration format (default: 1 hour)')
param queryFrequency string = 'PT1H'

@description('Query period in ISO 8601 duration format (default: 24 hours)')
param queryPeriod string = 'PT24H'

@description('Rule severity: High, Medium, Low, or Informational')
@allowed([
  'High'
  'Medium'
  'Low'
  'Informational'
])
param severity string = 'Medium'

@description('Enable or disable the analytics rule')
param enabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource appEnumerationRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'app-registration-enumeration')
  kind: 'Scheduled'
  properties: {
    displayName: 'App Registration Enumeration via Microsoft Graph API'
    description: 'Detects excessive app registration and service principal enumeration operations. This behavior may indicate reconnaissance activity or preparation for privilege escalation attacks. MITRE ATT&CK: T1087.004 (Account Discovery: Cloud Account), T1526 (Cloud Service Discovery).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nlet suspicious_app = "${suspiciousAppId}";\nAuditLogs\n| where TimeGenerated > ago(lookback_period)\n| where OperationName in ("Add application", "Update application", "List applications", "Get application", "Add service principal", "Get service principal")\n| where InitiatedBy.app.appId == suspicious_app\n| summarize OperationCount = count(), Operations = make_set(OperationName), TargetResources = make_set(TargetResources[0].displayName), FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated) by bin(TimeGenerated, 1h), AppDisplayName = tostring(InitiatedBy.app.displayName), AppId = tostring(InitiatedBy.app.appId), ServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId)\n| where OperationCount > ${operationThreshold}\n| project TimeGenerated, AppDisplayName, AppId, ServicePrincipalId, OperationCount, Operations, TargetResources, FirstSeen, LastSeen, Severity = case(OperationCount > 50, "High", OperationCount > 25, "Medium", "Low")\n| order by OperationCount desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Discovery'
      'Collection'
    ]
    techniques: [
      'T1087'
      'T1526'
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
          'CloudApplication'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'App Registration Enumeration: {{AppDisplayName}} performed {{OperationCount}} operations'
      alertDescriptionFormat: 'The service principal {{AppDisplayName}} performed {{OperationCount}} operations. This may indicate reconnaissance activity.'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      OperationCount: 'OperationCount'
      Operations: 'Operations'
      TargetResources: 'TargetResources'
      FirstSeen: 'FirstSeen'
      LastSeen: 'LastSeen'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'AppDisplayName'
          }
          {
            identifier: 'AadUserId'
            columnName: 'ServicePrincipalId'
          }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'AppId'
            columnName: 'AppId'
          }
          {
            identifier: 'Name'
            columnName: 'AppDisplayName'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = appEnumerationRule.id
output analyticsRuleName string = appEnumerationRule.name
