targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for number of sign-ins to trigger alert')
param signinThreshold int = 3

@description('Threshold for number of audit events to trigger alert')
param auditEventsThreshold int = 5

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
param severity string = 'High'

@description('Enable or disable the analytics rule')
param enabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource crossTenantRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'cross-tenant-activity')
  kind: 'Scheduled'
  properties: {
    displayName: 'Cross-Tenant Service Principal Activity (Stolen Credentials)'
    description: 'Detects service principals accessing resources across tenant boundaries, which may indicate credential theft and lateral movement. This is a high-severity indicator of compromise. MITRE ATT&CK: T1550 (Use Alternate Authentication Material).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nlet audits = AuditLogs\n| where TimeGenerated > ago(lookback_period)\n| where OperationName has_any ("application", "service principal", "secret", "credential")\n| summarize AuditActions = count() by CorrelationId;\nAADServicePrincipalSignInLogs\n| where TimeGenerated > ago(lookback_period)\n| extend AppDisplayName = ServicePrincipalName, HomeTenantId = AADTenantId\n| join kind=leftouter audits on CorrelationId\n| summarize SignIns = count(), Resources = make_set(ResourceDisplayName), AuditEventsTriggered = sum(AuditActions) by AppId, AppDisplayName, HomeTenantId, IPAddress\n| where SignIns > ${signinThreshold} or AuditEventsTriggered > ${auditEventsThreshold}\n| extend Alert = "Potential Credential Theft - Service Principal Used for Enumeration"\n| project AppDisplayName, AppId, HomeTenantId, IPAddress, SignIns, AuditEventsTriggered, Resources, Alert'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'LateralMovement'
      'Exfiltration'
    ]
    techniques: [
      'T1550'
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
      alertDisplayNameFormat: 'Suspicious Service Principal Activity: {{AppDisplayName}} with {{SignIns}} sign-ins'
      alertDescriptionFormat: 'Service principal {{AppDisplayName}} performed {{SignIns}} sign-ins with {{AuditEventsTriggered}} audit events. Potential credential theft detected.'
      alertSeverityColumnName: null
    }
    customDetails: {
      SignIns: 'SignIns'
      AuditEventsTriggered: 'AuditEventsTriggered'
      Resources: 'Resources'
      HomeTenantId: 'HomeTenantId'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'AppDisplayName'
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
      {
        entityType: 'IP'
        fieldMappings: [
          {
            identifier: 'Address'
            columnName: 'IPAddress'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = crossTenantRule.id
output analyticsRuleName string = crossTenantRule.name
