targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for number of failed attempts to trigger alert')
param failedAttemptsThreshold int = 10

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

resource spFailedAuthRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'sp-failed-auth')
  kind: 'Scheduled'
  properties: {
    displayName: 'Failed Service Principal Authentications (Credential Stuffing)'
    description: 'Detects multiple failed authentication attempts from the same IP address, indicating potential credential stuffing or brute force attacks against service principals. MITRE ATT&CK: T1110 (Brute Force).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nAADServicePrincipalSignInLogs\n| where TimeGenerated > ago(lookback_period)\n| where ResultType != 0\n| summarize FailedAttempts = count(), FailureCodes = make_set(ResultType), UniqueApps = dcount(AppId), TargetApps = make_set(ServicePrincipalName), SourceIPs = make_set(IPAddress) by bin(TimeGenerated, 1h), IPAddress\n| where FailedAttempts > ${failedAttemptsThreshold}\n| project TimeGenerated, IPAddress, FailedAttempts, UniqueApps, TargetApps, FailureCodes, Severity = case(FailedAttempts > 50, "High", FailedAttempts > 20, "Medium", "Low")'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
    ]
    techniques: [
      'T1110'
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
          'IP'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Failed Authentication Attack: {{FailedAttempts}} attempts from {{IPAddress}}'
      alertDescriptionFormat: 'IP {{IPAddress}} made {{FailedAttempts}} failed authentication attempts against {{UniqueApps}} apps.'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      FailedAttempts: 'FailedAttempts'
      UniqueApps: 'UniqueApps'
      TargetApps: 'TargetApps'
      FailureCodes: 'FailureCodes'
    }
    entityMappings: [
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

output analyticsRuleId string = spFailedAuthRule.id
output analyticsRuleName string = spFailedAuthRule.name
