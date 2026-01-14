targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('App ID to monitor for sign-in activity (leave empty to monitor all service principals)')
param suspiciousAppId string = ''

@description('Threshold for number of sign-ins to trigger alert')
param signinThreshold int = 5

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

resource spSignInRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'sp-signin-activity')
  kind: 'Scheduled'
  properties: {
    displayName: 'Suspicious Service Principal Sign-In Activity'
    description: 'Detects excessive sign-in activity from service principals. High volume sign-ins may indicate credential abuse or automated enumeration attacks. MITRE ATT&CK: T1078 (Valid Accounts).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nlet suspicious_app = "${suspiciousAppId}";\nAADServicePrincipalSignInLogs\n| where TimeGenerated > ago(lookback_period)\n| where AppId == suspicious_app\n| extend AppDisplayName = ServicePrincipalName\n| summarize SignInCount = count(), UniqueIPs = dcount(IPAddress), IPs = make_set(IPAddress), Resources = make_set(ResourceDisplayName), ResultTypes = make_set(ResultType) by bin(TimeGenerated, 1h), AppDisplayName, ServicePrincipalId\n| where SignInCount > ${signinThreshold}\n| project TimeGenerated, AppDisplayName, ServicePrincipalId, SignInCount, UniqueIPs, IPs, Resources, ResultTypes, Severity = iff(SignInCount > 20, "High", "Medium")'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'CredentialAccess'
    ]
    techniques: [
      'T1078'
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
      alertDisplayNameFormat: 'Suspicious Sign-In Activity: {{AppDisplayName}} had {{SignInCount}} sign-ins'
      alertDescriptionFormat: 'Service principal {{AppDisplayName}} performed {{SignInCount}} sign-ins. This may indicate credential abuse.'
      alertSeverityColumnName: 'Severity'
    }
    customDetails: {
      SignInCount: 'SignInCount'
      UniqueIPs: 'UniqueIPs'
      IPs: 'IPs'
      Resources: 'Resources'
      ResultTypes: 'ResultTypes'
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
            identifier: 'Name'
            columnName: 'AppDisplayName'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = spSignInRule.id
output analyticsRuleName string = spSignInRule.name
