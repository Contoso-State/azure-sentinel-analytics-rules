targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for number of failed logins before success')
param failedLoginsThreshold int = 3

@description('Minimum successful logins to confirm compromise')
param successfulLoginsThreshold int = 1

@description('Lookback period in hours')
param lookbackPeriodHours int = 4

@description('Query frequency in ISO 8601 duration format (default: 5 minutes)')
param queryFrequency string = 'PT5M'

@description('Query period in ISO 8601 duration format (default: 4 hours)')
param queryPeriod string = 'PT4H'

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

resource accountCompromiseRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'account-compromise')
  kind: 'Scheduled'
  properties: {
    displayName: 'Successful Login After Multiple Failures (Credential Compromise)'
    description: 'Detects successful authentication after multiple failed attempts, indicating credentials were compromised. MITRE ATT&CK: T1078.004 (Cloud Accounts), T1110 (Brute Force), T1098 (Account Manipulation).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nSigninLogs\n| where TimeGenerated > ago(lookback_period)\n| where AppDisplayName != ""\n| summarize TotalAttempts = count(), SuccessfulLogins = countif(ResultType == "0"), FailedLogins = countif(ResultType != "0"), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated), Applications = make_set(AppDisplayName) by IPAddress, UserPrincipalName\n| where FailedLogins >= ${failedLoginsThreshold} and SuccessfulLogins >= ${successfulLoginsThreshold}\n| project IPAddress, UserPrincipalName, TotalAttempts, SuccessfulLogins, FailedLogins, FirstAttempt, LastAttempt, Applications'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT4H'
    suppressionEnabled: false
    tactics: [
      'InitialAccess'
      'CredentialAccess'
      'Persistence'
    ]
    techniques: [
      'T1078'
      'T1110'
      'T1098'
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT4H'
        matchingMethod: 'Selected'
        groupByEntities: [
          'Account'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'CRITICAL: Account Compromised - {{UserPrincipalName}}'
      alertDescriptionFormat: 'Account {{UserPrincipalName}} was compromised after {{FailedLogins}} failed login attempts from {{IPAddress}}. Successful login detected.'
      alertSeverityColumnName: null
    }
    customDetails: {
      CompromisedAccount: 'UserPrincipalName'
      AttackerIP: 'IPAddress'
      FailedAttempts: 'FailedLogins'
      SuccessfulLogins: 'SuccessfulLogins'
      FirstSeen: 'FirstAttempt'
      CompromiseTime: 'LastAttempt'
      AppsAccessed: 'Applications'
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
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'UserPrincipalName'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = accountCompromiseRule.id
output analyticsRuleName string = accountCompromiseRule.name
