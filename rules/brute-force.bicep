targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for number of failed attempts to trigger alert')
param failedAttemptsThreshold int = 5

@description('Lookback period in hours')
param lookbackPeriodHours int = 1

@description('Query frequency in ISO 8601 duration format (default: 5 minutes)')
param queryFrequency string = 'PT5M'

@description('Query period in ISO 8601 duration format (default: 1 hour)')
param queryPeriod string = 'PT1H'

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

resource bruteForceRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'brute-force-attack')
  kind: 'Scheduled'
  properties: {
    displayName: 'Multiple Failed Sign-in Attempts (Brute Force)'
    description: 'Detects multiple failed authentication attempts from the same IP address, indicating potential brute force attacks against user accounts. MITRE ATT&CK: T1110.001 (Password Guessing), T1078 (Valid Accounts).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nSigninLogs\n| where TimeGenerated > ago(lookback_period)\n| where ResultType != "0"\n| where ResultType != "50125"\n| where ResultType != "50140"\n| summarize FailedAttempts = count(), UniqueUsers = make_set(UserPrincipalName), ResultTypes = make_set(ResultType), FirstFailure = min(TimeGenerated), LastFailure = max(TimeGenerated) by IPAddress, AppDisplayName\n| where FailedAttempts >= ${failedAttemptsThreshold}\n| project IPAddress, AppDisplayName, FailedAttempts, UniqueUsers, ResultTypes, FirstFailure, LastFailure'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'InitialAccess'
    ]
    techniques: [
      'T1110'
      'T1078'
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT1H'
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
      alertDisplayNameFormat: 'Brute Force Attack Detected - {{IPAddress}}'
      alertDescriptionFormat: 'IP {{IPAddress}} made {{FailedAttempts}} failed login attempts to {{AppDisplayName}}. This may indicate a brute force attack.'
      alertSeverityColumnName: null
    }
    customDetails: {
      FailedLoginCount: 'FailedAttempts'
      TargetedAccounts: 'UniqueUsers'
      FirstAttempt: 'FirstFailure'
      LastAttempt: 'LastFailure'
      Application: 'AppDisplayName'
      ErrorCodes: 'ResultTypes'
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
            identifier: 'Name'
            columnName: 'UniqueUsers'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = bruteForceRule.id
output analyticsRuleName string = bruteForceRule.name
