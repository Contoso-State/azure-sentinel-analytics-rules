targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for number of unique users targeted to trigger alert')
param targetedUsersThreshold int = 5

@description('Lookback period in hours')
param lookbackPeriodHours int = 1

@description('Query frequency in ISO 8601 duration format (default: 10 minutes)')
param queryFrequency string = 'PT10M'

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

resource passwordSprayRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'password-spray-attack')
  kind: 'Scheduled'
  properties: {
    displayName: 'Password Spray Attack Detection'
    description: 'Detects password spray attacks where one IP attempts to login to multiple different accounts. MITRE ATT&CK: T1110.003 (Password Spraying), T1087 (Account Discovery).'
    severity: severity
    enabled: enabled
    query: 'let lookback_period = ${lookbackPeriodHours}h;\nSigninLogs\n| where TimeGenerated > ago(lookback_period)\n| where ResultType == "50126"\n| summarize AttemptedUsers = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName), Applications = make_set(AppDisplayName), FirstAttempt = min(TimeGenerated), LastAttempt = max(TimeGenerated), TotalAttempts = count() by IPAddress\n| where AttemptedUsers >= ${targetedUsersThreshold}\n| project IPAddress, AttemptedUsers, UserList, Applications, FirstAttempt, LastAttempt, TotalAttempts'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT2H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'Discovery'
    ]
    techniques: [
      'T1110'
      'T1087'
    ]
    alertRuleTemplateName: null
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT2H'
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
      alertDisplayNameFormat: 'Password Spray Attack - {{IPAddress}}'
      alertDescriptionFormat: 'IP {{IPAddress}} attempted to login to {{AttemptedUsers}} different accounts with {{TotalAttempts}} total attempts. This indicates password spraying.'
      alertSeverityColumnName: null
    }
    customDetails: {
      TargetedUsers: 'AttemptedUsers'
      UserList: 'UserList'
      TotalAttempts: 'TotalAttempts'
      FirstAttempt: 'FirstAttempt'
      LastAttempt: 'LastAttempt'
      Apps: 'Applications'
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
            columnName: 'UserList'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = passwordSprayRule.id
output analyticsRuleName string = passwordSprayRule.name
