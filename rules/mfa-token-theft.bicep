targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Comma-separated UPNs to exclude from detection (e.g., admin accounts)')
param excludedUsers string = ''

@description('Window in minutes to correlate MFA change with password reset')
param mfaPasswordWindowMinutes int = 30

@description('Window in minutes for multi-IP token replay detection')
param tokenReplayWindowMinutes int = 15

@description('Minimum distinct IPs to trigger token replay detection')
param multiIpThreshold int = 2

@description('Lookback period in hours')
param lookbackPeriodHours int = 1

@description('Query frequency in ISO 8601 duration format')
param queryFrequency string = 'PT5M'

@description('Query period in ISO 8601 duration format')
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

resource mfaTokenTheftRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'mfa-token-theft-aitm')
  kind: 'Scheduled'
  properties: {
    displayName: 'MFA Token Theft — AiTM Phishing with Account Takeover'
    description: 'Detects two correlated attack patterns indicative of Adversary-in-the-Middle (AiTM) phishing: (a) MFA method reset followed by password reset for the same user within a configurable window — indicates full account takeover after session token theft, (b) Sign-ins from multiple IPs for the same user within a short window — indicates stolen token replay from attacker infrastructure. MITRE ATT&CK: T1557.003 (AiTM), T1528 (Steal Application Access Token), T1556.006 (Modify Authentication Process: MFA).'
    severity: severity
    enabled: enabled
    query: 'let mfaPasswordWindow = ${mfaPasswordWindowMinutes}m;\nlet tokenReplayWindow = ${tokenReplayWindowMinutes}m;\nlet lookback = ${lookbackPeriodHours}h;\nlet ExcludedUPNs = dynamic([${excludedUsers}]);\nlet MFAResetOperations = dynamic(["User registered security info", "User deleted security info", "User changed default security info method", "Admin registered security info", "Admin deleted security info", "Admin updated security info"]);\nlet PasswordResetOperations = dynamic(["Reset password (by admin)", "Reset user password", "Change user password", "Change password", "Reset password"]);\nlet MFAMethodChanges = AuditLogs\n| where TimeGenerated > ago(lookback)\n| where OperationName has_any (MFAResetOperations)\n| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)\n| where TargetUPN !in (ExcludedUPNs)\n| where not(TargetUPN startswith "svc-")\n| project MFAChangeTime = TimeGenerated, TargetUPN, MFAOperation = OperationName, MFAInitiatedBy = tostring(InitiatedBy.user.userPrincipalName), MFAChangeIP = tostring(InitiatedBy.user.ipAddress);\nlet PasswordResets = AuditLogs\n| where TimeGenerated > ago(lookback)\n| where OperationName has_any (PasswordResetOperations)\n| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)\n| where TargetUPN !in (ExcludedUPNs)\n| where not(TargetUPN startswith "svc-")\n| project PasswordResetTime = TimeGenerated, TargetUPN, PasswordOperation = OperationName, PasswordInitiatedBy = tostring(InitiatedBy.user.userPrincipalName), PasswordResetIP = tostring(InitiatedBy.user.ipAddress);\nlet DetectionA = MFAMethodChanges\n| join kind=inner (PasswordResets) on TargetUPN\n| where abs(datetime_diff(\'minute\', PasswordResetTime, MFAChangeTime)) <= ${mfaPasswordWindowMinutes}\n| extend TimeBetweenEvents = iff(PasswordResetTime > MFAChangeTime, PasswordResetTime - MFAChangeTime, MFAChangeTime - PasswordResetTime), DetectionType = "MFA_Reset_Plus_Password_Reset"\n| project TimeGenerated = MFAChangeTime, DetectionType, UserPrincipalName = TargetUPN, MFAChangeTime, MFAOperation, MFAInitiatedBy, PasswordResetTime, PasswordOperation, PasswordInitiatedBy, TimeBetweenEvents, AccountName = TargetUPN, IPAddress = coalesce(MFAChangeIP, PasswordResetIP);\nlet MultiIPSignins = SigninLogs\n| where TimeGenerated > ago(lookback)\n| where ResultType == 0\n| where UserPrincipalName !in (ExcludedUPNs)\n| where not(UserPrincipalName startswith "svc-")\n| summarize DistinctIPs = make_set(IPAddress, 20), IPCount = dcount(IPAddress), FirstSignin = min(TimeGenerated), LastSignin = max(TimeGenerated), Apps = make_set(AppDisplayName, 10) by UserPrincipalName, bin(TimeGenerated, ${tokenReplayWindowMinutes}m)\n| where IPCount >= ${multiIpThreshold}\n| where (LastSignin - FirstSignin) <= ${tokenReplayWindowMinutes}m;\nlet DetectionB = MultiIPSignins\n| extend DetectionType = "Token_Replay_Multi_IP", TimeBetweenEvents = LastSignin - FirstSignin\n| project TimeGenerated = FirstSignin, DetectionType, UserPrincipalName, IPCount, DistinctIPs, TimeBetweenEvents, Apps, AccountName = UserPrincipalName, IPAddress = tostring(DistinctIPs[0]);\nunion DetectionA, DetectionB\n| project TimeGenerated, DetectionType, UserPrincipalName, MFAOperation, PasswordOperation, TimeBetweenEvents, IPCount, DistinctIPs, AccountName, IPAddress\n| order by TimeGenerated desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CredentialAccess'
      'Persistence'
      'DefenseEvasion'
    ]
    techniques: [
      'T1557'
      'T1528'
      'T1556'
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
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'MFA Token Theft: {{DetectionType}} for {{UserPrincipalName}}'
      alertDescriptionFormat: 'Detected {{DetectionType}} for user {{UserPrincipalName}}. MFA operation: {{MFAOperation}}. Time between events: {{TimeBetweenEvents}}. This may indicate an AiTM phishing attack with account takeover.'
      alertSeverityColumnName: null
    }
    customDetails: {
      DetectionType: 'DetectionType'
      MFAOperation: 'MFAOperation'
      PasswordOperation: 'PasswordOperation'
      TimeBetweenEvents: 'TimeBetweenEvents'
      IPCount: 'IPCount'
      DistinctIPs: 'DistinctIPs'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'AccountName'
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

output analyticsRuleId string = mfaTokenTheftRule.id
output analyticsRuleName string = mfaTokenTheftRule.name
