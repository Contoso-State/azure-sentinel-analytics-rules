targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Comma-separated UPNs to exclude from detection')
param excludedUsers string = ''

@description('Comma-separated app display names to exclude (e.g., "Microsoft Graph","Azure Portal")')
param excludedApps string = '"Microsoft Graph","Azure Portal","Microsoft Azure CLI"'

@description('Minimum sensitive permissions to trigger over-permissioned app detection')
param sensitivePermissionThreshold int = 3

@description('Minimum emails sent to trigger mass send detection')
param emailSendThreshold int = 5

@description('Window for email send spike detection in minutes')
param emailSendWindowMinutes int = 15

@description('Minimum service principal API calls to trigger bulk activity detection')
param spSignInThreshold int = 5

@description('Lookback period in hours for email/SP detection')
param lookbackPeriodHours int = 1

@description('Lookback period in days for permission grant detection')
param permissionLookbackDays int = 7

@description('Query frequency in ISO 8601 duration format')
param queryFrequency string = 'PT1H'

@description('Query period in ISO 8601 duration format')
param queryPeriod string = 'P7D'

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

resource overpermissionedAppRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'overpermissioned-app-abuse')
  kind: 'Scheduled'
  properties: {
    displayName: 'Over-Permissioned App Registration Abuse'
    description: 'Detects three attack patterns related to over-permissioned app registrations: (a) App with 3+ sensitive Graph API permissions (Mail.Send, User.Read.All, Files.ReadWrite.All, etc.) granted within the lookback window, (b) Sudden spike in email sends from a user account — indicates Mail.Send abuse from application context, (c) Service principal bulk API activity — indicates user enumeration or data exfiltration. MITRE ATT&CK: T1098.003 (Account Manipulation), T1114.002 (Remote Email Collection), T1566.002 (Spearphishing Link).'
    severity: severity
    enabled: enabled
    query: 'let lookback = ${lookbackPeriodHours}h;\nlet permissionLookback = ${permissionLookbackDays}d;\nlet sensitivePermissionThreshold = ${sensitivePermissionThreshold};\nlet emailSendThreshold = ${emailSendThreshold};\nlet emailSendWindow = ${emailSendWindowMinutes}m;\nlet spSignInThreshold = ${spSignInThreshold};\nlet ExcludedUPNs = dynamic([${excludedUsers}]);\nlet ExcludedApps = dynamic([${excludedApps}]);\nlet SensitivePermissions = dynamic(["Mail.Send", "Mail.Read", "Mail.ReadWrite", "User.Read.All", "User.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All", "Files.ReadWrite.All", "Sites.ReadWrite.All", "RoleManagement.ReadWrite.Directory"]);\nlet PermissionGrants = AuditLogs\n| where TimeGenerated > ago(permissionLookback)\n| where OperationName has "Add app role assignment to service principal"\n| extend TargetApp = tostring(TargetResources[0].displayName), TargetAppId = tostring(TargetResources[0].id)\n| mv-expand ModifiedProperty = TargetResources[0].modifiedProperties\n| extend PropertyNewValue = tostring(ModifiedProperty.newValue)\n| where PropertyNewValue has_any (SensitivePermissions)\n| summarize PermissionCount = dcount(PropertyNewValue), PermissionsGranted = make_set(PropertyNewValue, 20), FirstGrant = min(TimeGenerated), LastGrant = max(TimeGenerated), GrantedBy = take_any(tostring(InitiatedBy.user.userPrincipalName)) by TargetApp, TargetAppId\n| where PermissionCount >= sensitivePermissionThreshold;\nlet DetectionA = PermissionGrants\n| extend DetectionType = "Over_Permissioned_App", TimeGenerated = LastGrant, AccountName = GrantedBy, IPAddress = ""\n| project TimeGenerated, DetectionType, AppDisplayName = TargetApp, PermissionCount, PermissionsGranted, GrantedBy, AccountName, IPAddress;\nlet EmailSendSpike = OfficeActivity\n| where TimeGenerated > ago(lookback)\n| where Operation has "Send"\n| where UserId !in (ExcludedUPNs)\n| where not(UserId startswith "svc-")\n| summarize EmailCount = count(), UniqueRecipients = dcount(MailboxOwnerUPN), Recipients = make_set(MailboxOwnerUPN, 50), FirstSend = min(TimeGenerated), LastSend = max(TimeGenerated) by UserId, ClientIP, bin(TimeGenerated, emailSendWindow)\n| where EmailCount >= emailSendThreshold;\nlet DetectionB = EmailSendSpike\n| extend DetectionType = "Mass_Email_Send_Spike", TimeGenerated = FirstSend, AccountName = UserId, IPAddress = ClientIP\n| project TimeGenerated, DetectionType, AccountName, EmailCount, UniqueRecipients, Recipients, IPAddress;\nlet SPBulkActivity = AADServicePrincipalSignInLogs\n| where TimeGenerated > ago(lookback)\n| where ServicePrincipalName !in (ExcludedApps)\n| where ResultType == 0\n| summarize CallCount = count(), Resources = make_set(ResourceDisplayName, 10), UniqueResources = dcount(ResourceDisplayName), FirstCall = min(TimeGenerated), LastCall = max(TimeGenerated), IPs = make_set(IPAddress, 5) by ServicePrincipalName, ServicePrincipalId\n| where CallCount >= spSignInThreshold;\nlet DetectionC = SPBulkActivity\n| extend DetectionType = "SP_Bulk_API_Activity", TimeGenerated = FirstCall, AccountName = ServicePrincipalName, IPAddress = tostring(IPs[0])\n| project TimeGenerated, DetectionType, AccountName, CallCount, Resources, UniqueResources, IPAddress;\nunion DetectionA, DetectionB, DetectionC\n| project TimeGenerated, DetectionType, AccountName, IPAddress\n| order by TimeGenerated desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT2H'
    suppressionEnabled: false
    tactics: [
      'Persistence'
      'Collection'
      'InitialAccess'
    ]
    techniques: [
      'T1098'
      'T1114'
      'T1566'
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
      alertDisplayNameFormat: 'Over-Permissioned App Abuse: {{DetectionType}} — {{AccountName}}'
      alertDescriptionFormat: 'Detected {{DetectionType}} involving {{AccountName}}. This may indicate abuse of an over-permissioned app registration for email exfiltration, mass phishing, or tenant enumeration.'
      alertSeverityColumnName: null
    }
    customDetails: {
      DetectionType: 'DetectionType'
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

output analyticsRuleId string = overpermissionedAppRule.id
output analyticsRuleName string = overpermissionedAppRule.name
