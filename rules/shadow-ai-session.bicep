targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Minimum connection count to trigger alert')
param usageThreshold int = 1

@description('Lookback period in hours')
param timeWindowHours int = 1

@description('UPN domain suffix for SAM-to-UPN fallback resolution')
param domainSuffix string = 'contoso.com'

@description('Comma-separated list of excluded user accounts (UPNs)')
param excludedUsers string = ''

@description('Query frequency in ISO 8601 duration format')
param queryFrequency string = 'PT15M'

@description('Query period in ISO 8601 duration format')
param queryPeriod string = 'PT1H'

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

resource shadowAiSessionRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'shadow-ai-session-attribution')
  kind: 'Scheduled'
  properties: {
    displayName: 'Shadow AI Usage with Session Attribution'
    description: 'Detects Shadow AI usage with reliable per-user attribution via DeviceInfo.LoggedOnUsers join. Solves the SYSTEM-context gap where InitiatingProcessAccountUpn is empty for background processes. Uses SigninLogs lookup to resolve SAM names to real UPNs. MITRE ATT&CK: T1567 (Exfiltration Over Web Service).'
    severity: severity
    enabled: enabled
    query: 'let domainSuffix = "${domainSuffix}";\nlet excludedUsers = split("${excludedUsers}", ",");\nlet upnLookup = SigninLogs\n    | where TimeGenerated > ago(14d)\n    | summarize arg_max(TimeGenerated, UserPrincipalName) by UserId\n    | extend SAMKey = tolower(replace_string(tostring(split(UserPrincipalName, "@")[0]), ".", ""))\n    | project SAMKey, RealUPN = UserPrincipalName;\nlet timeWindow = ${timeWindowHours}h;\nlet usageThreshold = ${usageThreshold};\nlet shadowAIDomains = dynamic([\n    "openai.com", "chatgpt.com", "chat.openai.com",\n    "anthropic.com", "claude.ai",\n    "gemini.google.com", "generativelanguage.googleapis.com",\n    "copilot.microsoft.com",\n    "deepseek.com", "chat.deepseek.com",\n    "perplexity.ai",\n    "grok.com", "x.ai",\n    "poe.com"\n]);\nDeviceNetworkEvents\n| where TimeGenerated > ago(timeWindow)\n| where ActionType == "ConnectionSuccess"\n| where RemoteUrl has_any (shadowAIDomains)\n| join kind=leftouter (\n    DeviceInfo\n    | where TimeGenerated > ago(timeWindow)\n    | mv-expand todynamic(LoggedOnUsers)\n    | extend LoggedOnUser = tostring(LoggedOnUsers.UserName)\n    | where LoggedOnUser != ""\n    | summarize arg_max(TimeGenerated, LoggedOnUser) by DeviceName\n) on DeviceName\n| where LoggedOnUser !in ("", "system", "local service", "network service")\n| extend SAMKey = tolower(LoggedOnUser)\n| lookup upnLookup on SAMKey\n| extend ResolvedUpn = coalesce(RealUPN, strcat(LoggedOnUser, "@", domainSuffix))\n| where ResolvedUpn !in~ (excludedUsers)\n| where ResolvedUpn != ""\n| extend ShadowAIApp = case(\n    RemoteUrl has "openai" or RemoteUrl has "chatgpt",          "ChatGPT",\n    RemoteUrl has "claude" or RemoteUrl has "anthropic",        "Claude",\n    RemoteUrl has "gemini" or RemoteUrl has "generativelanguage","Google Gemini",\n    RemoteUrl has "copilot.microsoft",                          "Microsoft Copilot",\n    RemoteUrl has "deepseek",                                   "DeepSeek",\n    RemoteUrl has "perplexity",                                 "Perplexity",\n    RemoteUrl has "grok" or RemoteUrl has "x.ai",              "Grok",\n    RemoteUrl has "poe.com",                                    "Poe",\n    "Unknown AI App"\n)\n| summarize\n    ConnectionCount   = count(),\n    FirstSeen         = min(TimeGenerated),\n    LastSeen          = max(TimeGenerated),\n    DistinctUrls      = make_set(RemoteUrl, 10),\n    DistinctIPs       = make_set(RemoteIP, 10),\n    DistinctProcesses = make_set(InitiatingProcessFileName, 5)\n  by\n    ResolvedUpn,\n    LoggedOnUser,\n    DeviceName,\n    ShadowAIApp\n| where ConnectionCount >= usageThreshold\n| extend\n    LoggedOnUserName = tostring(split(ResolvedUpn, "@")[0]),\n    UPNSuffix        = tostring(split(ResolvedUpn, "@")[1]),\n    AccountName      = ResolvedUpn,\n    HostName         = DeviceName,\n    TimeGenerated    = FirstSeen\n| project\n    TimeGenerated,\n    AccountName,\n    LoggedOnUserName,\n    UPNSuffix,\n    HostName,\n    LoggedOnUser,\n    ShadowAIApp,\n    ConnectionCount,\n    FirstSeen,\n    LastSeen,\n    DistinctUrls,\n    DistinctIPs,\n    DistinctProcesses\n| order by ConnectionCount desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Exfiltration'
      'Collection'
    ]
    techniques: [
      'T1567'
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
          'Host'
        ]
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'AlertPerResult'
    }
    alertDetailsOverride: {
      alertDisplayNameFormat: 'Shadow AI Session: {{LoggedOnUserName}} accessed {{ShadowAIApp}} ({{ConnectionCount}} connections)'
      alertDescriptionFormat: 'User {{AccountName}} (session user: {{LoggedOnUser}}) on {{HostName}} made {{ConnectionCount}} connections to {{ShadowAIApp}}.'
    }
    customDetails: {
      AIApplication: 'ShadowAIApp'
      ConnectionCount: 'ConnectionCount'
      LoggedOnUser: 'LoggedOnUser'
      ProcessesUsed: 'DistinctProcesses'
      FirstSeen: 'FirstSeen'
    }
    entityMappings: [
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'LoggedOnUserName'
          }
          {
            identifier: 'UPNSuffix'
            columnName: 'UPNSuffix'
          }
        ]
      }
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'FullName'
            columnName: 'HostName'
          }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'ShadowAIApp'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = shadowAiSessionRule.id
output analyticsRuleName string = shadowAiSessionRule.name
