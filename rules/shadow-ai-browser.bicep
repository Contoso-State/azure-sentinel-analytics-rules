targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Minimum connection count to trigger alert')
param usageThreshold int = 3

@description('Lookback period in hours')
param timeWindowHours int = 1

@description('Shadow AI domains to monitor (JSON array)')
param shadowAIDomains string = '["chat.openai.com","chatgpt.com","api.openai.com","cdn.oaistatic.com","claude.ai","api.anthropic.com","gemini.google.com","bard.google.com","generativelanguage.googleapis.com","copilot.microsoft.com","sydney.bing.com","edgeservices.bing.com","chat.deepseek.com","api.deepseek.com","perplexity.ai","www.perplexity.ai","grok.com","x.ai","poe.com","www.poe.com"]'

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

resource shadowAiBrowserRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'shadow-ai-browser-usage')
  kind: 'Scheduled'
  properties: {
    displayName: 'Shadow AI Browser Usage Detection'
    description: 'Detects employees accessing unauthorized AI applications (ChatGPT, Claude, Gemini, Copilot, DeepSeek, Perplexity, Grok, Poe) from managed endpoints via browser connections. MITRE ATT&CK: T1567 (Exfiltration Over Web Service).'
    severity: severity
    enabled: enabled
    query: 'let timeWindow = ${timeWindowHours}h;\nlet usageThreshold = ${usageThreshold};\nlet shadowAIDomains = dynamic(${shadowAIDomains});\nlet domainSuffix = "${domainSuffix}";\nlet excludedUsers = split("${excludedUsers}", ",");\nDeviceNetworkEvents\n| where TimeGenerated > ago(timeWindow)\n| where ActionType == "ConnectionSuccess"\n| where RemoteUrl has_any (shadowAIDomains)\n    or RemoteUrl has "openai.com"\n    or RemoteUrl has "anthropic.com"\n    or RemoteUrl has "gemini.google"\n    or RemoteUrl has "copilot.microsoft"\n    or RemoteUrl has "deepseek.com"\n    or RemoteUrl has "perplexity.ai"\n    or RemoteUrl has "grok.com"\n    or RemoteUrl has "poe.com"\n| extend ResolvedUpn = case(\n    InitiatingProcessAccountUpn != "",\n        InitiatingProcessAccountUpn,\n    InitiatingProcessAccountName !in ("", "system", "local service", "network service"),\n        strcat(InitiatingProcessAccountName, "@", domainSuffix),\n    ""\n)\n| where ResolvedUpn !in~ (excludedUsers)\n| where ResolvedUpn != ""\n| extend ShadowAIApp = case(\n    RemoteUrl has "openai" or RemoteUrl has "chatgpt", "ChatGPT",\n    RemoteUrl has "claude" or RemoteUrl has "anthropic", "Claude",\n    RemoteUrl has "gemini" or RemoteUrl has "bard" or RemoteUrl has "generativelanguage.googleapis", "Google Gemini",\n    RemoteUrl has "copilot.microsoft" or RemoteUrl has "sydney.bing" or RemoteUrl has "edgeservices.bing", "Microsoft Copilot",\n    RemoteUrl has "deepseek", "DeepSeek",\n    RemoteUrl has "perplexity", "Perplexity",\n    RemoteUrl has "grok" or RemoteUrl has "x.ai", "Grok",\n    RemoteUrl has "poe.com", "Poe",\n    "Unknown AI App"\n)\n| summarize\n    ConnectionCount = count(),\n    FirstSeen = min(TimeGenerated),\n    LastSeen = max(TimeGenerated),\n    DomainsAccessed = make_set(RemoteUrl, 10),\n    DistinctPorts = make_set(RemotePort, 5)\n  by\n    ResolvedUpn,\n    DeviceName,\n    ShadowAIApp\n| where ConnectionCount >= usageThreshold\n| extend\n    AccountName = ResolvedUpn,\n    HostName = DeviceName,\n    TimeGenerated = FirstSeen\n| project\n    TimeGenerated,\n    AccountName,\n    HostName,\n    ShadowAIApp,\n    ConnectionCount,\n    FirstSeen,\n    LastSeen,\n    DomainsAccessed,\n    DistinctPorts\n| order by ConnectionCount desc'
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
      alertDisplayNameFormat: 'Shadow AI Usage: {{AccountName}} accessed {{ShadowAIApp}} ({{ConnectionCount}} connections)'
      alertDescriptionFormat: 'User {{AccountName}} on {{HostName}} made {{ConnectionCount}} connections to {{ShadowAIApp}}. First seen: {{FirstSeen}}.'
    }
    customDetails: {
      AIApplication: 'ShadowAIApp'
      ConnectionCount: 'ConnectionCount'
      DomainsAccessed: 'DomainsAccessed'
      FirstSeen: 'FirstSeen'
      LastSeen: 'LastSeen'
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

output analyticsRuleId string = shadowAiBrowserRule.id
output analyticsRuleName string = shadowAiBrowserRule.name
