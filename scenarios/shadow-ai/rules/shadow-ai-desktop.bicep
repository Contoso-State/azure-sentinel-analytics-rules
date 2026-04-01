targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Minimum connection count to trigger alert')
param usageThreshold int = 3

@description('Lookback period in hours')
param timeWindowHours int = 1

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
param severity string = 'High'

@description('Enable or disable the analytics rule')
param enabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource shadowAiDesktopRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'shadow-ai-desktop-app')
  kind: 'Scheduled'
  properties: {
    displayName: 'Shadow AI Desktop Application Detection'
    description: 'Detects AI desktop applications (ChatGPT.exe, Claude.exe) communicating with AI API endpoints. Desktop apps are higher risk than browser usage: they persist across reboots, auto-start, bypass browser-based DLP/CASB, and create permanent data exfiltration channels. MITRE ATT&CK: T1219 (Remote Access Software), T1567 (Exfiltration Over Web Service).'
    severity: severity
    enabled: enabled
    query: 'let timeWindow = ${timeWindowHours}h;\nlet usageThreshold = ${usageThreshold};\nlet aiDesktopProcesses = dynamic(["ChatGPT.exe", "Claude.exe"]);\nlet aiAPIDomains = dynamic([\n    "api.openai.com", "chat.openai.com", "chatgpt.com", "cdn.oaistatic.com",\n    "api.anthropic.com", "claude.ai", "api.claude.ai"\n]);\nlet excludedUsers = split("${excludedUsers}", ",");\nDeviceNetworkEvents\n| where TimeGenerated > ago(timeWindow)\n| where ActionType == "ConnectionSuccess"\n| where InitiatingProcessFileName in~ (aiDesktopProcesses)\n| where RemoteUrl has_any (aiAPIDomains)\n    or RemoteUrl has "openai.com"\n    or RemoteUrl has "anthropic.com"\n    or RemoteUrl has "claude.ai"\n| where InitiatingProcessAccountUpn !in~ (excludedUsers)\n| where InitiatingProcessAccountUpn != ""\n| extend AIApplication = case(\n    InitiatingProcessFileName =~ "ChatGPT.exe", "ChatGPT Desktop",\n    InitiatingProcessFileName =~ "Claude.exe", "Claude Desktop",\n    "Unknown AI Desktop App"\n)\n| summarize\n    ConnectionCount = count(),\n    FirstSeen = min(TimeGenerated),\n    LastSeen = max(TimeGenerated),\n    TotalSentBytes = sum(tolong(column_ifexists("SentBytes", 0))),\n    TotalReceivedBytes = sum(tolong(column_ifexists("ReceivedBytes", 0))),\n    DistinctDomains = make_set(RemoteUrl, 10),\n    DistinctPorts = make_set(RemotePort, 5),\n    ProcessPaths = make_set(column_ifexists("InitiatingProcessFolderPath", ""), 3),\n    SHA256Hashes = make_set(column_ifexists("InitiatingProcessSHA256", ""), 3)\n  by\n    InitiatingProcessAccountUpn,\n    DeviceName,\n    AIApplication,\n    InitiatingProcessFileName,\n    bin(TimeGenerated, 1h)\n| where ConnectionCount >= usageThreshold\n| extend\n    DataSentMB = round(todouble(TotalSentBytes) / 1048576, 2),\n    DataReceivedMB = round(todouble(TotalReceivedBytes) / 1048576, 2)\n| extend\n    AccountName = InitiatingProcessAccountUpn,\n    HostName = DeviceName,\n    ProcessName = InitiatingProcessFileName\n| project\n    TimeGenerated,\n    AccountName,\n    HostName,\n    AIApplication,\n    ProcessName,\n    ConnectionCount,\n    DataSentMB,\n    DataReceivedMB,\n    FirstSeen,\n    LastSeen,\n    DistinctDomains,\n    DistinctPorts,\n    ProcessPaths,\n    SHA256Hashes\n| order by DataSentMB desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'CommandAndControl'
      'Exfiltration'
    ]
    techniques: [
      'T1219'
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
      alertDisplayNameFormat: 'Shadow AI Desktop App: {{AccountName}} running {{ProcessName}} ({{ConnectionCount}} connections)'
      alertDescriptionFormat: 'User {{AccountName}} on {{HostName}} is running {{AIApplication}} with {{ConnectionCount}} connections. Data sent: {{DataSentMB}} MB.'
    }
    customDetails: {
      AIApplication: 'AIApplication'
      ProcessName: 'ProcessName'
      ConnectionCount: 'ConnectionCount'
      DataSentMB: 'DataSentMB'
      DataReceivedMB: 'DataReceivedMB'
      SHA256Hashes: 'SHA256Hashes'
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
        entityType: 'Process'
        fieldMappings: [
          {
            identifier: 'ProcessId'
            columnName: 'ProcessName'
          }
        ]
      }
      {
        entityType: 'CloudApplication'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AIApplication'
          }
        ]
      }
    ]
  }
}

output analyticsRuleId string = shadowAiDesktopRule.id
output analyticsRuleName string = shadowAiDesktopRule.name
