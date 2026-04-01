targetScope = 'resourceGroup'

@description('Deployment location for Sentinel analytics rule')
param location string

@description('Log Analytics workspace name (must already exist with Sentinel enabled)')
param workspaceName string

@description('Threshold for total write operations to trigger alert')
param writeThreshold int = 10

@description('Lookback period in hours')
param timeWindowHours int = 1

@description('Comma-separated list of excluded user accounts (UPNs)')
param excludedUsers string = ''

@description('Query frequency in ISO 8601 duration format')
param queryFrequency string = 'PT1H'

@description('Query period in ISO 8601 duration format')
param queryPeriod string = 'PT1H'

@description('Rule severity: High, Medium, Low, or Informational')
@allowed([
  'High'
  'Medium'
  'Low'
  'Informational'
])
param severity string = 'Informational'

@description('Enable or disable the analytics rule')
param enabled bool = true

resource workspace 'Microsoft.OperationalInsights/workspaces@2023-09-01' existing = {
  name: workspaceName
}

resource aiAgentActivityRule 'Microsoft.SecurityInsights/alertRules@2023-02-01' = {
  scope: workspace
  name: guid(workspace.id, 'ai-agent-graph-activity')
  kind: 'Scheduled'
  properties: {
    displayName: 'High-Volume AI Agent API Activity'
    description: 'Detects high-volume programmatic operations across Azure Resource Manager, Microsoft Graph API, and Entra ID that may indicate AI agent activity (Claude Code, automated scripts, az CLI). Correlates ARM deployments, Graph API writes, and Entra directory changes by caller identity. MITRE ATT&CK: T1059 (Command and Scripting Interpreter), T1565 (Data Manipulation).'
    severity: severity
    enabled: enabled
    query: 'let timeWindow = ${timeWindowHours}h;\nlet writeThreshold = ${writeThreshold};\nlet AgentUserAgents = dynamic([\n    "AZURECLI",\n    "python-requests",\n    "python-httpx",\n    "curl",\n    "PowerShell"\n]);\nlet excludedUsers = split("${excludedUsers}", ",");\nlet ARMOperations =\n    AzureActivity\n    | where TimeGenerated > ago(timeWindow)\n    | where CategoryValue == "Administrative"\n    | where ActivityStatusValue in ("Success", "Failure", "Start")\n    | where isnotempty(Caller)\n    | where Caller !in~ (excludedUsers)\n    | extend\n        OperationType = case(\n            OperationNameValue contains "WRITE", "Write",\n            OperationNameValue contains "DELETE", "Delete",\n            OperationNameValue contains "ACTION", "Action",\n            "Other"\n        ),\n        ResourceProvider = tostring(split(OperationNameValue, "/")[0])\n    | summarize\n        ARMOperationCount = count(),\n        ARMWriteCount = countif(OperationType == "Write"),\n        ARMDeleteCount = countif(OperationType == "Delete"),\n        ARMFailureCount = countif(ActivityStatusValue == "Failure"),\n        DistinctOperations = make_set(OperationNameValue, 50),\n        ResourceProviders = make_set(ResourceProvider, 20),\n        FirstOperation = min(TimeGenerated),\n        LastOperation = max(TimeGenerated)\n      by Caller, CallerIpAddress;\nlet GraphOperations =\n    MicrosoftGraphActivityLogs\n    | where TimeGenerated > ago(timeWindow)\n    | extend IsAgentUA = iff(UserAgent has_any (AgentUserAgents), true, false)\n    | summarize\n        GraphCallCount = count(),\n        GraphWriteCount = countif(RequestMethod in ("POST", "PUT", "PATCH", "DELETE")),\n        GraphFailCount = countif(ResponseStatusCode >= 400),\n        GraphAgentCalls = countif(IsAgentUA),\n        UserAgents = make_set(UserAgent, 20),\n        RequestMethods = make_set(RequestMethod, 10),\n        FirstGraphCall = min(TimeGenerated),\n        LastGraphCall = max(TimeGenerated)\n      by IPAddress;\nlet EntraChanges =\n    AuditLogs\n    | where TimeGenerated > ago(timeWindow)\n    | where Result == "success"\n    | where OperationName has_any (\n        "Update user", "Reset user password", "Enable account",\n        "Disable account", "Add member to role", "Remove member from role",\n        "Add service principal credentials", "Update service principal",\n        "Add app role assignment to service principal",\n        "Consent to application", "Add application",\n        "Update application", "Add service principal"\n    )\n    | extend ActorUPN = tostring(InitiatedBy.user.userPrincipalName)\n    | extend ActorIP = tostring(InitiatedBy.user.ipAddress)\n    | where ActorUPN !in~ (excludedUsers)\n    | summarize\n        EntraChangeCount = count(),\n        EntraOperations = make_set(OperationName, 20),\n        TargetUsers = make_set(tostring(TargetResources[0].userPrincipalName), 20),\n        FirstChange = min(TimeGenerated),\n        LastChange = max(TimeGenerated)\n      by ActorUPN, ActorIP;\nARMOperations\n| join kind=leftouter (GraphOperations) on $left.CallerIpAddress == $right.IPAddress\n| join kind=leftouter (EntraChanges) on $left.Caller == $right.ActorUPN\n| extend\n    TotalOperations = ARMOperationCount + coalesce(GraphCallCount, 0) + coalesce(EntraChangeCount, 0),\n    TotalWrites = ARMWriteCount + coalesce(GraphWriteCount, 0) + coalesce(EntraChangeCount, 0)\n| where TotalWrites >= writeThreshold\n| project\n    AccountName = Caller,\n    IPAddress = CallerIpAddress,\n    TotalOperations,\n    TotalWrites,\n    ARMWriteCount,\n    GraphWriteCount = coalesce(GraphWriteCount, 0),\n    EntraChangeCount = coalesce(EntraChangeCount, 0),\n    EntraOperations,\n    TargetUsers,\n    ResourceProviders,\n    UserAgents,\n    DistinctOperations,\n    FirstOperation,\n    LastOperation\n| order by TotalOperations desc'
    queryFrequency: queryFrequency
    queryPeriod: queryPeriod
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT1H'
    suppressionEnabled: false
    tactics: [
      'Execution'
      'Impact'
    ]
    techniques: [
      'T1059'
      'T1565'
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
      alertDisplayNameFormat: 'AI Agent Activity: {{AccountName}} performed {{TotalWrites}} write operations'
      alertDescriptionFormat: 'Account {{AccountName}} from {{IPAddress}} performed {{TotalWrites}} write operations across ARM, Graph API, and Entra ID.'
    }
    customDetails: {
      TotalWrites: 'TotalWrites'
      ARMWrites: 'ARMWriteCount'
      GraphWrites: 'GraphWriteCount'
      EntraChanges: 'EntraChangeCount'
      UserAgents: 'UserAgents'
      TargetUsers: 'TargetUsers'
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

output analyticsRuleId string = aiAgentActivityRule.id
output analyticsRuleName string = aiAgentActivityRule.name
