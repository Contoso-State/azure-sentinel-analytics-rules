#!/usr/bin/env python3
"""
Build the Shadow AI Usage Monitor workbook ARM template.
Tracks AI usage across the enterprise correlating all Shadow AI detection rules.

Data sources:
  Tabs 1-4: SecurityAlert (pre-aggregated, fast)
  Tab 5:    DeviceNetworkEvents (live hunting, pre-alert visibility)

Run:   python3 build_shadow_ai_workbook.py
Output: shadow-ai-usage.json
Deploy: az deployment group create --resource-group <your-rg> \
          --template-file shadow-ai-usage.json
"""
import json

# =============================================================================
# HELPERS
# =============================================================================

def tile(name, query, title, viz, size=0, width=None,
         chart_settings=None, tile_settings=None):
    item = {
        "type": 3,
        "content": {
            "version": "KqlItem/1.0",
            "query": query,
            "size": size,
            "title": title,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": viz
        },
        "name": name
    }
    if width:
        item["customWidth"] = width
    if chart_settings:
        item["content"]["chartSettings"] = chart_settings
    if tile_settings:
        item["content"]["tileSettings"] = tile_settings
    return item


def md(name, text):
    return {"type": 1, "content": {"json": text}, "name": name}


def group(name, tab_value, children):
    return {
        "type": 12,
        "content": {
            "version": "NotebookGroup/1.0",
            "groupType": "editable",
            "items": children
        },
        "name": name,
        "conditionalVisibility": {
            "parameterName": "SelectedTab",
            "comparison": "isEqualTo",
            "value": tab_value
        }
    }


KPI_TILE_SETTINGS = {
    "titleContent": {"columnMatch": "Metric", "formatter": 1},
    "leftContent": {
        "columnMatch": "Value",
        "formatter": 12,
        "formatOptions": {"palette": "auto"}
    },
    "showBorder": True
}

# =============================================================================
# KQL QUERIES
# Note: {TimeRange} is a Sentinel workbook parameter -- not a Python format token.
# =============================================================================

# Shared filters
_ALL  = '(AlertName has "Shadow AI" or AlertName has "AI Agent")'
_WEB  = '(AlertName has "Shadow AI Browser" or AlertName has "Shadow AI.*Session")'
_DESK = 'AlertName has "Shadow AI Desktop"'
_AGT  = 'AlertName has "AI Agent"'

# Custom detail extraction snippet
_CD   = 'parse_json(tostring(parse_json(ExtendedProperties).["Custom Details"]))'

# Shadow AI domain list (reused in Tab 5)
_DOMAINS = '''dynamic([
    "openai.com", "chatgpt.com", "chat.openai.com",
    "anthropic.com", "claude.ai",
    "gemini.google.com", "generativelanguage.googleapis.com",
    "copilot.microsoft.com", "deepseek.com", "chat.deepseek.com",
    "perplexity.ai", "grok.com", "x.ai", "poe.com"
])'''

# -----------------------------------------------------------------------------
# Tab 1 -- Overview
# -----------------------------------------------------------------------------

Q_OVERVIEW_KPI = """
let alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where %s;
let kpi_alerts  = alerts
    | summarize v=count()
    | project Value=v, Metric="Total Alerts";
let kpi_users   = alerts
    | mv-expand parse_json(Entities)
    | where tostring(Entities.Type) == "account"
    | summarize v=dcount(tostring(Entities.Name))
    | project Value=v, Metric="Unique Users";
let kpi_devices = alerts
    | mv-expand parse_json(Entities)
    | where tostring(Entities.Type) == "host"
    | summarize v=dcount(tostring(Entities.HostName))
    | project Value=v, Metric="Unique Devices";
let kpi_apps    = alerts
    | mv-expand parse_json(Entities)
    | where tostring(Entities.Type) == "cloud-application"
    | summarize v=dcount(tostring(Entities.Name))
    | project Value=v, Metric="AI Apps Detected";
kpi_alerts | union kpi_users | union kpi_devices | union kpi_apps
""".strip() % _ALL

Q_OVERVIEW_TREND = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| summarize Count=count() by bin(TimeGenerated, 1h), AlertName
""".strip() % _ALL

Q_OVERVIEW_BY_RULE = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| summarize Count=count() by AlertName
| order by Count desc
""".strip() % _ALL

Q_OVERVIEW_APPS_PIE = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "cloud-application"
| extend AppName = tostring(Entities.Name)
| where isnotempty(AppName)
| summarize Count=count() by AppName
| order by Count desc
""".strip() % _ALL

Q_OVERVIEW_TOP_USERS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| summarize AlertCount=count() by User
| order by AlertCount desc
| take 10
""".strip() % _ALL

Q_OVERVIEW_RECENT = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Tactics
| order by TimeGenerated desc
| take 20
""".strip() % _ALL

# -----------------------------------------------------------------------------
# Tab 2 -- Shadow AI Web
# -----------------------------------------------------------------------------

Q_WEB_KPI = """
let alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where %s;
let kpi_alerts  = alerts
    | summarize v=count()
    | project Value=v, Metric="Web AI Alerts";
let kpi_users   = alerts
    | mv-expand parse_json(Entities)
    | where tostring(Entities.Type) == "account"
    | summarize v=dcount(tostring(Entities.Name))
    | project Value=v, Metric="Unique Users";
let kpi_devices = alerts
    | mv-expand parse_json(Entities)
    | where tostring(Entities.Type) == "host"
    | summarize v=dcount(tostring(Entities.HostName))
    | project Value=v, Metric="Unique Devices";
let kpi_conns = alerts
    | extend cd = %s
    | extend c = toint(cd.ConnectionCount[0])
    | summarize v=sum(c)
    | project Value=v, Metric="Total Connections";
kpi_alerts | union kpi_users | union kpi_devices | union kpi_conns
""".strip() % (_WEB, _CD)

Q_WEB_USER_APP = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend AIApp = tostring(cd.AIApplication[0])
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@" and isnotempty(AIApp)
| summarize AlertCount=count() by User, AIApp
| order by AlertCount desc
""".strip() % (_WEB, _CD)

Q_WEB_TIMELINE = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| summarize Count=count() by bin(TimeGenerated, 1h), User
""".strip() % _WEB

Q_WEB_PROCESSES = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where AlertName has "Session Attribution"
| extend cd = %s
| extend ProcessesUsed = tostring(cd.ProcessesUsed)
| where isnotempty(ProcessesUsed) and ProcessesUsed != "[]"
| project TimeGenerated, AlertName, ProcessesUsed
| order by TimeGenerated desc
| take 20
""".strip() % _CD

Q_WEB_DEVICES = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "host"
| extend Device = tostring(Entities.HostName)
| where isnotempty(Device)
| summarize AlertCount=count() by Device
| order by AlertCount desc
""".strip() % _WEB

Q_WEB_DETAIL = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend AIApp        = tostring(cd.AIApplication[0])
| extend ConnCount    = tostring(cd.ConnectionCount[0])
| extend LoggedOnUser = tostring(cd.LoggedOnUser[0])
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| project TimeGenerated, AlertName, User, AIApp, ConnCount, LoggedOnUser, AlertSeverity
| order by TimeGenerated desc
| take 25
""".strip() % (_WEB, _CD)

# -----------------------------------------------------------------------------
# Tab 3 -- Desktop Apps
# -----------------------------------------------------------------------------

Q_DESKTOP_KPI = """
let alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where %s;
let kpi_alerts = alerts
    | summarize v=count()
    | project Value=v, Metric="Desktop AI Alerts";
let kpi_apps = alerts
    | extend cd = %s
    | extend a = tostring(cd.AIApplication[0])
    | summarize v=dcount(a)
    | project Value=v, Metric="Desktop Apps Found";
let kpi_sent = alerts
    | extend cd = %s
    | extend s = todouble(cd.DataSentMB[0])
    | summarize v=toint(sum(s))
    | project Value=v, Metric="Total Sent (MB)";
let kpi_recv = alerts
    | extend cd = %s
    | extend r = todouble(cd.DataReceivedMB[0])
    | summarize v=toint(sum(r))
    | project Value=v, Metric="Total Received (MB)";
kpi_alerts | union kpi_apps | union kpi_sent | union kpi_recv
""".strip() % (_DESK, _CD, _CD, _CD)

Q_DESKTOP_VOLUME = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend DataSentMB     = todouble(cd.DataSentMB[0])
| extend DataReceivedMB = todouble(cd.DataReceivedMB[0])
| summarize SentMB=sum(DataSentMB), ReceivedMB=sum(DataReceivedMB)
    by bin(TimeGenerated, 1h)
""".strip() % (_DESK, _CD)

Q_DESKTOP_USER_VOLUME = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend DataSentMB = todouble(cd.DataSentMB[0])
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| summarize TotalSentMB=sum(DataSentMB) by User
| order by TotalSentMB desc
""".strip() % (_DESK, _CD)

Q_DESKTOP_HASHES = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend ProcessName  = tostring(cd.ProcessName[0])
| extend SHA256Hashes = tostring(cd.SHA256Hashes)
| extend ProcessPaths = tostring(cd.ProcessPaths)
| where isnotempty(ProcessName)
| project TimeGenerated, ProcessName, ProcessPaths, SHA256Hashes
| order by TimeGenerated desc
| take 20
""".strip() % (_DESK, _CD)

Q_DESKTOP_DETAIL = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend AIApp          = tostring(cd.AIApplication[0])
| extend ProcessName    = tostring(cd.ProcessName[0])
| extend DataSentMB     = tostring(cd.DataSentMB[0])
| extend DataReceivedMB = tostring(cd.DataReceivedMB[0])
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| project TimeGenerated, User, AIApp, ProcessName, DataSentMB, DataReceivedMB, AlertSeverity
| order by TimeGenerated desc
| take 25
""".strip() % (_DESK, _CD)

# -----------------------------------------------------------------------------
# Tab 4 -- AI Agent Activity
# -----------------------------------------------------------------------------

Q_AGENT_KPI = """
let alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where %s;
let kpi_alerts = alerts
    | summarize v=count()
    | project Value=v, Metric="Agent Alerts";
let kpi_writes = alerts
    | extend cd = %s
    | extend w = toint(cd.TotalWrites[0])
    | summarize v=sum(w)
    | project Value=v, Metric="Total Write Ops";
let kpi_graph = alerts
    | extend cd = %s
    | extend g = toint(cd.GraphWrites[0])
    | summarize v=sum(g)
    | project Value=v, Metric="Graph API Writes";
let kpi_entra = alerts
    | extend cd = %s
    | extend e = toint(cd.EntraChanges[0])
    | summarize v=sum(e)
    | project Value=v, Metric="Entra Changes";
kpi_alerts | union kpi_writes | union kpi_graph | union kpi_entra
""".strip() % (_AGT, _CD, _CD, _CD)

Q_AGENT_TREND = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend ARMWrites    = toint(cd.ARMWrites[0])
| extend GraphWrites  = toint(cd.GraphWrites[0])
| extend EntraChanges = toint(cd.EntraChanges[0])
| summarize ARMWrites=sum(ARMWrites), GraphWrites=sum(GraphWrites),
    EntraChanges=sum(EntraChanges) by bin(TimeGenerated, 1h)
""".strip() % (_AGT, _CD)

Q_AGENT_CALLERS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend TotalWrites = toint(cd.TotalWrites[0])
| mv-expand parse_json(Entities)
| where tostring(Entities.Type) == "account"
| extend User = strcat(tostring(Entities.Name), "@", tostring(Entities.UPNSuffix))
| where User != "@"
| summarize TotalWrites=sum(TotalWrites) by User
| order by TotalWrites desc
| take 10
""".strip() % (_AGT, _CD)

Q_AGENT_USERAGENTS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend UserAgents = tostring(cd.UserAgents)
| where isnotempty(UserAgents) and UserAgents != "[]"
| project TimeGenerated, UserAgents
| order by TimeGenerated desc
| take 20
""".strip() % (_AGT, _CD)

Q_AGENT_PROVIDERS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend ResourceProviders = tostring(cd.ResourceProviders)
| where isnotempty(ResourceProviders) and ResourceProviders != "[]"
| project TimeGenerated, ResourceProviders, AlertSeverity
| order by TimeGenerated desc
| take 20
""".strip() % (_AGT, _CD)

Q_AGENT_TARGETS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where %s
| extend cd = %s
| extend TargetUsers = tostring(cd.TargetUsers)
| where isnotempty(TargetUsers) and TargetUsers != "[]"
| project TimeGenerated, TargetUsers
| order by TimeGenerated desc
| take 20
""".strip() % (_AGT, _CD)

# -----------------------------------------------------------------------------
# Tab 5 -- Raw Connections (DeviceNetworkEvents)
# -----------------------------------------------------------------------------

_DOMAIN_FILTER = """let shadowAIDomains = %s;
DeviceNetworkEvents
| where TimeGenerated {TimeRange}
| where ActionType == "ConnectionSuccess"
| where RemoteUrl has_any (shadowAIDomains)""" % _DOMAINS

Q_RAW_TIMELINE = _DOMAIN_FILTER + """
| extend ShadowAIApp = case(
    RemoteUrl has "openai" or RemoteUrl has "chatgpt",          "ChatGPT",
    RemoteUrl has "claude" or RemoteUrl has "anthropic",        "Claude",
    RemoteUrl has "gemini" or RemoteUrl has "generativelanguage","Google Gemini",
    RemoteUrl has "copilot.microsoft",                          "Microsoft Copilot",
    RemoteUrl has "deepseek",                                   "DeepSeek",
    RemoteUrl has "perplexity",                                 "Perplexity",
    RemoteUrl has "grok" or RemoteUrl has "x.ai",              "Grok",
    RemoteUrl has "poe.com",                                    "Poe",
    "Other"
)
| summarize Count=count() by bin(TimeGenerated, 1h), ShadowAIApp"""

Q_RAW_BY_URL = _DOMAIN_FILTER + """
| summarize Count=count() by RemoteUrl
| order by Count desc
| take 15"""

Q_RAW_BY_DEVICE = _DOMAIN_FILTER + """
| summarize Count=count() by DeviceName
| order by Count desc"""

Q_RAW_TABLE = _DOMAIN_FILTER + """
| project TimeGenerated, DeviceName, RemoteUrl, RemoteIP,
    InitiatingProcessFileName, ActionType
| order by TimeGenerated desc
| take 100"""

# =============================================================================
# WORKBOOK STRUCTURE
# =============================================================================

HEADER = """# Shadow AI Usage Monitor

Track unauthorized AI application usage across the enterprise.
Correlates alerts from Shadow AI detection rules (browser, desktop, agent, session).

> **Rules:** Shadow AI Browser \u00b7 Desktop \u00b7 Agent Activity \u00b7 Session Attribution &nbsp;|&nbsp; **Sources:** SecurityAlert + DeviceNetworkEvents

---"""

params_panel = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            {
                "id": "a1a1a1a1-b2b2-c3c3-d4d4-e5e5e5e5e5e5",
                "version": "KqlParameterItem/1.0",
                "name": "TimeRange",
                "type": 4,
                "isRequired": True,
                "value": {"durationMs": 604800000},
                "typeSettings": {
                    "selectableValues": [
                        {"durationMs": 3600000},
                        {"durationMs": 14400000},
                        {"durationMs": 43200000},
                        {"durationMs": 86400000},
                        {"durationMs": 604800000},
                        {"durationMs": 2592000000}
                    ]
                }
            },
            {
                "id": "b2b2b2b2-c3c3-d4d4-e5e5-f6f6f6f6f6f6",
                "version": "KqlParameterItem/1.0",
                "name": "SelectedTab",
                "type": 1,
                "isRequired": False,
                "value": "overview",
                "isHiddenWhenLocked": True
            }
        ]
    },
    "name": "parameters"
}

tabs_selector = {
    "type": 11,
    "content": {
        "version": "LinkItem/1.0",
        "style": "tabs",
        "links": [
            {"id": "t1", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Overview",          "subTarget": "overview", "style": "link"},
            {"id": "t2", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Shadow AI Web",     "subTarget": "web",      "style": "link"},
            {"id": "t3", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Desktop Apps",      "subTarget": "desktop",  "style": "link"},
            {"id": "t4", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "AI Agent Activity", "subTarget": "agent",    "style": "link"},
            {"id": "t5", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Raw Connections",   "subTarget": "raw",      "style": "link"},
        ]
    },
    "name": "tabs"
}

# -- Tab 1: Overview --
tab_overview = group("grp-overview", "overview", [
    md("overview-hdr", "### Overview -- All Shadow AI Alerts"),
    tile("overview-kpi", Q_OVERVIEW_KPI, "Alert Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("overview-trend", Q_OVERVIEW_TREND, "Alert Trend by Rule (1h bins)", "timechart"),
    tile("overview-by-rule", Q_OVERVIEW_BY_RULE, "Alerts by Rule", "barchart", width="50"),
    tile("overview-apps-pie", Q_OVERVIEW_APPS_PIE, "AI Apps Detected", "piechart", width="50"),
    tile("overview-top-users", Q_OVERVIEW_TOP_USERS, "Top 10 Users by Alert Count", "barchart", width="50"),
    tile("overview-recent", Q_OVERVIEW_RECENT, "Recent Alerts", "table", width="50"),
])

# -- Tab 2: Shadow AI Web --
tab_web = group("grp-web", "web", [
    md("web-hdr", "### Shadow AI Web Access\n"
       "Browser-based connections to AI domains. Per-user attribution via session join."),
    tile("web-kpi", Q_WEB_KPI, "Web AI Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("web-user-app", Q_WEB_USER_APP, "User x AI Application", "table"),
    tile("web-timeline", Q_WEB_TIMELINE, "Alert Timeline by User", "timechart"),
    tile("web-devices", Q_WEB_DEVICES, "Alerts by Device", "barchart", width="50"),
    tile("web-processes", Q_WEB_PROCESSES,
         "Processes Used -- Session Attribution", "table", width="50"),
    tile("web-detail", Q_WEB_DETAIL, "Alert Detail", "table"),
])

# -- Tab 3: Desktop Apps --
tab_desktop = group("grp-desktop", "desktop", [
    md("desktop-hdr", "### Desktop AI Applications\n"
       "Installed AI desktop apps (ChatGPT.exe, Claude.exe) with data exfiltration volume metrics."),
    tile("desktop-kpi", Q_DESKTOP_KPI, "Desktop AI Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("desktop-volume", Q_DESKTOP_VOLUME,
         "Data Volume Over Time -- Sent vs Received (MB)", "timechart"),
    tile("desktop-user-vol", Q_DESKTOP_USER_VOLUME,
         "Data Sent by User (MB)", "barchart", width="50"),
    tile("desktop-hashes", Q_DESKTOP_HASHES,
         "Process & Hash Details", "table", width="50"),
    tile("desktop-detail", Q_DESKTOP_DETAIL, "Alert Detail", "table"),
])

# -- Tab 4: AI Agent Activity --
tab_agent = group("grp-agent", "agent", [
    md("agent-hdr", "### AI Agent Activity\n"
       "Programmatic AI agent calls via Azure Resource Manager, Microsoft Graph, and Entra ID."),
    tile("agent-kpi", Q_AGENT_KPI, "Agent Activity Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("agent-trend", Q_AGENT_TREND,
         "Write Operations Over Time -- ARM / Graph / Entra", "timechart"),
    tile("agent-callers", Q_AGENT_CALLERS,
         "Top Callers by Write Volume", "barchart", width="50"),
    tile("agent-useragents", Q_AGENT_USERAGENTS,
         "User Agent Fingerprints", "table", width="50"),
    tile("agent-providers", Q_AGENT_PROVIDERS,
         "Resource Providers Modified", "table", width="50"),
    tile("agent-targets", Q_AGENT_TARGETS,
         "Targeted Users", "table", width="50"),
])

# -- Tab 5: Raw Connections --
tab_raw = group("grp-raw", "raw", [
    md("raw-hdr", "### Raw Connections -- Live Hunting\n"
       "Direct `DeviceNetworkEvents` query -- shows pre-alert traffic and connections "
       "not yet captured by analytics rules. Requires MDE to Sentinel raw event streaming."),
    tile("raw-timeline", Q_RAW_TIMELINE,
         "AI Domain Connections Over Time", "timechart"),
    tile("raw-by-url", Q_RAW_BY_URL,
         "Connections by Remote URL", "barchart", width="50"),
    tile("raw-by-device", Q_RAW_BY_DEVICE,
         "Connections by Device", "barchart", width="50"),
    tile("raw-table", Q_RAW_TABLE, "Raw Connection Log", "table"),
])

# =============================================================================
# ASSEMBLE & WRITE ARM TEMPLATE
# =============================================================================

notebook = {
    "version": "Notebook/1.0",
    "items": [
        md("header", HEADER),
        params_panel,
        tabs_selector,
        tab_overview,
        tab_web,
        tab_desktop,
        tab_agent,
        tab_raw,
    ],
    "isLocked": False
}

arm_template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace": {
            "type": "string",
            "defaultValue": ""
        },
        "workbookDisplayName": {
            "type": "string",
            "defaultValue": "Shadow AI Usage Monitor"
        },
        "location": {
            "type": "string",
            "defaultValue": "[resourceGroup().location]"
        }
    },
    "variables": {
        "workbookId": "[guid('shadow-ai-usage-workbook-v1')]",
        "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]"
    },
    "resources": [
        {
            "type": "Microsoft.Insights/workbooks",
            "apiVersion": "2022-04-01",
            "name": "[variables('workbookId')]",
            "location": "[parameters('location')]",
            "kind": "shared",
            "properties": {
                "displayName": "[parameters('workbookDisplayName')]",
                "serializedData": json.dumps(notebook, ensure_ascii=False),
                "version": "1.0",
                "sourceId": "[variables('workspaceResourceId')]",
                "category": "sentinel"
            }
        }
    ]
}

OUTPUT = "shadow-ai-usage.json"
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(arm_template, f, indent=2, ensure_ascii=False)

print(f"Written: {OUTPUT}")
print(f"Tabs: Overview, Shadow AI Web, Desktop Apps, AI Agent Activity, Raw Connections")
print(f"Notebook items: {len(notebook['items'])}")
print()
print("Deploy:")
print("  az deployment group create \\")
print("    --resource-group <your-resource-group> \\")
print("    --template-file shadow-ai-usage.json")
