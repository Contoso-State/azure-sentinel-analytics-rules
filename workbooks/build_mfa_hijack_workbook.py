#!/usr/bin/env python3
"""
Build the MFA Hijacking Detection workbook ARM template.
Tracks MFA method changes, password resets, and sign-in anomalies
to detect AiTM phishing and account takeover attacks.

Data sources:
  Tabs 1-3: AuditLogs, SigninLogs (raw log queries)
  Tab 4:    Correlated attack timeline (AuditLogs + SigninLogs + SecurityAlert)

Run:   python3 build_mfa_hijack_workbook.py
Output: mfa-hijack-detection.json
Deploy: az deployment group create --resource-group <your-rg> \
          --template-file mfa-hijack-detection.json
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
# SHARED KQL FRAGMENTS
# =============================================================================

_MFA_OPS = """dynamic([
    "User registered security info",
    "User deleted security info",
    "User changed default security info method",
    "Admin registered security info",
    "Admin deleted security info",
    "Admin updated security info"
])"""

_PWD_OPS = """dynamic([
    "Reset password (by admin)",
    "Reset user password",
    "Change user password",
    "Change password",
    "Reset password"
])"""

# =============================================================================
# TAB 1 — Overview
# =============================================================================

Q_OVERVIEW_KPI = f"""
let mfaOps = {_MFA_OPS};
let pwdOps = {_PWD_OPS};
let mfa = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps);
let pwd = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps);
let alerts = SecurityAlert
| where TimeGenerated {{TimeRange}}
| where AlertName has "MFA";
let kpi_mfa = mfa | summarize v=count() | project Value=v, Metric="MFA Changes";
let kpi_pwd = pwd | summarize v=count() | project Value=v, Metric="Password Resets";
let kpi_users = mfa
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| summarize v=dcount(TargetUPN) | project Value=v, Metric="Affected Users";
let kpi_incidents = alerts | summarize v=dcount(SystemAlertId) | project Value=v, Metric="MFA Alerts";
kpi_mfa | union kpi_pwd | union kpi_users | union kpi_incidents
""".strip()

Q_OVERVIEW_TREND = f"""
let mfaOps = {_MFA_OPS};
let pwdOps = {_PWD_OPS};
let mfa = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| extend EventType = "MFA Change";
let pwd = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps)
| extend EventType = "Password Reset";
mfa | union pwd
| summarize Count=count() by bin(TimeGenerated, 1h), EventType
""".strip()

Q_OVERVIEW_ALERTS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where AlertName has "MFA"
| project TimeGenerated, AlertName, AlertSeverity, CompromisedEntity, Status
| order by TimeGenerated desc
| take 20
""".strip()

# =============================================================================
# TAB 2 — MFA Method Changes
# =============================================================================

Q_MFA_TIMELINE = f"""
let mfaOps = {_MFA_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| summarize Count=count() by bin(TimeGenerated, 1h), OperationName
""".strip()

Q_MFA_TABLE = f"""
let mfaOps = {_MFA_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedByUPN = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, TargetUPN, InitiatedByUPN, InitiatedByIP, Result
| order by TimeGenerated desc
| take 50
""".strip()

Q_MFA_BY_USER = f"""
let mfaOps = {_MFA_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| summarize Count=count() by TargetUPN
| order by Count desc
| take 10
""".strip()

Q_MFA_BY_OPERATION = f"""
let mfaOps = {_MFA_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| summarize Count=count() by OperationName
| order by Count desc
""".strip()

# =============================================================================
# TAB 3 — Password Resets
# =============================================================================

Q_PWD_TIMELINE = f"""
let pwdOps = {_PWD_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps)
| summarize Count=count() by bin(TimeGenerated, 1h), OperationName
""".strip()

Q_PWD_TABLE = f"""
let pwdOps = {_PWD_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedByUPN = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, TargetUPN, InitiatedByUPN, InitiatedByIP, Result
| order by TimeGenerated desc
| take 50
""".strip()

Q_PWD_BY_USER = f"""
let pwdOps = {_PWD_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| summarize Count=count() by TargetUPN
| order by Count desc
| take 10
""".strip()

# =============================================================================
# TAB 4 — Attack Timeline
# =============================================================================

Q_ATTACK_CORRELATION = f"""
let mfaOps = {_MFA_OPS};
let pwdOps = {_PWD_OPS};
let MFA = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| project MFATime=TimeGenerated, TargetUPN, MFAOp=OperationName,
    MFAInitiatedBy=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName));
let PWD = AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (pwdOps)
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| project PwdTime=TimeGenerated, TargetUPN, PwdOp=OperationName,
    PwdInitiatedBy=coalesce(tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayName));
MFA | join kind=inner (PWD) on TargetUPN
| where abs(datetime_diff('minute', PwdTime, MFATime)) <= 30
| project TargetUPN, MFATime, MFAOp, MFAInitiatedBy, PwdTime, PwdOp, PwdInitiatedBy,
    TimeDelta=iff(PwdTime > MFATime, PwdTime - MFATime, MFATime - PwdTime)
| order by MFATime desc
| take 25
""".strip()

Q_TARGET_SIGNINS = """
SigninLogs
| where TimeGenerated {TimeRange}
| where UserPrincipalName == "{TargetUser}"
| project TimeGenerated, IPAddress, AppDisplayName, ResultType,
    AuthenticationRequirement, ClientAppUsed, UserAgent
| order by TimeGenerated desc
| take 30
""".strip()

Q_TARGET_SIGNIN_IPS = """
SigninLogs
| where TimeGenerated {TimeRange}
| where UserPrincipalName == "{TargetUser}"
| where ResultType == 0
| summarize
    SignInCount=count(),
    Apps=make_set(AppDisplayName, 5),
    FirstSeen=min(TimeGenerated),
    LastSeen=max(TimeGenerated)
  by IPAddress
| order by SignInCount desc
""".strip()

Q_TARGET_AUDIT = f"""
let mfaOps = {_MFA_OPS};
let pwdOps = {_PWD_OPS};
AuditLogs
| where TimeGenerated {{TimeRange}}
| where OperationName has_any (mfaOps) or OperationName has_any (pwdOps)
    or OperationName has "Disable account" or OperationName has "Enable account"
    or OperationName has "Add member to role" or OperationName has "Consent to application"
| extend TargetUPN = tostring(TargetResources[0].userPrincipalName)
| where TargetUPN == "{{TargetUser}}"
| extend InitiatedByUPN = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| extend InitiatedByIP = tostring(InitiatedBy.user.ipAddress)
| project TimeGenerated, OperationName, InitiatedByUPN, InitiatedByIP, Result
| order by TimeGenerated desc
| take 30
""".strip()

# =============================================================================
# TAB 5 — App Registration Abuse
# =============================================================================

Q_APP_KPI = """
let appOps = AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any (
    "Add app role assignment to service principal",
    "Consent to application",
    "Add service principal credentials",
    "Update service principal",
    "Add application",
    "Update application",
    "Add service principal",
    "Add delegated permission grant"
);
let kpi_ops = appOps | summarize v=count() | project Value=v, Metric="App Operations";
let kpi_apps = appOps
| extend AppName = tostring(TargetResources[0].displayName)
| summarize v=dcount(AppName) | project Value=v, Metric="Apps Modified";
let kpi_perms = appOps
| where OperationName has "app role assignment" or OperationName has "permission"
| summarize v=count() | project Value=v, Metric="Permission Grants";
let kpi_creds = appOps
| where OperationName has "credentials"
| summarize v=count() | project Value=v, Metric="Credential Additions";
kpi_ops | union kpi_apps | union kpi_perms | union kpi_creds
""".strip()

Q_APP_TIMELINE = """
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any (
    "Add app role assignment to service principal",
    "Consent to application",
    "Add service principal credentials",
    "Update service principal",
    "Add application",
    "Update application",
    "Add service principal",
    "Add delegated permission grant"
)
| summarize Count=count() by bin(TimeGenerated, 1h), OperationName
""".strip()

Q_APP_BY_APP = """
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any (
    "Add app role assignment to service principal",
    "Consent to application",
    "Add service principal credentials",
    "Update service principal",
    "Add application",
    "Update application",
    "Add service principal",
    "Add delegated permission grant"
)
| extend AppName = tostring(TargetResources[0].displayName)
| where isnotempty(AppName)
| summarize Operations=count(), OpTypes=make_set(OperationName, 10) by AppName
| order by Operations desc
""".strip()

Q_APP_PERMISSIONS = """
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has "Add app role assignment to service principal"
    or OperationName has "Add delegated permission grant"
    or OperationName has "Consent to application"
| extend AppName = tostring(TargetResources[0].displayName)
| extend InitiatedBy = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, AppName, InitiatedBy, Result
| order by TimeGenerated desc
| take 30
""".strip()

Q_APP_MONITORED = """
let monitoredAppId = "{AppIdFilter}";
let auditActivity = AuditLogs
| where TimeGenerated {TimeRange}
| where InitiatedBy.app.appId == monitoredAppId
    or tostring(TargetResources[0].id) == monitoredAppId
| extend Source = "AuditLogs"
| extend Operation = OperationName
| extend Detail = tostring(TargetResources[0].userPrincipalName)
| extend InitiatedBy = coalesce(
    tostring(InitiatedBy.app.displayName),
    tostring(InitiatedBy.user.userPrincipalName))
| project TimeGenerated, Source, Operation, Detail, InitiatedBy;
let graphActivity = MicrosoftGraphActivityLogs
| where TimeGenerated {TimeRange}
| where AppId == monitoredAppId
| extend Source = "GraphAPI"
| extend Operation = strcat(RequestMethod, " ", tostring(split(RequestUri, "?")[0]))
| extend Detail = strcat("HTTP ", ResponseStatusCode)
| extend InitiatedBy = "Monitored Application"
| project TimeGenerated, Source, Operation, Detail, InitiatedBy;
auditActivity | union graphActivity
| order by TimeGenerated desc
| take 40
""".strip()

Q_APP_MAIL_SEND = """
OfficeActivity
| where TimeGenerated {TimeRange}
| where Operation == "Send" or Operation == "SendAs" or Operation == "SendOnBehalf"
| extend SenderApp = tostring(parse_json(tostring(ExtendedProperties))[0].Value)
| project TimeGenerated, Operation, UserId, ClientInfoString, ResultStatus
| order by TimeGenerated desc
| take 25
""".strip()

Q_APP_GRAPH_API = """
MicrosoftGraphActivityLogs
| where TimeGenerated {TimeRange}
| extend RequestPath = tostring(split(RequestUri, "?")[0])
| where RequestPath has "/users" or RequestPath has "/servicePrincipals"
    or RequestPath has "/sendMail" or RequestPath has "/messages"
    or RequestPath has "/authentication" or RequestPath has "/mailFolders"
| summarize
    CallCount=count(),
    WriteCalls=countif(RequestMethod in ("POST","PUT","PATCH","DELETE")),
    FailedCalls=countif(ResponseStatusCode >= 400)
  by RequestMethod, RequestPath, ResponseStatusCode, UserAgent, IPAddress
| order by CallCount desc
| take 30
""".strip()

Q_APP_GRAPH_TIMELINE = """
MicrosoftGraphActivityLogs
| where TimeGenerated {TimeRange}
| extend RequestPath = tostring(split(RequestUri, "?")[0])
| where RequestPath has "/users" or RequestPath has "/servicePrincipals"
    or RequestPath has "/sendMail" or RequestPath has "/messages"
    or RequestPath has "/authentication" or RequestPath has "/mailFolders"
| extend CallType = case(
    RequestPath has "sendMail", "Mail.Send",
    RequestPath has "messages" or RequestPath has "mailFolders", "Mail.Read",
    RequestPath has "authentication", "MFA Methods",
    RequestPath has "servicePrincipals", "App Enumeration",
    RequestPath has "/users", "User Enumeration",
    "Other"
)
| summarize Count=count() by bin(TimeGenerated, 1h), CallType
""".strip()

Q_APP_GRAPH_DETAIL = """
MicrosoftGraphActivityLogs
| where TimeGenerated {TimeRange}
| extend RequestPath = tostring(split(RequestUri, "?")[0])
| where RequestPath has "/users" or RequestPath has "/servicePrincipals"
    or RequestPath has "/sendMail" or RequestPath has "/messages"
    or RequestPath has "/authentication" or RequestPath has "/mailFolders"
| project TimeGenerated, RequestMethod, RequestPath, ResponseStatusCode,
    UserAgent, IPAddress
| order by TimeGenerated desc
| take 50
""".strip()

Q_APP_ALL_REGISTRATIONS = """
AuditLogs
| where TimeGenerated {TimeRange}
| where OperationName has_any (
    "Add application",
    "Update application",
    "Add service principal",
    "Update service principal",
    "Add service principal credentials",
    "Remove service principal credentials",
    "Add app role assignment to service principal",
    "Consent to application",
    "Add delegated permission grant",
    "Add owner to application"
)
| extend AppName = tostring(TargetResources[0].displayName)
| extend InitiatedBy = coalesce(
    tostring(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.app.displayName))
| project TimeGenerated, OperationName, AppName, InitiatedBy, Result
| order by TimeGenerated desc
| take 50
""".strip()

# =============================================================================
# WORKBOOK STRUCTURE
# =============================================================================

HEADER = """# MFA Hijacking Detection

Tracks MFA method changes, password resets, and sign-in anomalies to detect
AiTM phishing and account takeover attacks.

> **Workspace:** your-sentinel-workspace &nbsp;|&nbsp; **Sources:** AuditLogs + SigninLogs + SecurityAlert

---"""

ATTACK_HEADER = """### Attack Timeline — Correlated MFA Hijack Investigation

Correlated view of AiTM phishing attacks against a target user account.
Set the **Target User UPN** parameter above to filter sign-in and audit data for a specific user.

**Attack chain:** Phishing email with AiTM proxy link → Session token capture →
MFA method hijack (attacker registers new authentication method) → Password reset → Full account takeover.

**Detection signature:** MFA method change + password reset on the same account within 30 minutes.
Look for unfamiliar IPs in the sign-in data that may indicate attacker infrastructure.

---"""

params_panel = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            {
                "id": "c1c1c1c1-d2d2-e3e3-f4f4-a5a5a5a5a5a5",
                "version": "KqlParameterItem/1.0",
                "name": "TimeRange",
                "type": 4,
                "isRequired": True,
                "value": {"durationMs": 86400000},
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
                "id": "d2d2d2d2-e3e3-f4f4-a5a5-b6b6b6b6b6b6",
                "version": "KqlParameterItem/1.0",
                "name": "SelectedTab",
                "type": 1,
                "isRequired": False,
                "value": "overview",
                "isHiddenWhenLocked": True
            },
            {
                "id": "e3e3e3e3-f4f4-a5a5-b6b6-c7c7c7c7c7c7",
                "version": "KqlParameterItem/1.0",
                "name": "TargetUser",
                "label": "Target User UPN",
                "type": 1,
                "isRequired": False,
                "value": ""
            },
            {
                "id": "f4f4f4f4-a5a5-b6b6-c7c7-d8d8d8d8d8d8",
                "version": "KqlParameterItem/1.0",
                "name": "AppIdFilter",
                "label": "App ID to Monitor",
                "type": 1,
                "isRequired": False,
                "value": ""
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
             "linkLabel": "Overview",          "subTarget": "overview",  "style": "link"},
            {"id": "t2", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "MFA Changes",       "subTarget": "mfa",      "style": "link"},
            {"id": "t3", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Password Resets",   "subTarget": "password",  "style": "link"},
            {"id": "t4", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Attack Timeline",   "subTarget": "attack",    "style": "link"},
            {"id": "t5", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "App Registration Abuse", "subTarget": "appabuse", "style": "link"},
        ]
    },
    "name": "tabs"
}

# -- Tab 1: Overview ----------------------------------------------------------
tab_overview = group("grp-overview", "overview", [
    md("overview-hdr", "### Overview — MFA & Password Activity"),
    tile("overview-kpi", Q_OVERVIEW_KPI, "Activity Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("overview-trend", Q_OVERVIEW_TREND,
         "MFA Changes vs Password Resets Over Time", "timechart"),
    tile("overview-alerts", Q_OVERVIEW_ALERTS,
         "Recent MFA-Related Alerts", "table"),
])

# -- Tab 2: MFA Method Changes ------------------------------------------------
tab_mfa = group("grp-mfa", "mfa", [
    md("mfa-hdr", "### MFA Method Changes\n"
       "All MFA registration, deletion, and modification events from AuditLogs."),
    tile("mfa-timeline", Q_MFA_TIMELINE,
         "MFA Operations Over Time", "timechart"),
    tile("mfa-by-user", Q_MFA_BY_USER,
         "MFA Changes by Target User", "barchart", width="50"),
    tile("mfa-by-op", Q_MFA_BY_OPERATION,
         "MFA Changes by Operation Type", "piechart", width="50"),
    tile("mfa-table", Q_MFA_TABLE,
         "MFA Change Detail Log", "table"),
])

# -- Tab 3: Password Resets ---------------------------------------------------
tab_password = group("grp-password", "password", [
    md("pwd-hdr", "### Password Resets\n"
       "All password reset and change events from AuditLogs. "
       "Watch for resets initiated by apps (client_credentials) vs self-service."),
    tile("pwd-timeline", Q_PWD_TIMELINE,
         "Password Resets Over Time", "timechart"),
    tile("pwd-by-user", Q_PWD_BY_USER,
         "Password Resets by Target User", "barchart", width="50"),
    tile("pwd-table", Q_PWD_TABLE,
         "Password Reset Detail Log", "table"),
])

# -- Tab 4: Attack Timeline ---------------------------------------------------
tab_attack = group("grp-attack", "attack", [
    md("attack-hdr", ATTACK_HEADER),
    tile("attack-correlation", Q_ATTACK_CORRELATION,
         "Correlated MFA + Password Events (30-min window)", "table"),
    tile("target-ips", Q_TARGET_SIGNIN_IPS,
         "Target User — Sign-In IPs (look for unfamiliar IPs)", "table"),
    tile("target-signins", Q_TARGET_SIGNINS,
         "Target User — Recent Sign-Ins", "table"),
    tile("target-audit", Q_TARGET_AUDIT,
         "Target User — Security Operations Timeline", "table"),
])

# -- Tab 5: App Registration Abuse ---------------------------------------------
APP_HEADER = """### App Registration Abuse

Tracks all app registration activity across the tenant: permission grants, credential additions,
consent operations, and email sends via application permissions.

**Focus:** Use the **App ID to Monitor** parameter above to track a specific application.

---"""

tab_appabuse = group("grp-appabuse", "appabuse", [
    md("app-hdr", APP_HEADER),
    tile("app-kpi", Q_APP_KPI, "App Registration Activity", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),
    tile("app-timeline", Q_APP_TIMELINE,
         "App Operations Over Time", "timechart"),
    tile("app-by-app", Q_APP_BY_APP,
         "Activity by Application", "barchart", width="50"),
    tile("app-permissions", Q_APP_PERMISSIONS,
         "Permission Grants & Consent", "table", width="50"),
    tile("app-monitored", Q_APP_MONITORED,
         "Monitored Application — All Activity", "table"),
    md("graph-hdr", "### Graph API Activity\nReal-time view of Microsoft Graph API calls — "
       "shows enumeration activity including User.Read.All, Mail.Send, and service principal queries."),
    tile("app-graph-timeline", Q_APP_GRAPH_TIMELINE,
         "Graph API Calls Over Time by Type", "timechart"),
    tile("app-graph-summary", Q_APP_GRAPH_API,
         "Graph API Call Summary", "table", width="50"),
    tile("app-mail-send", Q_APP_MAIL_SEND,
         "Email Sends via Application Context (Mail.Send)", "table", width="50"),
    tile("app-graph-detail", Q_APP_GRAPH_DETAIL,
         "Graph API Call Detail Log", "table"),
    tile("app-all", Q_APP_ALL_REGISTRATIONS,
         "All App Registration Operations (Tenant-Wide)", "table"),
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
        tab_mfa,
        tab_password,
        tab_attack,
        tab_appabuse,
    ],
    "isLocked": False
}

arm_template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace": {
            "type": "string",
            "defaultValue": "your-sentinel-workspace"
        },
        "workbookDisplayName": {
            "type": "string",
            "defaultValue": "MFA Hijacking Detection"
        },
        "location": {
            "type": "string",
            "defaultValue": "[resourceGroup().location]"
        }
    },
    "variables": {
        "workbookId": "[guid('mfa-hijack-detection-workbook-v1')]",
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

OUTPUT = "mfa-hijack-detection.json"
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(arm_template, f, indent=2, ensure_ascii=False)

print(f"Written: {OUTPUT}")
print(f"Tabs: Overview, MFA Changes, Password Resets, Attack Timeline, App Registration Abuse")
print(f"Notebook items: {len(notebook['items'])}")
print()
print("Deploy:")
print("  az deployment group create \\")
print("    --resource-group <your-resource-group> \\")
print(f"    --template-file {OUTPUT}")
