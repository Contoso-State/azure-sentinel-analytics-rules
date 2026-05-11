#!/usr/bin/env python3
"""
Build a native Sentinel workbook for Azure AI Foundry telemetry.

This workbook intentionally avoids custom ingestion tables and relies on:
- AzureMetrics
- AzureDiagnostics (Audit, RequestResponse, Trace, AzureOpenAIRequestUsage)
- SecurityAlert (Defender for AI / Defender for Cloud)
- AzureActivity

Run:    python3 build_native_llm_monitoring_workbook.py
Output: csu_native_llm_monitoring_workbook.json
"""

import json


def tile(name, query, title, viz, size=0, width=None, chart_settings=None, tile_settings=None):
    item = {
        "type": 3,
        "content": {
            "version": "KqlItem/1.0",
            "query": query,
            "size": size,
            "title": title,
            "queryType": 0,
            "resourceType": "microsoft.operationalinsights/workspaces",
            "visualization": viz,
        },
        "name": name,
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
            "items": children,
        },
        "name": name,
        "conditionalVisibility": {
            "parameterName": "SelectedTab",
            "comparison": "isEqualTo",
            "value": tab_value,
        },
    }


KPI_TILE_SETTINGS = {
    "titleContent": {"columnMatch": "Metric", "formatter": 1},
    "leftContent": {
        "columnMatch": "Value",
        "formatter": 12,
        "formatOptions": {"palette": "auto"},
    },
    "showBorder": True,
}


# =============================================================================
# KQL (Native-only, no custom tables)
# =============================================================================

Q_EXEC_KPI = """
let m = AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES";
let kpi_requests = m
| where MetricName == "ModelRequests"
| summarize v=toint(sum(todouble(coalesce(Total, 0.0))))
| project Metric="Total Requests", Value=v;
let kpi_tokens = m
| where MetricName == "TotalTokens"
| summarize v=toint(sum(todouble(coalesce(Total, 0.0))))
| project Metric="Total Tokens", Value=v;
let kpi_input = m
| where MetricName == "InputTokens"
| summarize v=toint(sum(todouble(coalesce(Total, 0.0))))
| project Metric="Input Tokens", Value=v;
let kpi_output = m
| where MetricName == "OutputTokens"
| summarize v=toint(sum(todouble(coalesce(Total, 0.0))))
| project Metric="Output Tokens", Value=v;
let kpi_blocked = m
| where MetricName == "BlockedCalls"
| summarize v=toint(sum(todouble(coalesce(Total, 0.0))))
| project Metric="Blocked Calls", Value=v;
let ops = AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend StatusCode = toint(ResultSignature)
| summarize
    Throttles429 = countif(StatusCode == 429),
    Errors4xx = countif(StatusCode between (400 .. 499) and StatusCode != 429),
    Server5xx = countif(StatusCode >= 500);
let kpi_429 = ops | project Metric="429 Throttles", Value=Throttles429;
let kpi_4xx = ops | project Metric="4xx Client Errors", Value=Errors4xx;
let kpi_5xx = ops | project Metric="5xx Errors", Value=Server5xx;
let kpi_alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
    or AlertName has_any ("prompt", "LLM", "jailbreak", "foundry", "openai", "AI")
| summarize v=count()
| project Metric="Defender Alerts", Value=v;
kpi_requests
| union kpi_tokens
| union kpi_input
| union kpi_output
| union kpi_blocked
| union kpi_429
| union kpi_4xx
| union kpi_5xx
| union kpi_alerts
""".strip()

Q_USAGE_REQUEST_TREND = """
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = coalesce(tostring(p.modelDeploymentName), tostring(p.modelName), "unknown")
| where ModelDeployment != "" and ModelDeployment != "unknown"
| summarize Requests = count() by bin(TimeGenerated, 15m), ModelDeployment
| order by TimeGenerated asc
""".strip()

Q_USAGE_TOKEN_TREND = """
AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where MetricName in ("InputTokens", "OutputTokens", "TotalTokens")
| summarize
    InputTokens  = sumif(todouble(coalesce(Total, 0.0)), MetricName == "InputTokens"),
    OutputTokens = sumif(todouble(coalesce(Total, 0.0)), MetricName == "OutputTokens"),
    TotalTokens  = sumif(todouble(coalesce(Total, 0.0)), MetricName == "TotalTokens")
    by bin(TimeGenerated, 1h), Resource
| order by TimeGenerated asc
""".strip()

Q_USAGE_COST = """
// Per-model token totals are not exposed in AzureMetrics for this workspace.
// We approximate per-model cost by splitting aggregate token volume according to
// the per-model request share derived from AzureDiagnostics RequestResponse.
let rate_phi4_in      = 0.125;
let rate_phi4_out     = 0.500;
let rate_llama33_in   = 0.710;
let rate_llama33_out  = 0.710;
let tokens = AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where MetricName in ("InputTokens", "OutputTokens")
| summarize
    InputTokens  = sumif(todouble(coalesce(Total, 0.0)), MetricName == "InputTokens"),
    OutputTokens = sumif(todouble(coalesce(Total, 0.0)), MetricName == "OutputTokens")
    by Day=bin(TimeGenerated, 1d);
let shares = AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = tostring(p.modelDeploymentName)
| where ModelDeployment != ""
| summarize Requests = count() by Day=bin(TimeGenerated, 1d), ModelDeployment
| join kind=inner (
    AzureDiagnostics
    | where TimeGenerated {TimeRange}
    | where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
    | where Category == "RequestResponse"
    | extend p = parse_json(properties_s)
    | where tostring(p.modelDeploymentName) != ""
    | summarize TotalRequests = count() by Day=bin(TimeGenerated, 1d)
) on Day
| extend Share = todouble(Requests) / todouble(TotalRequests);
shares
| join kind=inner tokens on Day
| extend
    InputTokens  = InputTokens * Share,
    OutputTokens = OutputTokens * Share
| extend EstCostUSD = case(
    ModelDeployment =~ "phi-4",         (InputTokens / 1000000.0) * rate_phi4_in    + (OutputTokens / 1000000.0) * rate_phi4_out,
    ModelDeployment =~ "llama-3-3-70b", (InputTokens / 1000000.0) * rate_llama33_in + (OutputTokens / 1000000.0) * rate_llama33_out,
    real(null))
| project Day, ModelDeployment, Requests, InputTokens=toint(InputTokens), OutputTokens=toint(OutputTokens), EstCostUSD
| order by Day asc, ModelDeployment asc
""".strip()

Q_USAGE_MODEL_SPLIT = """
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = tostring(p.modelDeploymentName)
| extend ModelName       = tostring(p.modelName)
| extend ModelVersion    = tostring(p.modelVersion)
| extend StreamType      = tostring(p.streamType)
| extend StatusCode      = toint(ResultSignature)
| where ModelDeployment != ""
| summarize
    Requests = count(),
    AvgDurationMs = avg(todouble(DurationMs)),
    Errors = countif(StatusCode >= 400),
    Throttles = countif(StatusCode == 429)
    by ModelDeployment, ModelName, ModelVersion, StreamType
| order by Requests desc
""".strip()

Q_SAFETY_TREND = """
AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where MetricName in ("BlockedCalls", "ClientErrors", "TotalErrors", "SuccessfulCalls")
| summarize Value=sum(todouble(coalesce(Total, 0.0))) by bin(TimeGenerated, 1h), MetricName
| order by TimeGenerated asc
""".strip()

Q_SAFETY_BY_MODEL = """
// Per-model safety/error counts derived from RequestResponse HTTP status codes
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = tostring(p.modelDeploymentName)
| extend StatusCode      = toint(ResultSignature)
| where ModelDeployment != ""
| summarize
    Success = countif(StatusCode between (200 .. 299)),
    ContentFilter400 = countif(StatusCode == 400),
    Auth401_403 = countif(StatusCode in (401, 403)),
    Throttles429 = countif(StatusCode == 429),
    Server5xx = countif(StatusCode >= 500),
    Total = count()
    by ModelDeployment
| order by Total desc
""".strip()

Q_OPS_LATENCY = """
// Per-model latency from RequestResponse durations (AzureMetrics latency has no model dim here)
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = tostring(p.modelDeploymentName)
| where ModelDeployment != ""
| summarize
    AvgMs = avg(todouble(DurationMs)),
    P50Ms = percentile(todouble(DurationMs), 50),
    P95Ms = percentile(todouble(DurationMs), 95)
    by bin(TimeGenerated, 15m), ModelDeployment
| order by TimeGenerated asc
""".strip()

Q_OPS_ERRORS = """
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = coalesce(tostring(p.modelDeploymentName), Resource)
| extend StatusCode = toint(ResultSignature)
| summarize
    Throttles429 = countif(StatusCode == 429),
    Client4xx = countif(StatusCode between (400 .. 499) and StatusCode != 429),
    Server5xx = countif(StatusCode >= 500)
    by bin(TimeGenerated, 15m), ModelDeployment
| order by TimeGenerated asc
""".strip()

Q_OPS_FEED = """
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = coalesce(tostring(p.modelDeploymentName), Resource)
| extend ModelName       = tostring(p.modelName)
| extend StreamType      = tostring(p.streamType)
| extend StatusCode      = toint(ResultSignature)
| where StatusCode >= 400
| project TimeGenerated, Resource, ModelDeployment, ModelName, StreamType, StatusCode, DurationMs, CorrelationId
| order by TimeGenerated desc
| take 250
""".strip()

Q_TRACE_FEED = """
// Recent successful calls (sampled) — full Trace category not enabled in this workspace
AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend p = parse_json(properties_s)
| extend ModelDeployment = tostring(p.modelDeploymentName)
| extend ModelName       = tostring(p.modelName)
| extend StreamType      = tostring(p.streamType)
| extend StatusCode      = toint(ResultSignature)
| where StatusCode < 400
| project TimeGenerated, Resource, ModelDeployment, ModelName, StreamType, StatusCode, DurationMs, CorrelationId
| order by TimeGenerated desc
| take 100
""".strip()

Q_DEFENDER_ALERTS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
   or AlertName has_any ("prompt", "LLM", "jailbreak", "foundry", "openai", "AI", "model")
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Description=substring(Description, 0, 400)
| order by TimeGenerated desc
| take 100
""".strip()

Q_AUDIT_FEED = """
// Resource-level admin/control-plane events from Activity Log
// (AzureDiagnostics 'Audit' category is data-plane and may not be enabled on every account)
AzureActivity
| where TimeGenerated {TimeRange}
| where ResourceProviderValue =~ "MICROSOFT.COGNITIVESERVICES"
| where OperationNameValue has_any ("DEPLOYMENTS", "ACCOUNTS", "WRITE", "DELETE", "ACTION")
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup, _ResourceId
| order by TimeGenerated desc
| take 100
""".strip()

Q_ACTIVITY_FEED = """
AzureActivity
| where TimeGenerated {TimeRange}
| where ResourceProviderValue =~ "MICROSOFT.COGNITIVESERVICES"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup, ResourceId
| order by TimeGenerated desc
| take 100
""".strip()

Q_INGEST_HEALTH = """
let diag = AzureDiagnostics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| summarize Records=count(), LastSeen=max(TimeGenerated) by Source=strcat("AzureDiagnostics:", Category);
let metrics = AzureMetrics
| where TimeGenerated > ago(24h)
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| summarize Records=count(), LastSeen=max(TimeGenerated) by Source="AzureMetrics:CognitiveServices";
let activity = AzureActivity
| where TimeGenerated > ago(24h)
| where ResourceProviderValue =~ "MICROSOFT.COGNITIVESERVICES"
| summarize Records=count(), LastSeen=max(TimeGenerated) by Source="AzureActivity:CognitiveServices";
let alerts = SecurityAlert
| where TimeGenerated > ago(24h)
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
| summarize Records=count(), LastSeen=max(TimeGenerated) by Source="SecurityAlert:DefenderForAI";
diag
| union metrics
| union activity
| union alerts
| extend Status = iff(Records > 0, "Receiving", "Missing in last 24h")
| project Source, Status, Records, LastSeen
| order by Source asc
""".strip()


HEADER = """# CSU: Native LLM Monitoring — Usage, Cost, Safety & Defender

Detailed Sentinel workbook for Azure AI Foundry telemetry using **native logs and metrics only**.

Data sources:
- `AzureMetrics` (requests, tokens, latency, safety metrics)
- `AzureDiagnostics` (`Audit`, `RequestResponse`, `Trace`, `AzureOpenAIRequestUsage`)
- `SecurityAlert` (Defender for AI / Defender for Cloud)
- `AzureActivity` (governance changes)

> No `PyRITInteractions_CL` dependency.

---"""


params_panel = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            {
                "id": "n1000000-0000-0000-0000-00000000n1",
                "version": "KqlParameterItem/1.0",
                "name": "TimeRange",
                "type": 4,
                "isRequired": True,
                "value": {"durationMs": 86400000},
                "typeSettings": {
                    "selectableValues": [
                        {"durationMs": 900000},
                        {"durationMs": 3600000},
                        {"durationMs": 14400000},
                        {"durationMs": 86400000},
                        {"durationMs": 604800000},
                        {"durationMs": 2592000000},
                    ]
                },
            },
            {
                "id": "n1000000-0000-0000-0000-00000000n2",
                "version": "KqlParameterItem/1.0",
                "name": "SelectedTab",
                "type": 1,
                "isRequired": False,
                "value": "executive",
                "isHiddenWhenLocked": True,
            },
        ],
    },
    "name": "parameters",
}


tabs_selector = {
    "type": 11,
    "content": {
        "version": "LinkItem/1.0",
        "style": "tabs",
        "links": [
            {
                "id": "t1",
                "cellValue": "SelectedTab",
                "linkTarget": "parameter",
                "linkLabel": "Executive",
                "subTarget": "executive",
                "style": "link",
            },
            {
                "id": "t2",
                "cellValue": "SelectedTab",
                "linkTarget": "parameter",
                "linkLabel": "Usage & Cost",
                "subTarget": "usage",
                "style": "link",
            },
            {
                "id": "t3",
                "cellValue": "SelectedTab",
                "linkTarget": "parameter",
                "linkLabel": "Safety & Ops",
                "subTarget": "safetyops",
                "style": "link",
            },
            {
                "id": "t4",
                "cellValue": "SelectedTab",
                "linkTarget": "parameter",
                "linkLabel": "Defender & Gov",
                "subTarget": "defgov",
                "style": "link",
            },
        ],
    },
    "name": "tabs",
}


tab_executive = group(
    "grp-executive",
    "executive",
    [
        md(
            "exec-hdr",
            "### Executive\nNative AI posture summary from Foundry diagnostics + Defender for AI.",
        ),
        tile("exec-kpi", Q_EXEC_KPI, "Executive KPIs", "tiles", size=4, tile_settings=KPI_TILE_SETTINGS),
        tile("exec-requests", Q_USAGE_REQUEST_TREND, "Requests Trend by Model", "timechart", width="50"),
        tile("exec-safety", Q_SAFETY_TREND, "Safety Trend (Blocked/Harmful/Abusive)", "timechart", width="50"),
        tile("exec-health", Q_INGEST_HEALTH, "Telemetry Ingestion Health (last 24h)", "table"),
    ],
)


tab_usage = group(
    "grp-usage",
    "usage",
    [
        md(
            "usage-hdr",
            "### Usage & Cost\nDetailed request, token, and estimated spend monitoring from native metrics.",
        ),
        tile("usage-req", Q_USAGE_REQUEST_TREND, "Requests by Model (15m)", "timechart"),
        tile("usage-token", Q_USAGE_TOKEN_TREND, "Prompt/Output/Total Tokens (1h)", "table"),
        tile("usage-cost", Q_USAGE_COST, "Estimated Cost by Model (daily)", "table", width="50"),
        tile("usage-model", Q_USAGE_MODEL_SPLIT, "Model Split — Requests vs Tokens", "table", width="50"),
    ],
)


tab_safetyops = group(
    "grp-safetyops",
    "safetyops",
    [
        md(
            "safetyops-hdr",
            "### Safety & Operations\nContent safety signals and platform reliability from RequestResponse/Trace + metrics.",
        ),
        tile("safety-model", Q_SAFETY_BY_MODEL, "Safety Metrics by Model", "table", width="50"),
        tile("ops-lat", Q_OPS_LATENCY, "Latency Metrics by Model", "timechart", width="50"),
        tile("ops-errors", Q_OPS_ERRORS, "429 / 4xx / 5xx Trend", "timechart"),
        tile("ops-feed", Q_OPS_FEED, "RequestResponse Error Feed", "table", width="50"),
        tile("trace-feed", Q_TRACE_FEED, "Trace Feed", "table", width="50"),
    ],
)


tab_defgov = group(
    "grp-defgov",
    "defgov",
    [
        md(
            "defgov-hdr",
            "### Defender & Governance\nSecurity detections and control-plane change visibility.",
        ),
        tile("def-alerts", Q_DEFENDER_ALERTS, "Defender for AI Alerts", "table"),
        tile("audit-feed", Q_AUDIT_FEED, "Cognitive Services Audit Feed", "table", width="50"),
        tile("activity-feed", Q_ACTIVITY_FEED, "Azure Activity Feed (Cognitive Services)", "table", width="50"),
    ],
)


notebook = {
    "version": "Notebook/1.0",
    "items": [
        md("header", HEADER),
        params_panel,
        tabs_selector,
        tab_executive,
        tab_usage,
        tab_safetyops,
        tab_defgov,
    ],
    "isLocked": False,
}


arm_template = {
    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
    "contentVersion": "1.0.0.0",
    "parameters": {
        "workspace": {
            "type": "string",
            "defaultValue": "cst-security-law",
        },
        "workbookDisplayName": {
            "type": "string",
            "defaultValue": "CSU: Native LLM Monitoring — Usage, Cost, Safety & Defender",
        },
        "location": {
            "type": "string",
            "defaultValue": "[resourceGroup().location]",
        },
    },
    "variables": {
        "workbookId": "[guid('csu-native-llm-monitoring-workbook-v1')]",
        "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
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
                "category": "sentinel",
            },
        }
    ],
}


OUTPUT = "csu_native_llm_monitoring_workbook.json"
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(arm_template, f, indent=2, ensure_ascii=False)

print(f"Written: {OUTPUT}")
print(f"Notebook items: {len(notebook['items'])}")
print("Tabs: Executive, Usage & Cost, Safety & Ops, Defender & Gov")
