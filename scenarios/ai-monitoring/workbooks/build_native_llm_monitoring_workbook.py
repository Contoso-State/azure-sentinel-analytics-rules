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


def tile(name, query, title, viz, size=0, width=None, chart_settings=None, tile_settings=None, grid_settings=None, export_field=None, export_param=None):
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
    if grid_settings:
        item["content"]["gridSettings"] = grid_settings
    if export_field is not None and export_param is not None:
        item["content"]["exportFieldName"] = export_field
        item["content"]["exportParameterName"] = export_param
        item["content"]["exportDefaultValue"] = "*"
        item["content"]["showExportToExcel"] = True
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


KPI_GRID_SETTINGS = {
    "formatters": [
        {
            "columnMatch": "Metric",
            "formatter": 1,
            "formatOptions": {
                "customColumnWidthSetting": "30ch",
            },
        },
        {
            "columnMatch": "Value",
            "formatter": 8,
            "formatOptions": {
                "min": 0,
                "palette": "blue",
                "compositeBarSettings": {"labelText": ""},
            },
            "numberFormat": {
                "unit": 0,
                "options": {
                    "style": "decimal",
                    "useGrouping": True,
                    "maximumFractionDigits": 0,
                },
            },
        },
    ],
    "rowLimit": 20,
    "labelSettings": [
        {"columnId": "Metric", "label": "KPI (click row to drill)"},
        {"columnId": "Value", "label": "Value"},
    ],
}


# =============================================================================
# KQL (Native-only, no custom tables)
# =============================================================================

Q_EXEC_KPI = """
let m = AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES";
let kpi_metric = (n:string, mn:string) {
    m | where MetricName == mn
    | summarize v=tolong(sum(todouble(coalesce(Total, 0.0))))
    | project Metric=n, Value=tolong(v)
};
let ops = AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend StatusCode = toint(ResultSignature);
let kpi_alerts = SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
    or AlertName has_any ("prompt", "LLM", "jailbreak", "foundry", "openai", "AI")
| summarize v=tolong(count())
| project Metric="Defender Alerts", Value=tolong(v);
kpi_metric("Total Requests", "ModelRequests")
| union (kpi_metric("Total Tokens", "TotalTokens"))
| union (kpi_metric("Input Tokens", "InputTokens"))
| union (kpi_metric("Output Tokens", "OutputTokens"))
| union (kpi_metric("Blocked Calls", "BlockedCalls"))
| union (ops | summarize v=tolong(countif(StatusCode == 429)) | project Metric="429 Throttles", Value=tolong(v))
| union (ops | summarize v=tolong(countif(StatusCode between (400 .. 499) and StatusCode != 429)) | project Metric="4xx Client Errors", Value=tolong(v))
| union (ops | summarize v=tolong(countif(StatusCode >= 500)) | project Metric="5xx Errors", Value=tolong(v))
| union kpi_alerts
| project Metric, Value=tolong(Value)
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
| where "{ModelFilter}" == "*" or ModelDeployment =~ "{ModelFilter}"
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
| where "{ModelFilter}" == "*" or ModelDeployment =~ "{ModelFilter}"
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
| where "{ModelFilter}" == "*" or ModelDeployment =~ "{ModelFilter}"
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
| where "{ModelFilter}" == "*" or ModelDeployment =~ "{ModelFilter}"
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
// Cognitive Services admin/write events from Activity Log.
// Forced 30d window: governance events are sparse and TimeRange (e.g. 24h) often returns nothing.
AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue =~ "MICROSOFT.COGNITIVESERVICES"
| where OperationNameValue has_any ("WRITE", "DELETE", "ACTION")
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup, _ResourceId
| order by TimeGenerated desc
| take 200
""".strip()

Q_ACTIVITY_FEED = """
// All Cognitive Services activity (read+write) — 30d window.
AzureActivity
| where TimeGenerated > ago(30d)
| where ResourceProviderValue =~ "MICROSOFT.COGNITIVESERVICES"
| project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller, ResourceGroup, ResourceId
| order by TimeGenerated desc
| take 200
""".strip()

Q_KPI_DETAIL = """
// Time-series detail driven by the SelectedKPI parameter (clicked row in Executive KPIs grid).
let kpi = "{SelectedKPI}";
let metric_for_kpi = case(
    kpi == "Total Requests",   "ModelRequests",
    kpi == "Total Tokens",     "TotalTokens",
    kpi == "Input Tokens",     "InputTokens",
    kpi == "Output Tokens",    "OutputTokens",
    kpi == "Blocked Calls",    "BlockedCalls",
    "");
let m_series = AzureMetrics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where MetricName == metric_for_kpi
| summarize Value = sum(todouble(coalesce(Total, 0.0))) by bin(TimeGenerated, 15m)
| extend Series = kpi;
let status_series = AzureDiagnostics
| where TimeGenerated {TimeRange}
| where ResourceProvider == "MICROSOFT.COGNITIVESERVICES"
| where Category == "RequestResponse"
| extend StatusCode = toint(ResultSignature)
| where (kpi == "429 Throttles"     and StatusCode == 429)
     or (kpi == "4xx Client Errors" and StatusCode between (400 .. 499) and StatusCode != 429)
     or (kpi == "5xx Errors"        and StatusCode >= 500)
| summarize Value = todouble(count()) by bin(TimeGenerated, 15m)
| extend Series = kpi;
let alert_series = SecurityAlert
| where TimeGenerated {TimeRange}
| where kpi == "Defender Alerts"
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
    or AlertName has_any ("prompt", "LLM", "jailbreak", "foundry", "openai", "AI")
| summarize Value = todouble(count()) by bin(TimeGenerated, 15m)
| extend Series = kpi;
m_series
| union status_series
| union alert_series
| order by TimeGenerated asc
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
            {
                "id": "n1000000-0000-0000-0000-00000000n4",
                "version": "KqlParameterItem/1.0",
                "name": "SelectedKPI",
                "type": 1,
                "isRequired": False,
                "value": "Total Requests",
                "isHiddenWhenLocked": True,
            },
            {
                "id": "n1000000-0000-0000-0000-00000000n3",
                "version": "KqlParameterItem/1.0",
                "name": "ModelFilter",
                "label": "Model filter (click a row in Model Split to drill)",
                "type": 2,
                "isRequired": False,
                "value": "*",
                "typeSettings": {"additionalResourceOptions": []},
                "query": "AzureDiagnostics\n| where TimeGenerated > ago(7d)\n| where ResourceProvider == \"MICROSOFT.COGNITIVESERVICES\"\n| where Category == \"RequestResponse\"\n| extend p = parse_json(properties_s)\n| extend ModelDeployment = tostring(p.modelDeploymentName)\n| where ModelDeployment != \"\"\n| summarize by ModelDeployment\n| project Value=ModelDeployment, Label=ModelDeployment\n| union (print Value=\"*\", Label=\"All models\")\n| order by Label asc",
                "queryType": 0,
                "resourceType": "microsoft.operationalinsights/workspaces",
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
        tile("exec-kpi", Q_EXEC_KPI, "Executive KPIs (click a row to drill)", "table", size=4, grid_settings=KPI_GRID_SETTINGS, export_field="Metric", export_param="SelectedKPI"),
        tile("exec-kpi-detail", Q_KPI_DETAIL, "KPI Detail \u2014 {SelectedKPI}", "timechart"),
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
        tile("usage-model", Q_USAGE_MODEL_SPLIT, "Model Split \u2014 Requests vs Tokens (click a row to drill)", "table", width="50", export_field="ModelDeployment", export_param="ModelFilter"),
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
            "defaultValue": "your-sentinel-workspace",
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
