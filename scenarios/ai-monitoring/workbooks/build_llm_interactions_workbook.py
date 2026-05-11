#!/usr/bin/env python3
"""
Build the CSU LLM Interactions workbook ARM template.

Dashboard for every prompt/completion sent to the Azure AI Foundry deployments
via PyRIT. Six operational tiles plus a SOC Analyst Hunting tab.

Data source:
    PyRITInteractions_CL  — custom Log Analytics table populated by
    contoso/sentinel_logger.py (Logs Ingestion API via DCE/DCR).

Columns used:
    TimeGenerated, ModelDeployment, ModelName, Prompt, Completion,
    PromptTokens, CompletionTokens, TotalTokens, LatencyMs,
    Refused, Blocked, AttackName, AttackCategory,
    ContentFilterResult, CallerUPN, CallerIP, ConversationId, TurnNumber.

Run:    python3 build_llm_interactions_workbook.py
Output: csu_llm_interactions_workbook.json
Deploy: az deployment group create --resource-group rg-cst-monitor \
          --template-file csu_llm_interactions_workbook.json
"""
import json


# =============================================================================
# HELPERS — same pattern as build_ai_usage_workbook.py
# =============================================================================

def tile(name, query, title, viz, size=0, width=None,
         chart_settings=None, tile_settings=None,
         export_field=None, export_param=None):
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
    if export_field and export_param:
        item["content"]["exportFieldName"] = export_field
        item["content"]["exportParameterName"] = export_param
        item["content"]["exportDefaultValue"] = ""
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
# KQL QUERIES
# {TimeRange} is a Sentinel workbook token and must NOT be Python-formatted.
# =============================================================================

# --- Tab 1: Overview ---------------------------------------------------------

Q_OVR_KPI = """
let rows = PyRITInteractions_CL
| where TimeGenerated {TimeRange};
let kpi_calls = rows
    | summarize v=count()
    | project Value=v, Metric="Total Interactions";
let kpi_tokens = rows
    | summarize v=toint(sum(TotalTokens))
    | project Value=v, Metric="Total Tokens";
let kpi_refuse = rows
    | summarize v=toint(round(100.0 * countif(Refused) / count(), 0))
    | project Value=v, Metric="Refusal % (All Models)";
let kpi_models = rows
    | summarize v=dcount(ModelDeployment)
    | project Value=v, Metric="Models Hit";
kpi_calls | union kpi_tokens | union kpi_refuse | union kpi_models
""".strip()

# Tile 1 — Calls per minute by model (timechart)
Q_TILE1_CALLS_BY_MIN = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| summarize Count=count() by bin(TimeGenerated, 1m), ModelDeployment
""".strip()

# Tile 2 — Token spend + $ estimate by model (daily bar)
# Rates as of 2026-04 (adjust in one place): phi-4 ~ $0.125 / 1M input, $0.50 / 1M output;
# llama-3-3-70b ~ $0.71 / 1M input, $0.71 / 1M output (MaaS pricing, approximate).
Q_TILE2_TOKEN_SPEND = """
let rate_phi4_in       = 0.125;
let rate_phi4_out      = 0.500;
let rate_llama33_in    = 0.710;
let rate_llama33_out   = 0.710;
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend InCost_USD = case(
    ModelDeployment == "phi-4",          (todouble(PromptTokens)     / 1000000.0) * rate_phi4_in,
    ModelDeployment == "llama-3-3-70b",  (todouble(PromptTokens)     / 1000000.0) * rate_llama33_in,
    0.0)
| extend OutCost_USD = case(
    ModelDeployment == "phi-4",          (todouble(CompletionTokens) / 1000000.0) * rate_phi4_out,
    ModelDeployment == "llama-3-3-70b",  (todouble(CompletionTokens) / 1000000.0) * rate_llama33_out,
    0.0)
| summarize
    Calls         = count(),
    PromptTokens  = sum(PromptTokens),
    OutputTokens  = sum(CompletionTokens),
    EstCostUSD    = round(sum(InCost_USD + OutCost_USD), 4)
    by bin(TimeGenerated, 1d), ModelDeployment
| order by TimeGenerated asc
""".strip()

# Tile 3 — Refusal rate comparison (bar)
Q_TILE3_REFUSAL_DELTA = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| summarize
    Total   = count(),
    Refused = countif(Refused),
    Blocked = countif(Blocked)
    by ModelDeployment
| extend RefusalPct = round(100.0 * Refused / Total, 1)
| extend BlockPct   = round(100.0 * Blocked / Total, 1)
| project ModelDeployment, Total, Refused, Blocked, RefusalPct, BlockPct
| order by RefusalPct desc
""".strip()

# Tile 4 — Content filter verdicts (phi-4 & llama, but filter only meaningful where populated)
# Note: uses tostring() to test emptiness because KQL forbids `dynamic != dynamic({})`
# direct comparisons. Iterates both completion-side (flat keys like "hate","violence")
# and the "_prompt" wrapper written by the sidecar for prompt_filter_results lists.
Q_TILE4_FILTER_VERDICTS = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend _cf = ContentFilterResult
| extend _cfStr = tostring(_cf)
| where isnotempty(_cfStr) and _cfStr !in ("{}", "null")
// Flatten completion-side categories (hate, violence, sexual, self_harm, jailbreak, ...)
| mv-apply cat = bag_keys(_cf) on (
    extend
        Category = tostring(cat),
        CatVal   = _cf[tostring(cat)]
)
| where Category != "_prompt"
| extend
    Filtered = tobool(CatVal.filtered),
    Severity = tostring(CatVal.severity),
    Detected = tobool(CatVal.detected)
| where Filtered == true or Detected == true
| summarize FilteredHits = count() by ModelDeployment, Category, Severity=coalesce(Severity, "n/a")
| order by FilteredHits desc
""".strip()

# Tile 5 — Jailbreak hunting feed (grid) — live, last 24h default
# Flags suspicious phrases + embedded base64 chunks.
Q_TILE5_JAILBREAK_FEED = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend PromptLower = tolower(Prompt)
| extend MatchedPhrases = extract_all(@"(ignore previous|ignore all previous|disregard previous|DAN|developer mode|jailbreak|unlock|system prompt|repeat everything above|reveal your instructions|you are now|pretend you|act as|roleplay|bypass|disable your|without restriction|uncensored|base64|rot13|leetspeak|decode this)", PromptLower)
| extend PhraseHits = array_length(MatchedPhrases)
| extend LikelyBase64 = iff(Prompt matches regex @"[A-Za-z0-9+/]{40,}={0,2}", true, false)
| where PhraseHits > 0 or LikelyBase64 == true
| project TimeGenerated, ModelDeployment, AttackName, AttackCategory,
          Refused, Blocked, PhraseHits, MatchedPhrases = tostring(MatchedPhrases), LikelyBase64,
          PromptExcerpt = substring(Prompt, 0, 200),
          CompletionExcerpt = substring(Completion, 0, 200),
          CallerUPN, CallerIP, ConversationId
| order by TimeGenerated desc
| take 200
""".strip()

# Tile 6 — Top callers by volume (bar)
Q_TILE6_TOP_CALLERS = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend Caller = iff(isempty(CallerUPN), CallerIP, CallerUPN)
| where isnotempty(Caller)
| summarize
    Interactions = count(),
    Models       = make_set(ModelDeployment, 10),
    Refusals     = countif(Refused),
    Tokens       = sum(TotalTokens)
    by Caller
| order by Interactions desc
| take 20
""".strip()

# --- SOC Analyst Hunting tab -------------------------------------------------

# KPI row: what happened in the time window that matters to an analyst
Q_SOC_KPI = """
let suspicious = PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend PromptLower = tolower(Prompt)
| extend Hits = array_length(extract_all(@"(ignore previous|ignore all previous|disregard previous|DAN|developer mode|jailbreak|system prompt|repeat everything above|reveal your instructions|pretend you|bypass|without restriction|uncensored|base64|rot13|decode this)", PromptLower))
| extend LikelyBase64 = iff(Prompt matches regex @"[A-Za-z0-9+/]{40,}={0,2}", true, false)
| extend IsSuspicious = (Hits > 0 or LikelyBase64 == true);
let kpi_suspicious = suspicious | summarize v=countif(IsSuspicious) | project Value=v, Metric="Suspicious Prompts";
let kpi_bypass     = suspicious | where IsSuspicious | summarize v=countif(Refused == false and Blocked == false) | project Value=v, Metric="Suspicious + Not Refused";
let kpi_callers    = suspicious | where IsSuspicious | extend c = iff(isempty(CallerUPN), CallerIP, CallerUPN) | summarize v=dcount(c) | project Value=v, Metric="Unique Suspicious Callers";
let kpi_blocked    = suspicious | summarize v=countif(Blocked) | project Value=v, Metric="Blocked by Filter";
kpi_suspicious | union kpi_bypass | union kpi_callers | union kpi_blocked
""".strip()

# Hunt feed with severity scoring for triage.
# Honors the TriageFilter parameter exported by the Triage Summary tiles:
#   "Blocked by Filter"        → only Blocked rows
#   "Suspicious Prompts"       → any suspicious (phrase or base64)
#   "Suspicious + Not Refused" → suspicious AND not refused AND not blocked
#   "Unique Suspicious Callers"→ suspicious (same feed as 'Suspicious Prompts')
#   ""                         → no filter (default)
Q_SOC_HUNT_FEED = """
let phraseRegex = @"(ignore previous|ignore all previous|disregard previous|DAN|developer mode|jailbreak|unlock|system prompt|repeat everything above|reveal your instructions|you are now|pretend you|act as|roleplay|bypass|disable your|without restriction|uncensored|base64|rot13|leetspeak|decode this)";
let f = "{TriageFilter}";
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend PromptLower = tolower(Prompt)
| extend PhraseHits = array_length(extract_all(phraseRegex, PromptLower))
| extend LikelyBase64 = iff(Prompt matches regex @"[A-Za-z0-9+/]{40,}={0,2}", true, false)
| extend LongPrompt  = iff(strlen(Prompt) > 2000, true, false)
| where PhraseHits > 0 or LikelyBase64 or LongPrompt
// Severity: block > high-phrase-count > base64 > any
| extend Severity = case(
    PhraseHits >= 3 or (PhraseHits >= 1 and Refused == false and Blocked == false), "High",
    LikelyBase64 and Refused == false, "High",
    PhraseHits >= 1, "Medium",
    LikelyBase64 or LongPrompt, "Low",
    "Informational")
| extend IsSuspicious = (PhraseHits > 0 or LikelyBase64)
// Apply the Triage-Summary click filter (f is "" when no tile is selected)
| where (f == "")
    or (f == "Blocked by Filter"         and Blocked)
    or (f == "Suspicious Prompts"        and IsSuspicious)
    or (f == "Suspicious + Not Refused"  and IsSuspicious and Refused == false and Blocked == false)
    or (f == "Unique Suspicious Callers" and IsSuspicious)
| project TimeGenerated, Severity, ModelDeployment, AttackName, AttackCategory,
          PhraseHits, LikelyBase64, LongPrompt, Refused, Blocked,
          PromptExcerpt = substring(Prompt, 0, 300),
          CompletionExcerpt = substring(Completion, 0, 300),
          Caller = iff(isempty(CallerUPN), CallerIP, CallerUPN),
          ConversationId, TurnNumber
| order by TimeGenerated desc
| take 300
""".strip()

# Full conversation replay — drill down on a single ConversationId via parameter
Q_SOC_CONVO_REPLAY = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| where ConversationId == '{ConversationIdFilter}' or '{ConversationIdFilter}' == ''
| order by TurnNumber asc
| project TimeGenerated, TurnNumber, ModelDeployment, Prompt, Completion,
          Refused, Blocked, PromptTokens, CompletionTokens, LatencyMs
""".strip()

# Suspicious caller leaderboard
Q_SOC_CALLER_LEAD = """
let phraseRegex = @"(ignore previous|DAN|jailbreak|system prompt|bypass|uncensored|base64|rot13|decode this)";
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| extend PromptLower   = tolower(Prompt)
| extend PhraseHits    = array_length(extract_all(phraseRegex, PromptLower))
| extend LikelyBase64  = iff(Prompt matches regex @"[A-Za-z0-9+/]{40,}={0,2}", true, false)
| extend IsSuspicious  = (PhraseHits > 0 or LikelyBase64)
| extend Caller        = iff(isempty(CallerUPN), CallerIP, CallerUPN)
| where isnotempty(Caller)
| summarize
    Total       = count(),
    Suspicious  = countif(IsSuspicious),
    Bypassed    = countif(IsSuspicious and Refused == false and Blocked == false),
    Models      = make_set(ModelDeployment, 5),
    FirstSeen   = min(TimeGenerated),
    LastSeen    = max(TimeGenerated)
    by Caller
| extend SuspiciousPct = round(100.0 * Suspicious / Total, 1)
| order by Bypassed desc, Suspicious desc
| take 25
""".strip()

# Attack-module effectiveness (when AttackName/AttackCategory populated)
Q_SOC_ATTACK_MATRIX = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| where isnotempty(AttackName)
| summarize
    Attempts    = count(),
    Refused     = countif(Refused),
    Blocked     = countif(Blocked),
    ModelsHit   = make_set(ModelDeployment, 5)
    by AttackCategory, AttackName
| extend RefusalPct = round(100.0 * Refused / Attempts, 1)
| order by Attempts desc
""".strip()

# Recent raw — table of last 50, no filtering
Q_SOC_RECENT = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| project TimeGenerated, ModelDeployment, AttackName,
          PromptExcerpt = substring(Prompt, 0, 150),
          CompletionExcerpt = substring(Completion, 0, 150),
          Refused, Blocked,
          Caller = iff(isempty(CallerUPN), CallerIP, CallerUPN)
| order by TimeGenerated desc
| take 50
""".strip()


# --- Model Compare tab (NEW) -------------------------------------------------

# Refusal-rate × attack-category heatmap, phi-4 vs llama head-to-head.
Q_CMP_REFUSAL_HEATMAP = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| where isnotempty(AttackCategory)
| summarize Total=count(), Refused=countif(Refused), Blocked=countif(Blocked)
    by ModelDeployment, AttackCategory
| extend RefusalPct = round(100.0 * Refused / Total, 1)
| extend BlockPct   = round(100.0 * Blocked / Total, 1)
| order by AttackCategory asc, ModelDeployment asc
""".strip()

# Token-usage asymmetry — completion length per refusal outcome.
Q_CMP_TOKEN_ASYMMETRY = """
PyRITInteractions_CL
| where TimeGenerated {TimeRange}
| summarize
    MedianOutTokens = percentile(CompletionTokens, 50),
    P95OutTokens    = percentile(CompletionTokens, 95),
    AvgLatencyMs    = avg(LatencyMs),
    Calls           = count()
    by ModelDeployment, Refused
| order by ModelDeployment asc, Refused asc
""".strip()

# Join PyRIT text with Foundry diagnostic RequestResponse (both now land in LA).
# Uses a 60s window since PyRIT logs the turn completion while Foundry diag
# stamps the HTTP request arrival — they rarely line up to the millisecond.
Q_CMP_FOUNDRY_CORRELATION = """
let pyrit = PyRITInteractions_CL
    | where TimeGenerated {TimeRange}
    | project pyTime=TimeGenerated, ModelDeployment, AttackName, Refused, Blocked, CallerIP,
              PromptExcerpt=substring(Prompt, 0, 150);
let diag = AzureDiagnostics
    | where TimeGenerated {TimeRange}
    | where ResourceProvider == "MICROSOFT.COGNITIVESERVICES" and Category == "RequestResponse"
    | extend props = parse_json(properties_s)
    | project diagTime=TimeGenerated, OperationName, ResultSignature, DurationMs,
              ResponseLength = toint(props.responseLength),
              ApiName = tostring(props.apiName);
pyrit
| extend joinKey = bin(pyTime, 1m)
| join kind=inner (diag | extend joinKey = bin(diagTime, 1m)) on joinKey
| where abs(datetime_diff('second', pyTime, diagTime)) <= 60
| project pyTime, ModelDeployment, AttackName, OperationName, ResultSignature,
          DurationMs, ResponseLength, Refused, Blocked, PromptExcerpt
| order by pyTime desc
| take 100
""".strip()

# Defender for AI — surface any alerts tagged to this Foundry resource.
Q_CMP_DEFENDER_ALERTS = """
SecurityAlert
| where TimeGenerated {TimeRange}
| where ProductName has_any ("Azure AI", "Defender for AI", "Microsoft Defender for Cloud")
   or AlertName has_any ("prompt", "LLM", "jailbreak", "foundry", "openai")
   or Entities has "aif-cst-aiatk-a6"
| project TimeGenerated, AlertName, AlertSeverity, ProductName, Description=substring(Description, 0, 300)
| order by TimeGenerated desc
| take 50
""".strip()


# =============================================================================
# WORKBOOK STRUCTURE
# =============================================================================

HEADER = """# CSU: LLM Interactions — Usage, Cost & SOC Hunting

End-to-end visibility into every prompt/completion against the Azure AI Foundry deployments
(`phi-4`, `llama-3-3-70b`). Powered by the custom `PyRITInteractions_CL` table.

> **Table:** PyRITInteractions_CL &nbsp;|&nbsp; **DCR:** dcr-pyrit-interactions &nbsp;|&nbsp; **Ingest path:** PyRIT → Logs Ingestion API → Log Analytics

**Two tabs:**
- **Overview** — operational dashboard (usage, cost, refusals, content filter verdicts, jailbreak feed, top callers).
- **SOC Hunting** — triage view for security analysts: suspicious prompts scored by severity, caller leaderboard, attack-module effectiveness, conversation replay.

---"""

params_panel = {
    "type": 9,
    "content": {
        "version": "KqlParameterItem/1.0",
        "parameters": [
            {
                "id": "b0000000-0000-0000-0000-00000000llm1",
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
                "id": "b0000000-0000-0000-0000-00000000llm2",
                "version": "KqlParameterItem/1.0",
                "name": "SelectedTab",
                "type": 1,
                "isRequired": False,
                "value": "overview",
                "isHiddenWhenLocked": True,
            },
            {
                "id": "b0000000-0000-0000-0000-00000000llm3",
                "version": "KqlParameterItem/1.0",
                "name": "ConversationIdFilter",
                "label": "ConversationId (SOC drill-down)",
                "type": 1,
                "isRequired": False,
                "value": "",
                "description": "Paste a ConversationId to replay its full turn history on the SOC tab. Leave blank for all.",
            },
            {
                "id": "b0000000-0000-0000-0000-00000000llm4",
                "version": "KqlParameterItem/1.0",
                "name": "TriageFilter",
                "label": "Triage filter (click a Triage Summary tile)",
                "type": 1,
                "isRequired": False,
                "value": "",
                "description": "Set by clicking a Triage Summary tile on the SOC Hunting tab. Clear to remove filter.",
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
            {"id": "t1", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Overview",     "subTarget": "overview", "style": "link"},
            {"id": "t2", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "SOC Hunting",  "subTarget": "soc",      "style": "link"},
            {"id": "t3", "cellValue": "SelectedTab", "linkTarget": "parameter",
             "linkLabel": "Model Compare", "subTarget": "compare", "style": "link"},
        ],
    },
    "name": "tabs",
}

# ── Tab: Overview (6 tiles + KPI row) ────────────────────────────────────────
tab_overview = group("grp-overview", "overview", [
    md("ovr-hdr",
       "### Overview — All LLM Interactions\n"
       "Operational view: usage, cost, refusal asymmetry, filter verdicts, hunting feed, top callers."),
    tile("ovr-kpi", Q_OVR_KPI, "Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS),

    tile("tile1-calls",       Q_TILE1_CALLS_BY_MIN,
         "1 — Calls per minute by model", "timechart"),

    tile("tile2-spend",       Q_TILE2_TOKEN_SPEND,
         "2 — Token spend & estimated cost (USD) by model (daily)", "table"),

    tile("tile3-refusal",     Q_TILE3_REFUSAL_DELTA,
         "3 — Refusal / block comparison (phi-4 vs llama-3-3-70b)", "table", width="50"),

    tile("tile4-filter",      Q_TILE4_FILTER_VERDICTS,
         "4 — Content-filter verdicts (where populated)", "barchart", width="50"),

    tile("tile5-jailbreak",   Q_TILE5_JAILBREAK_FEED,
         "5 — Jailbreak hunting feed (phrase + base64 heuristics)", "table"),

    tile("tile6-callers",     Q_TILE6_TOP_CALLERS,
         "6 — Top callers by interaction volume", "table"),
])

# ── Tab: SOC Hunting ─────────────────────────────────────────────────────────
tab_soc = group("grp-soc", "soc", [
    md("soc-hdr",
       "### SOC Analyst — LLM Abuse Hunting\n"
       "Severity-scored triage view. Use the **ConversationIdFilter** parameter above to replay a specific conversation in the last tile.\n\n"
       "Severity heuristics:\n"
       "- **High** — 3+ suspicious phrases, OR ≥1 phrase + not refused/blocked, OR likely base64 + not refused.\n"
       "- **Medium** — ≥1 suspicious phrase.\n"
       "- **Low** — likely-base64 payload or unusually long prompt (>2 000 chars).\n\n"
       "💡 **Click any Triage Summary tile below** to filter the hunt feed. The current filter shows above as `Triage filter` — clear it to see all rows."),
    tile("soc-kpi", Q_SOC_KPI, "Triage Summary", "tiles",
         size=4, tile_settings=KPI_TILE_SETTINGS,
         export_field="Metric", export_param="TriageFilter"),
    tile("soc-hunt-feed", Q_SOC_HUNT_FEED,
         "Suspicious Prompts — severity-scored (filtered by Triage Summary click)", "table"),
    tile("soc-leader", Q_SOC_CALLER_LEAD,
         "Suspicious Callers — ranked by bypass count", "table", width="50"),
    tile("soc-attack-matrix", Q_SOC_ATTACK_MATRIX,
         "Attack Module Effectiveness", "table", width="50"),
    tile("soc-convo", Q_SOC_CONVO_REPLAY,
         "Conversation Replay — paste a ConversationId above to drill down", "table"),
    tile("soc-recent", Q_SOC_RECENT,
         "Last 50 Interactions — all traffic", "table"),
])

# ── Tab: Model Compare (NEW) ─────────────────────────────────────────────────
tab_compare = group("grp-compare", "compare", [
    md("cmp-hdr",
       "### Model Compare — phi-4 vs llama-3-3-70b\n"
       "Head-to-head view of refusal behavior, token-usage asymmetry, and cross-source "
       "correlation with Azure AI Foundry diagnostic logs (`AzureDiagnostics` / "
       "`RequestResponse`) plus Microsoft Defender for AI alerts.\n\n"
       "If a row has `PromptExcerpt` populated but no matching Foundry diag row, the "
       "call likely went straight to the model endpoint rather than through APIM."),
    tile("cmp-refusal-heat", Q_CMP_REFUSAL_HEATMAP,
         "Refusal / Block rate by AttackCategory (per model)", "table"),
    tile("cmp-tokens", Q_CMP_TOKEN_ASYMMETRY,
         "Completion-length asymmetry (refused vs honored)", "table", width="50"),
    tile("cmp-defender", Q_CMP_DEFENDER_ALERTS,
         "Defender for AI alerts (last N)", "table", width="50"),
    tile("cmp-corr", Q_CMP_FOUNDRY_CORRELATION,
         "PyRIT ↔ Foundry diagnostic correlation (same-minute join)", "table"),
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
        tab_soc,
        tab_compare,
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
            "defaultValue": "CSU: LLM Interactions — Usage, Cost & SOC Hunting",
        },
        "location": {
            "type": "string",
            "defaultValue": "[resourceGroup().location]",
        },
    },
    "variables": {
        "workbookId": "[guid('csu-llm-interactions-workbook-v1')]",
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

OUTPUT = "csu_llm_interactions_workbook.json"
with open(OUTPUT, "w", encoding="utf-8") as f:
    json.dump(arm_template, f, indent=2, ensure_ascii=False)

print(f"Written: {OUTPUT}")
print("Tabs: Overview (6 tiles + KPI), SOC Hunting (5 tiles + KPI)")
print(f"Notebook items: {len(notebook['items'])}")
print()
print("Deploy:")
print("  az deployment group create \\")
print("    --resource-group rg-cst-monitor \\")
print("    --template-file csu_llm_interactions_workbook.json")
