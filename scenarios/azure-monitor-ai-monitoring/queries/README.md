# Queries — Azure Monitor AI Monitoring

Standalone KQL files used by the [Azure Monitor: AI Monitoring workbook](../workbooks/azure-monitor-ai-monitoring-workbook.json). Each file has a header block describing its purpose, data sources, output columns, and parameters.

You can run any of these directly in **Log Analytics → Logs** (or in **Microsoft Sentinel → Logs**) after replacing the workbook tokens. See the [Run a query in Log Analytics](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-tutorial) tutorial for first-time users.

## Workbook tokens

The workbook substitutes these tokens at run time. Replace them manually when running a file outside the workbook:

| Token | What it is | Example replacement |
| --- | --- | --- |
| `{TimeRange}` | A KQL fragment that follows `TimeGenerated`. Set by the TimeRange picker at the top of the workbook. | `> ago(24h)` |
| `{ModelFilter}` | Selected model deployment name, or `*` for all. Set by clicking a row in **Model Split — Requests vs Tokens**. | `"phi-4"` or `"*"` |
| `{SelectedKPI}` | Label of the KPI row a user clicked in **Executive KPIs**. | `"Total Requests"` |

## Index

| File | Tab | Purpose |
| --- | --- | --- |
| [exec_kpi.kql](exec_kpi.kql) | Executive | 9 headline KPIs (requests, tokens, errors, alerts) |
| [kpi_detail.kql](kpi_detail.kql) | Executive | Time-series detail driven by the clicked KPI |
| [usage_request_trend.kql](usage_request_trend.kql) | Executive, Usage & Cost | Per-model request count in 15 min buckets |
| [usage_token_trend.kql](usage_token_trend.kql) | Usage & Cost | Hourly Input / Output / Total tokens |
| [usage_cost.kql](usage_cost.kql) | Usage & Cost | Approximate daily USD cost per model (edit price constants at top) |
| [usage_model_split.kql](usage_model_split.kql) | Usage & Cost | Per-model summary; row-click exports `ModelFilter` |
| [safety_trend.kql](safety_trend.kql) | Executive, Safety & Ops | Trend of BlockedCalls / Errors / SuccessfulCalls |
| [safety_by_model.kql](safety_by_model.kql) | Safety & Ops | Per-model status-code breakdown (2xx, 400, 401/403, 429, 5xx) |
| [ops_latency.kql](ops_latency.kql) | Safety & Ops | Per-model avg / p50 / p95 latency |
| [ops_errors.kql](ops_errors.kql) | Safety & Ops | Per-model 429 / 4xx / 5xx trend |
| [ops_feed.kql](ops_feed.kql) | Safety & Ops | Most-recent failed RequestResponse rows with correlation IDs |
| [trace_feed.kql](trace_feed.kql) | Safety & Ops | Most-recent successful RequestResponse rows |
| [defender_alerts.kql](defender_alerts.kql) | Defender & Gov | Defender for AI / Defender for Cloud alerts |
| [audit_feed.kql](audit_feed.kql) | Defender & Gov | Cognitive Services admin / write events from Activity Log (30 d) |
| [activity_feed.kql](activity_feed.kql) | Defender & Gov | All Cognitive Services Activity Log events (30 d) |
| [ingest_health.kql](ingest_health.kql) | Executive | Which tables are receiving data right now — use this when tiles are blank |

## Re-using queries elsewhere

These files are written as plain Kusto. You can use them anywhere KQL is accepted:

- **[Microsoft Sentinel analytics rules](https://learn.microsoft.com/azure/sentinel/detect-threats-custom)** — wrap a query into a scheduled rule, add `| where` filters, project to alert entities.
- **[Sentinel hunting queries](https://learn.microsoft.com/azure/sentinel/hunting)** — save as a hunting query and run on demand or pin to a livestream.
- **[Azure Monitor alert rules](https://learn.microsoft.com/azure/azure-monitor/alerts/alerts-create-log-alert-rule)** — turn a number-returning query (like `exec_kpi.kql` filtered to one Metric) into a metric- or log-alert.
- **[Log Analytics Logs blade](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-overview)** — paste a query, run, and pin the chart to an Azure dashboard.

## Schema references

- `AzureMetrics` — [schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azuremetrics). MetricNames available for `MICROSOFT.COGNITIVESERVICES` include `ModelRequests`, `TotalCalls`, `SuccessfulCalls`, `TotalErrors`, `ClientErrors`, `BlockedCalls`, `Latency`, `InputTokens`, `OutputTokens`, `TotalTokens`, `TokensPerSecond`, `TimeToResponse`, `TimeToLastByte`, `Ratelimit`.
- `AzureDiagnostics` — [schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics). For Cognitive Services the most useful Category is `RequestResponse`; per-call detail (model deployment name, model version, stream type, request/response sizes) lives in the `properties_s` JSON column.
- `SecurityAlert` — [schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert). Populated by Defender for Cloud / Defender for AI.
- `AzureActivity` — [schema](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity). Subscription-level control-plane events.

## KQL reference

- [Kusto Query Language quick reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference)
- [Common KQL operators](https://learn.microsoft.com/azure/data-explorer/kusto/query/tutorial)
- [Best practices for KQL queries](https://learn.microsoft.com/azure/data-explorer/kusto/query/best-practices)
