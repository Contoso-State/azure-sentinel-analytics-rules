# AI Monitoring Scenario

Monitor LLM interactions for operational usage, estimated token cost, and SOC hunting workflows using the workbook **CSU: LLM Interactions — Usage, Cost & SOC Hunting**.

## What Is Included

- Workbook artifacts copied from the Contoso purple lab:
  - `workbooks/csu_llm_interactions_workbook.json`
  - `workbooks/build_llm_interactions_workbook.py`
- 17 standalone KQL files extracted from the workbook queries in `queries/`

Native telemetry workbook assets (no custom table required):

- `workbooks/build_native_llm_monitoring_workbook.py`
- `workbooks/csu_native_llm_monitoring_workbook.json`
- `queries-native/*.kql` (15 native telemetry queries)

## Native Workbook (No PyRIT Table)

Use this workbook when Azure AI Foundry diagnostics and metrics are already routed into Sentinel and you do not want custom ingestion through `PyRITInteractions_CL`.

Workbook:

- **CSU: Native LLM Monitoring — Usage, Cost, Safety & Defender**

Native data sources:

1. `AzureMetrics`
2. `AzureDiagnostics`
3. `SecurityAlert`
4. `AzureActivity`

Native workbook tabs:

1. Executive
2. Usage & Cost
3. Safety & Ops
4. Defender & Gov

### Required Diagnostic Settings For Native Workbook

On the Azure AI Foundry / Cognitive Services resource, route these to the same Log Analytics workspace used by Sentinel:

1. **Logs**
  - `Audit Logs`
  - `Request and Response Logs`
  - `Trace Logs`
  - `Azure OpenAI Request Usage`
2. **Metrics**
  - `AllMetrics`

If Microsoft Defender for AI is enabled, ensure alerts are present in `SecurityAlert`.

### Deploy Native Workbook

From `scenarios/ai-monitoring/workbooks`:

```bash
python3 build_native_llm_monitoring_workbook.py

az deployment group create \
  --resource-group <your-resource-group> \
  --template-file csu_native_llm_monitoring_workbook.json \
  --parameters workspace=<your-sentinel-workspace>
```

### Native Validation

1. Run `queries-native/native-ingestion-health.kql` and confirm all categories show `Receiving`.
2. Run `queries-native/native-exec-kpi.kql` and verify non-zero values.
3. Run `queries-native/native-defender-alerts.kql` and confirm Defender alerts appear when detections exist.
4. Open the native workbook and verify all four tabs render with data.

## Workbook Overview

The workbook has three tabs:

- **Overview**: interaction volume, token/cost trend, refusals, filter verdicts, jailbreak feed, top callers.
- **SOC Hunting**: suspicious prompt triage, caller leaderboard, attack effectiveness matrix, conversation replay.
- **Model Compare**: refusal heatmap, token asymmetry, Foundry diagnostics correlation, Defender-for-AI alerts.

Primary table expected by workbook queries:

- **PyRITInteractions_CL**

## KQL Inventory

| Area | Query File | Purpose |
|------|------------|---------|
| Overview | `queries/llm-overview-kpi.kql` | Total interactions, total tokens, refusal %, models hit |
| Overview | `queries/llm-calls-by-minute.kql` | Calls per minute trend by model |
| Overview | `queries/llm-token-spend-cost.kql` | Prompt/output tokens and estimated daily USD cost |
| Overview | `queries/llm-refusal-delta.kql` | Refusal and block percentage by model |
| Overview | `queries/llm-content-filter-verdicts.kql` | Content filter category/severity hit counts |
| Overview | `queries/llm-jailbreak-feed.kql` | Suspicious prompts (phrase/base64 heuristics) |
| Overview | `queries/llm-top-callers.kql` | Top callers by interactions, refusals, tokens |
| SOC Hunting | `queries/llm-soc-kpi.kql` | Suspicious prompt KPIs and blocked/bypass counts |
| SOC Hunting | `queries/llm-soc-hunt-feed.kql` | Severity-scored suspicious prompt feed |
| SOC Hunting | `queries/llm-soc-conversation-replay.kql` | Full conversation replay by ConversationId |
| SOC Hunting | `queries/llm-soc-suspicious-callers.kql` | Suspicious caller leaderboard |
| SOC Hunting | `queries/llm-soc-attack-matrix.kql` | Attack category/name effectiveness matrix |
| SOC Hunting | `queries/llm-soc-recent-raw.kql` | Last 50 recent raw interactions |
| Model Compare | `queries/llm-compare-refusal-heatmap.kql` | Refusal/block heatmap by attack category and model |
| Model Compare | `queries/llm-compare-token-asymmetry.kql` | Completion token percentiles and latency by refusal outcome |
| Model Compare | `queries/llm-compare-foundry-correlation.kql` | Correlate PyRIT interaction events with AzureDiagnostics |
| Model Compare | `queries/llm-compare-defender-alerts.kql` | Defender-for-AI/SecurityAlert signal surface |

## Sentinel Data Sources To Ingest

### Required

1. **Custom table `PyRITInteractions_CL`** in the Sentinel Log Analytics workspace.
2. Ingestion pipeline using **Logs Ingestion API** with:
   - Data Collection Endpoint (DCE)
   - Data Collection Rule (DCR), for example `dcr-pyrit-interactions`
3. Sender/application that posts interaction telemetry (for example, PyRIT sidecar/logger).

### How To Set Up `PyRITInteractions_CL`

Use this sequence to create the ingestion path and verify data lands in the workspace.

1. Create (or identify) a Log Analytics workspace connected to Sentinel.
2. Create a Data Collection Endpoint (DCE) in the same region as the workspace.
3. Create a Data Collection Rule (DCR) with:
   - A stream declaration for your PyRIT interaction payload shape.
   - A destination pointing to the target Log Analytics workspace.
   - A transformation that outputs records into `PyRITInteractions_CL`.
4. Grant the sender identity permission to ingest via the DCR.
5. Configure your PyRIT logger to post JSON records to the Logs Ingestion API using the DCE endpoint and DCR immutable ID.
6. Send a small test batch (1-5 records).
7. Validate ingestion in Sentinel Logs with:

```kusto
PyRITInteractions_CL
| where TimeGenerated > ago(30m)
| order by TimeGenerated desc
| take 20
```

Example Azure CLI scaffolding (adapt names/IDs for your environment):

```bash
# Variables
RG=<your-rg>
LOC=<region>
WS=<your-law-workspace-name>
DCE=dce-pyrit-interactions
DCR=dcr-pyrit-interactions

# 1) Create DCE
az monitor data-collection endpoint create \
  --name "$DCE" \
  --resource-group "$RG" \
  --location "$LOC"

# 2) Get workspace resource ID
WS_ID=$(az monitor log-analytics workspace show \
  --resource-group "$RG" \
  --workspace-name "$WS" \
  --query id -o tsv)

# 3) Create DCR from a local JSON definition that includes:
#    - streamDeclarations
#    - destinations.logAnalytics
#    - dataFlows with outputStream = Custom-PyRITInteractions_CL
az monitor data-collection rule create \
  --name "$DCR" \
  --resource-group "$RG" \
  --location "$LOC" \
  --rule-file dcr-pyrit-interactions.json
```

Important notes:

- Column names in custom table ingestion are case-sensitive and must match the DCR stream declaration exactly.
- Custom table ingestion can take a few minutes before records become queryable.
- If data does not appear, first verify DCR immutable ID, DCE endpoint URI, auth token scope, and payload field names.

Minimum columns required by the workbook/KQL:

- `TimeGenerated`
- `ModelDeployment`
- `ModelName`
- `Prompt`
- `Completion`
- `PromptTokens`
- `CompletionTokens`
- `TotalTokens`
- `LatencyMs`
- `Refused`
- `Blocked`
- `AttackName`
- `AttackCategory`
- `ContentFilterResult` (dynamic JSON)
- `CallerUPN`
- `CallerIP`
- `ConversationId`
- `TurnNumber`

### Optional (enables specific model-compare views)

1. **AzureDiagnostics**
   - Needed for `llm-compare-foundry-correlation.kql`
   - Expected filters in query:
     - `ResourceProvider == "MICROSOFT.COGNITIVESERVICES"`
     - `Category == "RequestResponse"`
2. **SecurityAlert**
   - Needed for `llm-compare-defender-alerts.kql`
   - If Defender for AI is not enabled, results may be empty (this is expected).

## Deployment

Deploy workbook to your Sentinel resource group:

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file workbooks/csu_llm_interactions_workbook.json
```

## Validation Checklist

1. Confirm recent records exist in `PyRITInteractions_CL`.
2. Run `queries/llm-overview-kpi.kql` in Logs and validate non-zero counts.
3. Open workbook and verify all three tabs render.
4. If using Foundry diagnostics, validate data in `AzureDiagnostics` and run `queries/llm-compare-foundry-correlation.kql`.
5. If using Defender for AI, validate signal in `SecurityAlert` and run `queries/llm-compare-defender-alerts.kql`.

## Notes

- Cost estimates in `llm-token-spend-cost.kql` use static model pricing constants from the source workbook and should be reviewed periodically.
- Query files include workbook tokens such as `{TimeRange}`, `{TriageFilter}`, and `{ConversationIdFilter}` for workbook compatibility.