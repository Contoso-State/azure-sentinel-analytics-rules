# AI Monitoring Scenario

Monitor LLM interactions for operational usage, estimated token cost, and SOC hunting workflows using the workbook **CSU: LLM Interactions — Usage, Cost & SOC Hunting**.

## What Is Included

- Workbook artifacts copied from the Contoso purple lab:
  - `workbooks/csu_llm_interactions_workbook.json`
  - `workbooks/build_llm_interactions_workbook.py`
- 17 standalone KQL files extracted from the workbook queries in `queries/`

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