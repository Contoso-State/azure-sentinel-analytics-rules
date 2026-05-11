# Azure Monitor — AI Monitoring Workbook

A ready-to-deploy **Azure Workbook** that shows you how your Azure AI Foundry / Azure OpenAI service is being used: requests, tokens, costs, errors, safety blocks, Defender for AI alerts, and governance changes — all in one dashboard.

> **You do not need to be technical to deploy this.** Follow the steps below. The whole thing takes about 10 minutes.

**Helpful background reading from Microsoft Learn** (you can skip these and come back later):
- [What are Azure Monitor Workbooks?](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-overview)
- [Monitor Azure OpenAI](https://learn.microsoft.com/azure/ai-foundry/openai/how-to/monitor-openai)
- [Monitor model deployments in Microsoft Foundry Models](https://learn.microsoft.com/azure/foundry/foundry-models/how-to/monitor-models)
- [Microsoft Defender for Cloud — AI threat protection overview](https://learn.microsoft.com/azure/defender-for-cloud/ai-threat-protection)

---

## What you get

After deployment you will see a new workbook in your Microsoft Sentinel (or Azure Monitor) workspace called:

> **Azure Monitor: AI Monitoring — Usage, Cost, Safety & Defender**

It has four tabs:

| Tab | What it shows |
| --- | --- |
| **Executive** | At-a-glance KPIs (requests, tokens, errors, Defender alerts) and a clickable detail chart |
| **Usage & Cost** | Per-model request and token trends, daily estimated USD cost, model split |
| **Safety & Ops** | Content-safety blocks, per-model latency, 4xx/5xx/429 error trends, recent error and trace feeds |
| **Defender & Gov** | Defender for AI alerts, Cognitive Services audit and Activity Log feed |

### Click-to-drill

- On **Executive**, click any KPI row → the chart below updates to show the time-series for that KPI.
- On **Usage & Cost**, click a model row in **Model Split** → all detail charts on the **Safety & Ops** tab filter to that model.

---

## What you need before you start

1. **An Azure subscription** with at least one of:
   - [Azure AI Foundry](https://learn.microsoft.com/azure/ai-foundry/what-is-azure-ai-foundry) resource (recommended), **or**
   - [Azure OpenAI](https://learn.microsoft.com/azure/ai-foundry/openai/overview) resource
2. **A [Log Analytics workspace](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview)** (a Microsoft Sentinel workspace works too). If you don't have one, [create one here](https://learn.microsoft.com/azure/azure-monitor/logs/quick-create-workspace).
3. Permission to **deploy resources** to a resource group ([Contributor role](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#contributor)).

That's it.

---

## Step 1 — Turn on the data

The workbook reads from Azure's **built-in** logs and metrics. You do **not** need to install any agents or custom code. You just need to tell your AI resource to send its logs to your workspace.

> Microsoft Learn reference: [Diagnostic settings in Azure Monitor](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings).

### 1a. Send AI Foundry / Azure OpenAI logs to your workspace

Follow the official Microsoft procedure for your resource type:
- **Azure OpenAI:** [Monitor Azure OpenAI → Configure diagnostic settings](https://learn.microsoft.com/azure/ai-foundry/openai/how-to/monitor-openai#analyze-monitoring-data)
- **Microsoft Foundry Models:** [Monitor model deployments → Configure diagnostic settings](https://learn.microsoft.com/azure/foundry/foundry-models/how-to/monitor-models#configure-diagnostic-settings)
- **Azure AI services (general):** [Enable diagnostic logging](https://learn.microsoft.com/azure/ai-services/diagnostic-logging#enable-diagnostic-log-collection)

Short version:

1. Open the [Azure Portal](https://portal.azure.com).
2. Search for and open your **Azure AI Foundry** (or **Azure OpenAI**) resource.
3. In the left menu, click **Diagnostic settings**.
4. Click **+ Add diagnostic setting**.
5. Name it something like `send-to-monitor`.
6. Under **Logs**, tick:
   - `Audit Logs`
   - `RequestResponse Logs`
   - `Trace Logs`
   - `Azure OpenAI Request Usage` (if shown)
7. Under **Metrics**, tick **AllMetrics**.
8. Under **Destination details**, tick **Send to Log Analytics workspace** and pick your workspace.
9. Click **Save**.

> Repeat this for every AI Foundry / Azure OpenAI resource you want to monitor. It can take up to two hours for the first logs to appear (see [Microsoft Learn note on initial latency](https://learn.microsoft.com/azure/ai-services/diagnostic-logging#enable-diagnostic-log-collection)).

### 1b. (Optional but recommended) Turn on Microsoft Defender for AI

Follow the official walkthrough: [Enable threat protection for AI services](https://learn.microsoft.com/azure/defender-for-cloud/ai-onboarding).

Short version:

1. In the portal, search for **Microsoft Defender for Cloud**.
2. Open **Environment settings** → pick your subscription → **Defender plans**.
3. Find **AI services** (Defender for AI) and toggle it **On**.
4. Click **Save**.

Defender for AI then surfaces [alerts for AI workloads](https://learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads) (prompt-injection, jailbreak, sensitive-data exposure, wallet-abuse, etc.) into the **SecurityAlert** table — the **Defender & Gov** tab of the workbook will populate automatically.

---

## Step 2 — Deploy the workbook

You have two equally easy options. Pick whichever you prefer.

### Option A — One-click "Deploy to Azure" (easiest)

Click the button below. It will open the Azure Portal and pre-fill everything for you.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FContoso-State%2Fazure-sentinel-analytics-rules%2Fmaster%2Fscenarios%2Fazure-monitor-ai-monitoring%2Fworkbooks%2Fazure-monitor-ai-monitoring-workbook.json)

When the page opens:

1. Pick your **Subscription**.
2. Pick the **Resource group** that contains your Log Analytics workspace.
3. In **Workspace**, type the **name** of your Log Analytics workspace (not the full ID — just the name, e.g. `my-sentinel-ws`).
4. Leave **Workbook display name** as-is, or rename if you like.
5. Click **Review + create**, then **Create**.

After about 30 seconds you will see "Your deployment is complete".

### Option B — Upload through the Workbooks gallery

Reference: [Create an Azure Workbook — ARM template](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-create-workbook).

1. In the [Azure Portal](https://portal.azure.com), search for **Monitor** and open it.
2. In the left menu, click **Workbooks**.
3. Click **+ New**.
4. Click the **</>** (Advanced Editor) icon at the top.
5. In the **Template Type** dropdown, choose **ARM Template**.
6. Open [`workbooks/azure-monitor-ai-monitoring-workbook.json`](workbooks/azure-monitor-ai-monitoring-workbook.json) in this repo, copy the entire contents, and paste it into the editor.
7. Click **Apply**.
8. Click **Save** (disk icon), pick a region, and choose your workspace's resource group.

---

## Step 3 — Open the workbook

1. In the [Azure Portal](https://portal.azure.com), search for **Microsoft Sentinel** (or **Azure Monitor → Workbooks**).
2. Open your workspace.
3. In the left menu, click **Workbooks**.
4. Click the **My workbooks** tab.
5. Open **Azure Monitor: AI Monitoring — Usage, Cost, Safety & Defender**.

Use the **TimeRange** picker at the top to change the window (default: last 24 hours).

---

## When will I see data?

| Data source | First data appears in |
| --- | --- |
| [`AzureMetrics`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azuremetrics) (requests, tokens, latency) | **2–5 minutes** after a call is made to your model |
| [`AzureDiagnostics`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics) (RequestResponse, Audit, Trace) | **5–15 minutes** |
| [`SecurityAlert`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert) (Defender for AI) | **10–30 minutes** after Defender for AI is enabled |
| [`AzureActivity`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azureactivity) (governance changes) | **3–10 minutes** |

If a tile shows "The query returned no results", widen the **TimeRange** at the top of the workbook — for low-traffic environments try **7 days** or **30 days**.

---

## What does each tile cost to run?

Running the workbook is **free**. You only pay for:

- The logs your AI resource sends to Log Analytics ([standard Log Analytics ingestion rates](https://azure.microsoft.com/pricing/details/monitor/) — see [cost calculations and options](https://learn.microsoft.com/azure/azure-monitor/logs/cost-logs)).
- Microsoft Defender for AI, if you enable it ([Defender for Cloud pricing](https://azure.microsoft.com/pricing/details/defender-for-cloud/)).

A single AI Foundry resource typically ingests **well under 1 GB / month** of diagnostic logs.

---

## What's in the queries folder?

The [`queries/`](queries) folder contains every KQL query the workbook uses, as standalone `.kql` files. You don't need them to deploy — they are there so your security or platform team can:

- Re-use the queries in [Microsoft Sentinel analytics rules](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in) or the Log Analytics [**Logs** blade](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-tutorial).
- Adapt them for [scheduled alert rules](https://learn.microsoft.com/azure/sentinel/detect-threats-custom).
- Audit exactly what the workbook is querying.

Reference for the Kusto query language used in every file: [KQL quick reference](https://learn.microsoft.com/azure/data-explorer/kql-quick-reference).

| File | What it does |
| --- | --- |
| `exec_kpi.kql` | Executive KPIs (9 metrics) |
| `kpi_detail.kql` | Time-series detail for the clicked KPI |
| `usage_request_trend.kql` | Requests per 15 min, per model |
| `usage_token_trend.kql` | Input/Output/Total tokens per hour |
| `usage_cost.kql` | Estimated daily USD cost per model |
| `usage_model_split.kql` | Requests, latency, errors per model |
| `safety_trend.kql` | BlockedCalls / errors / successes trend |
| `safety_by_model.kql` | Per-model success / 400 / 401-403 / 429 / 5xx counts |
| `ops_latency.kql` | Per-model latency (avg, p50, p95) |
| `ops_errors.kql` | 429 / 4xx / 5xx trend |
| `ops_feed.kql` | Recent error responses (with correlation IDs) |
| `trace_feed.kql` | Recent successful responses |
| `defender_alerts.kql` | Defender for AI alerts |
| `audit_feed.kql` | Cognitive Services Activity Log audit feed (30 d) |
| `activity_feed.kql` | All Cognitive Services Activity Log events (30 d) |
| `ingest_health.kql` | Which tables are receiving data right now |

---

## Troubleshooting

**"The query returned no results" on every tile**
→ The diagnostic setting in **Step 1a** is missing or points to a different workspace. Re-check using [Troubleshoot Azure Monitor diagnostic settings](https://learn.microsoft.com/azure/azure-monitor/essentials/diagnostic-settings#troubleshooting) and re-deploy.

**KPI grid shows 0 for everything**
→ No traffic to your AI model in the selected time window. Widen **TimeRange** or send a test prompt through the [Azure AI Foundry playground](https://learn.microsoft.com/azure/ai-foundry/quickstarts/get-started-playground).

**Defender & Gov tab is empty**
→ Defender for AI is not enabled (Step 1b). The Audit/Activity feeds use a fixed 30-day window so they will populate once any change is made. See [Alerts for AI workloads](https://learn.microsoft.com/azure/defender-for-cloud/alerts-ai-workloads) for a list of alerts that should appear.

**I want to add my own model pricing**
→ Edit the rate constants at the top of [`queries/usage_cost.kql`](queries/usage_cost.kql) and re-deploy. Pricing reference: [Azure OpenAI pricing](https://azure.microsoft.com/pricing/details/cognitive-services/openai-service/).

**I want to edit the workbook visuals**
→ See [Workbook visualizations](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-visualizations) and [Create interactive reports with Azure Monitor Workbooks](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-interactive-reports).

---

## Support

This workbook is provided as-is by the Microsoft Customer Success Unit (CSU). For issues open a ticket against this repository.
