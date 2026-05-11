# Microsoft Sentinel & Azure Monitor — Workbooks and KQL Hunting Library

[![Azure](https://img.shields.io/badge/Azure-Sentinel-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/services/azure-sentinel/)
[![Azure Monitor](https://img.shields.io/badge/Azure-Monitor-0078D4?logo=microsoft-azure)](https://learn.microsoft.com/azure/azure-monitor/)
[![Bicep](https://img.shields.io/badge/IaC-Bicep-blue)](https://learn.microsoft.com/azure/azure-resource-manager/bicep/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

A curated collection of **Microsoft Sentinel & Azure Monitor workbooks** plus a **KQL hunting-query library** for identity, AI, and cloud-app threats. Everything is organized into self-contained **scenario packages** that can be deployed independently or together.

> **Each scenario includes its own README with step-by-step deployment instructions** — designed for both SOC analysts and non-technical workload owners.

---

## Repository at a glance

| Resource type | Count |
| --- | --- |
| Scenario packages | 4 |
| Sentinel analytics rules (Bicep) | 6 |
| Workbooks (ARM) | 5 |
| Standalone KQL files (hunting + workbook backings) | 50+ |

---

## Scenario index

| Scenario | What it detects / monitors | Artifacts |
| --- | --- | --- |
| [Azure Monitor — AI Monitoring](scenarios/azure-monitor-ai-monitoring/) | **Customer-deployable** workbook for Azure AI Foundry / Azure OpenAI **usage, cost, safety, latency, Defender for AI alerts**, governance changes. Native diagnostics only — no custom tables. | 1 workbook · 16 KQL files · README + queries README |
| [AI Monitoring (CSU)](scenarios/ai-monitoring/) | Original **PyRIT + native LLM monitoring** workbooks for SOC use cases — jailbreak feed, conversation replay, refusal heatmap, attack matrix, content-filter verdicts. | 2 workbooks · 17 PyRIT KQL files · 15 native KQL files |
| [Shadow AI](scenarios/shadow-ai/) | Unauthorized AI app usage across **browser, desktop, and API channels**; user-session attribution; AI agent activity. | 4 analytics rules · 1 workbook · 4 KQL files |
| [MFA Hijack](scenarios/mfa-hijack/) | **AiTM phishing** session-token theft, MFA + password reset correlation, **over-permissioned app abuse** (Mail.Send, User.Read.All, bulk Graph API). | 2 analytics rules · 1 workbook |

Each scenario folder contains the subset that makes sense for it: `rules/`, `parameters/`, `queries/`, `workbooks/`, and a `README.md`.

---

## Workbooks

| Workbook | Scenario | Purpose |
| --- | --- | --- |
| [`azure-monitor-ai-monitoring-workbook.json`](scenarios/azure-monitor-ai-monitoring/workbooks/azure-monitor-ai-monitoring-workbook.json) | Azure Monitor AI Monitoring | 4-tab dashboard: Executive KPIs, Usage & Cost, Safety & Ops, Defender & Gov. Click-to-drill on KPIs and model split. |
| [`csu_native_llm_monitoring_workbook.json`](scenarios/ai-monitoring/workbooks/csu_native_llm_monitoring_workbook.json) | AI Monitoring (CSU) | Internal-facing twin of the customer workbook above. |
| [`csu_llm_interactions_workbook.json`](scenarios/ai-monitoring/workbooks/csu_llm_interactions_workbook.json) | AI Monitoring (CSU) | PyRIT-based deep dive: prompt/response replay, jailbreak feed, refusal heatmap, attack matrix, token spend. |
| [`shadow-ai-usage.json`](scenarios/shadow-ai/workbooks/shadow-ai-usage.json) | Shadow AI | Browser + desktop AI usage, user-session attribution, AI agent activity. |
| [`mfa-hijack-detection.json`](scenarios/mfa-hijack/workbooks/mfa-hijack-detection.json) | MFA Hijack | MFA changes, password resets, AiTM correlation timeline, app-abuse evidence. |

---

## Analytics rules (Bicep)

| Rule | Scenario | MITRE ATT&CK | Severity | Cadence |
| --- | --- | --- | --- | --- |
| [Shadow AI — Browser](scenarios/shadow-ai/rules/shadow-ai-browser.bicep) | Shadow AI | T1567 | Medium | 15 min |
| [Shadow AI — Desktop](scenarios/shadow-ai/rules/shadow-ai-desktop.bicep) | Shadow AI | T1219, T1567 | High | 15 min |
| [Shadow AI — Session attribution](scenarios/shadow-ai/rules/shadow-ai-session.bicep) | Shadow AI | T1567 | Medium | 15 min |
| [AI Agent activity](scenarios/shadow-ai/rules/ai-agent-activity.bicep) | Shadow AI | T1059, T1565 | Informational | 1 h |
| [MFA token theft / AiTM](scenarios/mfa-hijack/rules/mfa-token-theft.bicep) | MFA Hijack | T1557.003, T1528, T1556.006 | High | 5 min |
| [Over-permissioned app abuse](scenarios/mfa-hijack/rules/overpermissioned-app.bicep) | MFA Hijack | T1098.003, T1114.002, T1566.002 | High | 1 h |

All rules ship with:

- ✅ Configurable thresholds via `.bicepparam` parameter files
- ✅ [MITRE ATT&CK](https://attack.mitre.org/) technique mappings
- ✅ Entity mappings (IP, Account, CloudApplication, Host)
- ✅ Custom alert details for investigation
- ✅ Automated incident creation and grouping

---

## KQL hunting library

Every scenario contains a `queries/` folder of standalone `.kql` files you can paste into the **Log Analytics → Logs** blade, [Microsoft Sentinel hunting](https://learn.microsoft.com/azure/sentinel/hunting), or [scheduled analytics rules](https://learn.microsoft.com/azure/sentinel/detect-threats-custom). The AI-monitoring scenario also includes a dedicated [queries README](scenarios/azure-monitor-ai-monitoring/queries/README.md) explaining workbook tokens, schema references, and re-use patterns.

For cross-cutting hunting queries (geo-impossible travel, privilege monitoring, anomalous app access, baseline comparisons), see [ADVANCED-HUNTING-QUERIES.md](ADVANCED-HUNTING-QUERIES.md).

---

## Prerequisites

| Required for | What you need |
| --- | --- |
| All scenarios | An [Azure subscription](https://azure.microsoft.com/free/) and a [Log Analytics workspace](https://learn.microsoft.com/azure/azure-monitor/logs/log-analytics-workspace-overview) (a [Microsoft Sentinel](https://learn.microsoft.com/azure/sentinel/overview) workspace works too). |
| Identity scenarios (MFA Hijack, Shadow AI session attribution) | [Microsoft Entra ID P1 or P2](https://learn.microsoft.com/entra/fundamentals/get-started-premium); diagnostic settings sending `SigninLogs`, `AuditLogs`, `AADServicePrincipalSignInLogs`, `NonInteractiveUserSignInLogs` to your workspace ([how to configure](https://learn.microsoft.com/entra/identity/monitoring-health/howto-configure-diagnostic-settings)). |
| Shadow AI desktop / browser detection | Microsoft Defender for Endpoint with the [`DeviceNetworkEvents`](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table) and [`DeviceProcessEvents`](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table) tables connected to Sentinel. |
| AI monitoring scenarios | [Azure AI Foundry](https://learn.microsoft.com/azure/ai-foundry/what-is-azure-ai-foundry) or [Azure OpenAI](https://learn.microsoft.com/azure/ai-foundry/openai/overview) resource with [diagnostic settings](https://learn.microsoft.com/azure/ai-foundry/openai/how-to/monitor-openai) enabled. Optionally [Defender for AI](https://learn.microsoft.com/azure/defender-for-cloud/ai-onboarding). |
| Deployment | [Azure CLI](https://learn.microsoft.com/cli/azure/install-azure-cli) (`az login`) and the [Bicep CLI](https://learn.microsoft.com/azure/azure-resource-manager/bicep/install) (`az bicep install`). PowerShell works too. |

### Log tables and licensing

| Log table | Required license |
| --- | --- |
| [`SigninLogs`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/signinlogs) | Entra ID P1 or P2 |
| [`AuditLogs`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/auditlogs) | Entra ID Free or Premium |
| [`AADServicePrincipalSignInLogs`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/aadserviceprincipalsigninlogs) | Entra ID P1 or P2 |
| [`OfficeActivity`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/officeactivity) | Office 365 E1/E3/E5 |
| [`MicrosoftGraphActivityLogs`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/microsoftgraphactivitylogs) | Microsoft Graph activity logging |
| [`DeviceNetworkEvents`](https://learn.microsoft.com/defender-xdr/advanced-hunting-devicenetworkevents-table) / [`DeviceProcessEvents`](https://learn.microsoft.com/defender-xdr/advanced-hunting-deviceprocessevents-table) | Microsoft Defender for Endpoint P2 |
| [`AzureMetrics`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azuremetrics) / [`AzureDiagnostics`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/azurediagnostics) | Azure Monitor (built-in) |
| [`SecurityAlert`](https://learn.microsoft.com/azure/azure-monitor/reference/tables/securityalert) | Microsoft Defender for Cloud / Defender for AI |

---

## Quick start

### 1 · Clone the repo

```bash
git clone https://github.com/Contoso-State/azure-sentinel-analytics-rules.git
cd azure-sentinel-analytics-rules
```

### 2 · Pick a scenario

- **Workload owner / customer** monitoring AI usage and cost
  → [Azure Monitor — AI Monitoring](scenarios/azure-monitor-ai-monitoring/) (one-click "Deploy to Azure" button included).
- **SOC analyst** hunting AI abuse and Defender alerts
  → [AI Monitoring](scenarios/ai-monitoring/).
- **SOC analyst** hunting AiTM / app-abuse
  → [MFA Hijack](scenarios/mfa-hijack/).
- **SOC analyst** detecting unsanctioned AI use
  → [Shadow AI](scenarios/shadow-ai/).

### 3 · Deploy an analytics rule (Bicep)

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file scenarios/mfa-hijack/rules/mfa-token-theft.bicep \
  --parameters scenarios/mfa-hijack/parameters/mfa-token-theft.bicepparam
```

### 4 · Deploy a workbook (ARM)

```bash
az deployment group create \
  --resource-group <your-rg> \
  --template-file scenarios/azure-monitor-ai-monitoring/workbooks/azure-monitor-ai-monitoring-workbook.json \
  --parameters workspace=<your-log-analytics-workspace-name>
```

Find rules in **Microsoft Sentinel → Analytics** and workbooks in **Microsoft Sentinel → Workbooks → My workbooks** (or **Azure Monitor → Workbooks**). Reference: [Detect threats with built-in analytics rules](https://learn.microsoft.com/azure/sentinel/detect-threats-built-in) · [Visualize collected data with Azure Monitor Workbooks](https://learn.microsoft.com/azure/sentinel/monitor-your-data).

---

## Customizing rules

Every rule exposes thresholds and cadence through its `.bicepparam` file:

| Parameter | Description | Example |
| --- | --- | --- |
| `location` | Azure region | `'eastus'` |
| `workspaceName` | Sentinel / Log Analytics workspace name | `'my-sentinel-workspace'` |
| `enabled` | Enable or disable the rule | `true` |
| `severity` | Alert severity | `'High'`, `'Medium'`, `'Low'`, `'Informational'` |
| `queryFrequency` | How often the rule runs (ISO-8601) | `'PT5M'`, `'PT1H'` |
| `queryPeriod` | Lookback window (ISO-8601) | `'PT1H'`, `'PT24H'` |

ISO-8601 duration cheat sheet: `PT5M` = 5 min · `PT1H` = 1 h · `PT24H` = 24 h · `P1D` = 1 day.

Scenario-specific thresholds (MFA-correlation window, sensitive-permission count, Shadow AI byte thresholds, AI per-model price constants) are documented in each scenario README.

---

## MITRE ATT&CK coverage

| Tactic | Technique(s) | Rule / hunting query |
| --- | --- | --- |
| Initial Access | T1078, T1078.004, T1566.002 | MFA token theft · Over-permissioned app |
| Credential Access | T1110, T1110.001, T1110.003, T1528, T1556.006, T1557.003 | MFA token theft · hunting queries |
| Discovery | T1087, T1087.004, T1526 | Hunting queries (app enumeration) |
| Persistence | T1098, T1098.003 | Over-permissioned app |
| Collection | T1114.002 | Over-permissioned app |
| Command & Control | T1219, T1567 | Shadow AI (browser / desktop / session) |
| Execution | T1059 | AI Agent activity |
| Impact | T1565 | AI Agent activity |

See each scenario README for the full per-rule MITRE mapping.

---

## Troubleshooting

| Symptom | First thing to check |
| --- | --- |
| Workbook tiles all blank | Diagnostic settings are missing or point at a different workspace. For AI workbooks, run [`ingest_health.kql`](scenarios/azure-monitor-ai-monitoring/queries/ingest_health.kql) first. |
| Rule never fires | Confirm data is flowing (`SigninLogs \| where TimeGenerated > ago(1h) \| count`), the rule is **Enabled** in Analytics, and licensing is correct. |
| Bicep deploy error — "workspace not found" | The `workspaceName` parameter must match an existing workspace in the target resource group. |
| Bicep deploy error — 403 | You need the [Microsoft Sentinel Contributor](https://learn.microsoft.com/azure/role-based-access-control/built-in-roles#microsoft-sentinel-contributor) role on the resource group. |

More: [Microsoft Sentinel troubleshooting](https://learn.microsoft.com/azure/sentinel/troubleshooting) · [Workbooks overview](https://learn.microsoft.com/azure/azure-monitor/visualize/workbooks-overview).

---

## Best practices

1. Deploy with defaults first; tune thresholds **after** observing baseline behavior.
2. Roll out one rule at a time and review **Last triggered** before deploying the next.
3. Document every exclusion (IPs, accounts, apps) in source control alongside the parameter file.
4. Review and prune rules quarterly — attacker tradecraft changes.
5. Use the scenario READMEs as runbooks: each lists the investigation questions to ask when an alert fires.

---

## Contributing

PRs welcome. For new detections include:

1. Detection logic, sample data, and tuning notes.
2. MITRE ATT&CK technique mapping.
3. A `.bicepparam` (rules) or schema-aware KQL header (queries).
4. Updates to the relevant scenario README.

Test against a non-production Sentinel workspace before submitting.

---

## Support and feedback

- **Issues** — [GitHub Issues](https://github.com/Contoso-State/azure-sentinel-analytics-rules/issues)
- **Discussions** — [GitHub Discussions](https://github.com/Contoso-State/azure-sentinel-analytics-rules/discussions)

---

## License

MIT — see [LICENSE](LICENSE).

## Acknowledgments

- Microsoft Sentinel and Azure Monitor product documentation
- The [MITRE ATT&CK](https://attack.mitre.org/) framework
- Microsoft Customer Success Unit (CSU) field engineers

---

> **Disclaimer** — These artifacts are provided as-is. Always validate in a non-production environment, and tune thresholds and price constants to your organization's risk tolerance and contracts before production use.
