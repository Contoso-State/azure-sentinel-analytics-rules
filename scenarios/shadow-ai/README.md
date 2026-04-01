# Shadow AI Detection Scenario

Detect unauthorized use of generative AI applications across managed endpoints and cloud APIs. Four complementary rules provide layered visibility from browser access through desktop apps to programmatic AI agent operations.

## Analytics Rules

| Rule | Detection | MITRE ATT&CK | Severity | Frequency |
|------|-----------|---------------|----------|-----------|
| **shadow-ai-browser** | Browser connections to AI domains via DeviceNetworkEvents | T1567 | Medium | PT15M |
| **shadow-ai-desktop** | Desktop AI apps (ChatGPT.exe, Claude.exe) with process correlation | T1219, T1567 | High | PT15M |
| **ai-agent-activity** | High-volume AI agent operations across ARM, Graph API, Entra ID | T1059, T1565 | Informational | PT1H |
| **shadow-ai-session** | Session-attributed AI usage via DeviceInfo join | T1567 | Medium | PT15M |

## Data Sources

- **DeviceNetworkEvents** -- endpoint network connections (MDE)
- **DeviceInfo** -- logged-on user session data (MDE)
- **AzureActivity** -- ARM resource operations
- **MicrosoftGraphActivityLogs** -- Graph API calls
- **AuditLogs** -- Entra ID directory changes

## Deployment

Deploy each rule with its parameter file:

```bash
# Shadow AI Browser Detection
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/shadow-ai-browser.bicep \
  --parameters parameters/shadow-ai-browser.bicepparam

# Shadow AI Desktop App Detection
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/shadow-ai-desktop.bicep \
  --parameters parameters/shadow-ai-desktop.bicepparam

# AI Agent Activity Detection
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/ai-agent-activity.bicep \
  --parameters parameters/ai-agent-activity.bicepparam

# Shadow AI Session Attribution
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/shadow-ai-session.bicep \
  --parameters parameters/shadow-ai-session.bicepparam

# Workbook
az deployment group create \
  --resource-group <your-rg> \
  --template-file workbooks/shadow-ai-usage.json
```

Or deploy from the top-level `rules/` and `parameters/` directories which contain the same files.

## Standalone KQL

The `queries/` directory contains standalone `.kql` files with hardcoded defaults that can be pasted directly into Sentinel Logs for testing without deploying the Bicep rules.

## Customization

### Thresholds

| Parameter | Default | Description |
|-----------|---------|-------------|
| `usageThreshold` | 3 (browser/desktop), 1 (session) | Minimum connections to trigger |
| `writeThreshold` | 10 | Minimum write operations for agent rule |
| `timeWindowHours` | 1 | Lookback period |

### Domain List

The `shadowAIDomains` parameter in `shadow-ai-browser.bicep` accepts a JSON array of domains. Add organization-specific blocked AI services as needed.

### Exclusions

Set `excludedUsers` to a comma-separated list of UPNs for service accounts or approved AI users (e.g., `svc-ai@contoso.com,admin@contoso.com`).

### Domain Suffix

Set `domainSuffix` in browser and session rules to match your organization's UPN domain (e.g., `contoso.com`).
