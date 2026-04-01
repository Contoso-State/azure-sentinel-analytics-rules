# MFA Hijack Detection Scenario

Detect MFA token theft and abuse of overpermissioned app registrations used in OAuth consent phishing and post-compromise lateral movement.

## Analytics Rules

| Rule | Detection | MITRE ATT&CK | Severity | Frequency |
|------|-----------|---------------|----------|-----------|
| **mfa-token-theft** | Detects MFA token replay and session hijacking via anomalous sign-in patterns | T1539, T1550.001 | High | PT15M |
| **overpermissioned-app** | Detects app registrations with excessive Graph API permissions or suspicious consent grants | T1098.003, T1550.001 | Medium | PT1H |

## Data Sources

- **AuditLogs** -- Entra ID audit events (app consent, role changes)
- **SigninLogs** -- Interactive user sign-in events
- **OfficeActivity** -- M365 activity post-compromise
- **AADServicePrincipalSignInLogs** -- Service principal authentication events
- **MicrosoftGraphActivityLogs** -- Graph API call patterns

## Deployment

Deploy each rule with its parameter file:

```bash
# MFA Token Theft Detection
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/mfa-token-theft.bicep \
  --parameters parameters/mfa-token-theft.bicepparam

# Overpermissioned App Detection
az deployment group create \
  --resource-group <your-rg> \
  --template-file rules/overpermissioned-app.bicep \
  --parameters parameters/overpermissioned-app.bicepparam

# Workbook
az deployment group create \
  --resource-group <your-rg> \
  --template-file workbooks/mfa-hijack-detection.json
```

## Standalone KQL

The `queries/` directory contains standalone `.kql` files for testing in Sentinel Logs without deploying Bicep rules.
