# Deployment Guide

This guide provides step-by-step instructions for deploying Microsoft Sentinel analytics rules using Azure Bicep.

## Table of Contents

- [Prerequisites](#prerequisites)
- [Pre-Deployment Checklist](#pre-deployment-checklist)
- [Deployment Methods](#deployment-methods)
- [Post-Deployment Validation](#post-deployment-validation)
- [Updating Existing Rules](#updating-existing-rules)
- [Troubleshooting](#troubleshooting)

## Prerequisites

### Required Azure Resources

1. **Azure Subscription** with Owner or Contributor permissions
2. **Resource Group** for your Sentinel workspace
3. **Log Analytics Workspace** with Microsoft Sentinel enabled
4. **Azure AD Diagnostic Settings** configured (see [Data Source Configuration](#data-source-configuration))

### Required Tools

- **Azure CLI** (version 2.50.0 or higher)
  ```bash
  az --version
  ```

- **Bicep CLI**
  ```bash
  az bicep install
  az bicep version
  ```

### Required Licenses

| Feature | License Required |
|---------|-----------------|
| SigninLogs | Azure AD Premium P1 or P2 |
| AuditLogs | Azure AD Free (included with subscription) |
| AADServicePrincipalSignInLogs | Azure AD Premium P1 or P2 |

Verify licenses:
```bash
az rest --method GET \
  --uri "https://graph.microsoft.com/v1.0/subscribedSkus" \
  --query "value[].{sku:skuPartNumber, status:capabilityStatus}"
```

## Pre-Deployment Checklist

### 1. Data Source Configuration

Ensure Azure AD logs are flowing to your Log Analytics workspace:

```bash
# Check if diagnostic settings exist
az monitor diagnostic-settings list \
  --resource /providers/microsoft.aadiam/diagnosticSettings
```

Required log categories:
- ✅ SignInLogs
- ✅ AuditLogs
- ✅ AADServicePrincipalSignInLogs
- ✅ NonInteractiveUserSignInLogs

### 2. Verify Data Ingestion

Run these queries in Log Analytics to confirm data is being ingested:

```kusto
// Check for sign-in logs
SigninLogs
| where TimeGenerated > ago(24h)
| summarize count()

// Check for audit logs
AuditLogs
| where TimeGenerated > ago(24h)
| summarize count()

// Check for service principal sign-ins
AADServicePrincipalSignInLogs
| where TimeGenerated > ago(24h)
| summarize count()
```

### 3. Get Your Workspace Information

```bash
# List Log Analytics workspaces
az monitor log-analytics workspace list \
  --query "[].{name:name, resourceGroup:resourceGroup, location:location}" \
  --output table

# Get workspace details
az monitor log-analytics workspace show \
  --workspace-name <workspace-name> \
  --resource-group <resource-group>
```

## Deployment Methods

### Method 1: Deploy Single Rule (Recommended for Testing)

1. **Edit the parameter file** for the rule you want to deploy:

```bicep
// parameters/brute-force.bicepparam
using '../rules/brute-force.bicep'

param location = 'eastus'
param workspaceName = 'my-sentinel-workspace'  // Change this
param enabled = true
```

2. **Deploy the rule:**

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file rules/brute-force.bicep \
  --parameters parameters/brute-force.bicepparam \
  --name deploy-brute-force-rule
```

3. **Verify deployment:**

```bash
# Check deployment status
az deployment group show \
  --resource-group <your-resource-group> \
  --name deploy-brute-force-rule \
  --query "properties.provisioningState"
```

### Method 2: Deploy All Rules (Production)

#### Option A: Using Bash

```bash
#!/bin/bash
RESOURCE_GROUP="<your-resource-group>"

for param_file in parameters/*.bicepparam; do
  rule_name=$(basename "$param_file" .bicepparam)
  echo "Deploying $rule_name..."

  az deployment group create \
    --resource-group "$RESOURCE_GROUP" \
    --template-file "rules/${rule_name}.bicep" \
    --parameters "$param_file" \
    --name "deploy-${rule_name}" \
    --no-wait
done

echo "All deployments initiated. Check status in Azure Portal."
```

#### Option B: Using PowerShell

```powershell
$ResourceGroup = "<your-resource-group>"

Get-ChildItem -Path "parameters" -Filter "*.bicepparam" | ForEach-Object {
    $ruleName = $_.BaseName
    Write-Host "Deploying $ruleName..." -ForegroundColor Cyan

    New-AzResourceGroupDeployment `
        -ResourceGroupName $ResourceGroup `
        -TemplateFile "rules/$ruleName.bicep" `
        -TemplateParameterFile $_.FullName `
        -Name "deploy-$ruleName" `
        -AsJob
}

Get-Job | Wait-Job
Write-Host "All deployments complete!" -ForegroundColor Green
```

### Method 3: Deploy Using Azure Portal

1. Navigate to **Resource Groups** → Select your resource group
2. Click **Create** → Search for "Template deployment"
3. Click **Build your own template in the editor**
4. Click **Load file** and select a rule file (e.g., `rules/brute-force.bicep`)
5. Fill in parameters manually or load a parameter file
6. Click **Review + create** → **Create**

## Post-Deployment Validation

### 1. Verify Rules in Sentinel

Navigate to: **Microsoft Sentinel** → **Analytics** → **Active rules**

Check for your deployed rules:
- ✅ Rule appears in the list
- ✅ Status is "Enabled"
- ✅ Severity is correct
- ✅ Schedule shows correct frequency

### 2. Test Rule Execution

You can manually run a rule to test it:

1. In Sentinel Analytics, click on the rule
2. Click **Run query** to see if it returns results
3. Adjust thresholds if needed based on results

### 3. Monitor First Alerts

```bash
# Query for alerts from your rules (using Azure CLI)
az monitor log-analytics query \
  --workspace <workspace-id> \
  --analytics-query "SecurityAlert | where TimeGenerated > ago(1h) | where AlertName contains 'Brute Force' or AlertName contains 'Password Spray'"
```

### 4. Check Incident Creation

Navigate to: **Microsoft Sentinel** → **Incidents**

Look for:
- ✅ Incidents created automatically
- ✅ Entities are mapped correctly (IP, Account, App)
- ✅ Custom details are populated

## Updating Existing Rules

### Update Rule Parameters

1. Edit the parameter file
2. Redeploy using the same deployment name:

```bash
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file rules/brute-force.bicep \
  --parameters parameters/brute-force.bicepparam \
  --name deploy-brute-force-rule
```

### Disable a Rule

Set `enabled = false` in the parameter file and redeploy:

```bicep
param enabled = false
```

### Delete a Rule

```bash
# Get the rule ID first
az rest --method GET \
  --uri "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>/providers/Microsoft.SecurityInsights/alertRules?api-version=2023-02-01"

# Delete the rule
az rest --method DELETE \
  --uri "https://management.azure.com/subscriptions/<sub-id>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>/providers/Microsoft.SecurityInsights/alertRules/<rule-id>?api-version=2023-02-01"
```

## Troubleshooting

### Common Deployment Errors

#### Error: "Workspace not found"

**Cause**: Incorrect workspace name in parameter file

**Solution**:
```bash
# List all workspaces to find the correct name
az monitor log-analytics workspace list \
  --query "[].{name:name, resourceGroup:resourceGroup}" \
  --output table
```

#### Error: "Insufficient permissions"

**Cause**: User doesn't have required RBAC roles

**Solution**: Ensure you have one of these roles:
- Owner
- Contributor
- Microsoft Sentinel Contributor

```bash
# Check your current role assignment
az role assignment list \
  --assignee <your-email> \
  --resource-group <resource-group> \
  --query "[].roleDefinitionName"
```

#### Error: "Table 'SigninLogs' not found"

**Cause**: Either:
1. Diagnostic settings not configured
2. No Azure AD Premium licenses
3. No sign-in activity yet

**Solution**:
1. Check diagnostic settings (see [Pre-Deployment Checklist](#pre-deployment-checklist))
2. Verify licensing
3. Wait 15-30 minutes for initial data ingestion

### No Alerts Generated

1. **Verify rule is enabled:**
   - Check in Sentinel Analytics that status = "Enabled"

2. **Run the query manually:**
   - Copy the KQL query from the Bicep file
   - Run in Log Analytics to see if it returns results

3. **Check data freshness:**
   ```kusto
   SigninLogs
   | summarize max(TimeGenerated)
   ```

4. **Verify threshold settings:**
   - Default thresholds might be too high for your environment
   - Temporarily lower thresholds for testing

### Rule Triggers Too Many Alerts

1. **Increase thresholds** in parameter file
2. **Add exclusions** to the KQL query for known IPs or accounts
3. **Adjust query frequency** to run less often

Example exclusion:
```kusto
| where IPAddress !in ("1.2.3.4", "5.6.7.8")  // Exclude known IPs
| where UserPrincipalName !contains "#EXT#"   // Exclude guest users
```

## Best Practices

1. **Deploy to Development First**: Test rules in a dev/test workspace before production
2. **Start with High Thresholds**: Begin conservative, then tune down based on environment
3. **Monitor for 1 Week**: Baseline normal activity before tuning
4. **Document Exclusions**: Keep a record of any IPs, accounts, or apps you exclude
5. **Version Control**: Use Git to track parameter file changes
6. **Scheduled Reviews**: Review and update rules quarterly

## Next Steps

After successful deployment:

1. Review [Rule Details](../README.md#rule-details) for investigation guidance
2. Set up **automation rules** for common response actions
3. Configure **alert notifications** for high-severity incidents
4. Integrate with **SOAR/SIEM** workflows
5. Train SOC team on rule logic and investigation procedures

## Support

- GitHub Issues: [Report problems or request features]
- Microsoft Sentinel Documentation: https://docs.microsoft.com/azure/sentinel/
- MITRE ATT&CK: https://attack.mitre.org/
