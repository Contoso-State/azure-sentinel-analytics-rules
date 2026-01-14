# Quick Start Guide

Get up and running with Microsoft Sentinel Analytics Rules in 5 minutes.

## Prerequisites Checklist

- [ ] Azure subscription with Sentinel workspace
- [ ] Azure AD Premium P1/P2 licenses
- [ ] Azure CLI installed (`az --version`)
- [ ] Bicep CLI installed (`az bicep version`)
- [ ] Diagnostic settings configured for Azure AD logs

## 5-Minute Deployment

### Step 1: Clone Repository (30 seconds)

```bash
git clone https://github.com/Contoso-State/azure-sentinel-analytics-rules.git
cd azure-sentinel-analytics-rules
```

### Step 2: Configure Parameters (2 minutes)

Edit `parameters/brute-force.bicepparam`:

```bicep
param workspaceName = 'my-sentinel-workspace'  // Change this!
param location = 'eastus'                       // Your region
```

### Step 3: Deploy Rule (2 minutes)

```bash
# Login to Azure
az login

# Deploy
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file rules/brute-force.bicep \
  --parameters parameters/brute-force.bicepparam
```

### Step 4: Verify (30 seconds)

1. Open Azure Portal → Microsoft Sentinel → Analytics
2. Find "Multiple Failed Sign-in Attempts (Brute Force)"
3. Status should be **Enabled** ✅

## Deploy All Rules at Once

### Bash

```bash
RG="your-resource-group"

for param in parameters/*.bicepparam; do
  rule=$(basename "$param" .bicepparam)
  az deployment group create \
    --resource-group "$RG" \
    --template-file "rules/${rule}.bicep" \
    --parameters "$param" \
    --name "deploy-${rule}" &
done

wait
echo "All rules deployed!"
```

### PowerShell

```powershell
$RG = "your-resource-group"

Get-ChildItem parameters/*.bicepparam | ForEach-Object {
  $rule = $_.BaseName
  New-AzResourceGroupDeployment `
    -ResourceGroupName $RG `
    -TemplateFile "rules/$rule.bicep" `
    -TemplateParameterFile $_.FullName `
    -Name "deploy-$rule" `
    -AsJob
}

Get-Job | Wait-Job
Write-Host "All rules deployed!" -ForegroundColor Green
```

## What Gets Deployed?

| Rule | Detects | Severity | Runs Every |
|------|---------|----------|------------|
| Account Compromise | Login success after failures | High | 5 min |
| Brute Force | Multiple failed logins from IP | High | 5 min |
| Password Spray | One IP → many accounts | High | 10 min |
| App Enumeration | Excessive app/SP operations | Medium | 1 hour |
| Cross-Tenant Activity | SP cross-tenant access | High | 1 hour |
| SP Failed Auth | Failed SP authentications | Medium | 1 hour |
| SP Sign-In | Excessive SP sign-ins | Medium | 1 hour |

## Verify Data Ingestion

Before deploying, ensure logs are flowing:

```kusto
// Run in Log Analytics
SigninLogs
| where TimeGenerated > ago(1h)
| summarize count()

// Should return > 0
```

## Troubleshooting

### "Workspace not found"
→ Check workspace name in parameter files

### "No alerts generated"
→ Verify data ingestion with query above

### "Permission denied"
→ Ensure you have Sentinel Contributor role

## Next Steps

1. ✅ Deploy rules
2. ⏰ Wait 1 hour for data
3. 📊 Check Incidents in Sentinel
4. 🎯 Tune thresholds based on your environment
5. 📖 Read full [README](README.md) for details

## Support

- 📚 [Full Documentation](README.md)
- 🚀 [Deployment Guide](docs/deployment-guide.md)
- 🐛 [Report Issues](https://github.com/Contoso-State/azure-sentinel-analytics-rules/issues)

---

**Pro Tip**: Start with just the brute-force and password-spray rules. These have the highest signal-to-noise ratio and will give you quick wins!
