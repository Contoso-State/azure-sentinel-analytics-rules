# Microsoft Sentinel Analytics Rules - Identity Attack Detection

[![Azure](https://img.shields.io/badge/Azure-Sentinel-0078D4?logo=microsoft-azure)](https://azure.microsoft.com/services/azure-sentinel/)
[![Bicep](https://img.shields.io/badge/IaC-Bicep-blue)](https://learn.microsoft.com/azure/azure-resource-manager/bicep/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red)](https://attack.mitre.org/)

A comprehensive collection of Microsoft Sentinel analytics rules designed to detect identity-based attacks in Azure/Entra ID environments. These rules provide detection coverage across the full attack lifecycle, from initial access through credential compromise, reconnaissance, and lateral movement.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Analytics Rules](#analytics-rules)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Customization](#customization)
- [Rule Details](#rule-details)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Contributing](#contributing)
- [License](#license)

## Overview

This repository contains **7 production-ready Sentinel analytics rules** implemented as Infrastructure-as-Code using Azure Bicep. Each rule is designed to detect specific attack patterns targeting Azure AD/Entra ID identities, including:

- User account attacks (brute force, password spray, credential compromise)
- Service principal abuse and credential theft
- Reconnaissance and enumeration activities
- Cross-tenant attacks and lateral movement

All rules include:
- ✅ Configurable detection thresholds
- ✅ MITRE ATT&CK technique mappings
- ✅ Custom alert details for investigation
- ✅ Entity mappings (IP, Account, CloudApplication)
- ✅ Automated incident creation and grouping

## Features

- **Infrastructure as Code**: Deploy and manage rules using Bicep templates
- **Parameterized Configuration**: Easily customize thresholds and settings via parameter files
- **Dynamic Severity**: Some rules adjust severity based on attack intensity
- **Comprehensive Coverage**: Detects attacks against both user accounts and service principals
- **Production Ready**: Battle-tested in live environments
- **Well Documented**: Each rule includes detailed descriptions and investigation guidance

## Prerequisites

Before deploying these analytics rules, ensure you have:

1. **Azure Subscription** with appropriate permissions
2. **Microsoft Sentinel** workspace already deployed
3. **Azure AD Premium P1/P2** licenses (required for SignInLogs)
4. **Diagnostic Settings** configured to send Azure AD logs to Log Analytics:
   - SignInLogs
   - AuditLogs
   - AADServicePrincipalSignInLogs
   - NonInteractiveUserSignInLogs
5. **Azure CLI** or **Azure PowerShell** installed
6. **Bicep CLI** installed (`az bicep install`)

### Licensing Requirements

| Log Table | Required License |
|-----------|------------------|
| SigninLogs | Azure AD Premium P1 or P2 |
| AuditLogs | Azure AD Free (basic) or Premium |
| AADServicePrincipalSignInLogs | Azure AD Premium P1 or P2 |

## Analytics Rules

| Rule | Detection Type | MITRE ATT&CK | Severity | Frequency |
|------|---------------|--------------|----------|-----------|
| [Account Compromise](#1-account-compromise-detection) | Successful login after failed attempts | T1078, T1110, T1098 | High | 5 min |
| [Brute Force](#2-brute-force-attack-detection) | Multiple failed sign-ins from same IP | T1110.001, T1078 | High | 5 min |
| [Password Spray](#3-password-spray-attack-detection) | One IP targeting multiple accounts | T1110.003, T1087 | High | 10 min |
| [App Enumeration](#4-app-registration-enumeration) | Excessive app/SP enumeration operations | T1087.004, T1526 | Medium | 1 hour |
| [Cross-Tenant Activity](#5-cross-tenant-service-principal-activity) | Service principal cross-tenant access | T1550 | High | 1 hour |
| [SP Failed Auth](#6-failed-service-principal-authentications) | Failed SP authentication attempts | T1110 | Medium | 1 hour |
| [SP Sign-In Activity](#7-suspicious-service-principal-sign-in-activity) | Excessive SP sign-in volume | T1078 | Medium | 1 hour |

## Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/Contoso-State/azure-sentinel-analytics-rules.git
cd azure-sentinel-analytics-rules
```

### 2. Update Parameters

Edit the parameter files in the `parameters/` directory to match your environment:

```bicep
// parameters/brute-force.bicepparam
using '../rules/brute-force.bicep'

param location = 'eastus'
param workspaceName = 'your-sentinel-workspace'  // Change this!
param enabled = true
```

### 3. Deploy a Single Rule

```bash
# Deploy using Azure CLI
az deployment group create \
  --resource-group <your-resource-group> \
  --template-file rules/brute-force.bicep \
  --parameters parameters/brute-force.bicepparam
```

### 4. Deploy All Rules

```bash
# Bash script to deploy all rules
for param_file in parameters/*.bicepparam; do
  rule_name=$(basename "$param_file" .bicepparam)
  echo "Deploying $rule_name..."
  az deployment group create \
    --resource-group <your-resource-group> \
    --template-file "rules/${rule_name}.bicep" \
    --parameters "$param_file"
done
```

## Deployment

### Using Azure CLI with Bicep

```bash
# Login to Azure
az login

# Set your subscription
az account set --subscription <subscription-id>

# Deploy a specific rule
az deployment group create \
  --resource-group <resource-group> \
  --template-file rules/password-spray.bicep \
  --parameters parameters/password-spray.bicepparam
```

### Using Azure PowerShell

```powershell
# Login to Azure
Connect-AzAccount

# Set your subscription
Set-AzContext -Subscription <subscription-id>

# Deploy a specific rule
New-AzResourceGroupDeployment `
  -ResourceGroupName <resource-group> `
  -TemplateFile rules/password-spray.bicep `
  -TemplateParameterFile parameters/password-spray.bicepparam
```

### Deployment Validation

After deployment, verify the rules in the Azure Portal:

1. Navigate to **Microsoft Sentinel** → **Analytics**
2. Look for rules with the display names listed in the table above
3. Check that the rules are **Enabled**
4. Review the **Last triggered** column after some time

## Customization

### Adjusting Detection Thresholds

Each rule supports customizable thresholds. Edit the parameter files to fine-tune for your environment:

```bicep
// Example: Adjust password spray threshold
param targetedUsersThreshold = 10  // Default is 5
param queryFrequency = 'PT5M'      // Run more frequently (default 10 min)
```

### Common Parameters

All rules support these standard parameters:

| Parameter | Description | Example |
|-----------|-------------|---------|
| `location` | Azure region | `'eastus'` |
| `workspaceName` | Sentinel workspace name | `'my-sentinel-workspace'` |
| `enabled` | Enable/disable the rule | `true` or `false` |
| `severity` | Alert severity | `'High'`, `'Medium'`, `'Low'`, `'Informational'` |
| `queryFrequency` | How often to run | `'PT5M'`, `'PT1H'` |
| `queryPeriod` | Lookback window | `'PT1H'`, `'PT24H'` |

### ISO 8601 Duration Format

Query frequency and period use ISO 8601 duration format:

- `PT5M` = 5 minutes
- `PT1H` = 1 hour
- `PT24H` = 24 hours
- `P1D` = 1 day

## Rule Details

### 1. Account Compromise Detection

**File:** `rules/account-compromise.bicep`

**Purpose:** Detects when an account is successfully compromised after multiple failed login attempts.

**Detection Logic:**
- Monitors SigninLogs for patterns of failed attempts followed by successful authentication
- Groups events by IP address and user principal name
- Triggers when failed attempts ≥ 3 and successful logins ≥ 1 within a 4-hour window

**Default Thresholds:**
- Failed logins: 3
- Successful logins: 1
- Lookback period: 4 hours
- Query frequency: Every 5 minutes

**Alert Example:**
```
CRITICAL: Account Compromised - user@example.com
Account user@example.com was compromised after 5 failed login attempts from 192.0.2.1.
Successful login detected.
```

**Investigation Questions:**
- Is this IP address known to the user?
- What applications were accessed after compromise?
- Were there subsequent suspicious activities from this account?

---

### 2. Brute Force Attack Detection

**File:** `rules/brute-force.bicep`

**Purpose:** Detects multiple failed authentication attempts from the same IP address.

**Detection Logic:**
- Monitors SigninLogs for failed logins (ResultType != 0)
- Excludes conditional access policy errors (50125, 50140)
- Groups by IP address and application
- Triggers when failed attempts ≥ 5 within 1 hour

**Default Thresholds:**
- Failed attempts: 5
- Lookback period: 1 hour
- Query frequency: Every 5 minutes

**Alert Example:**
```
Brute Force Attack Detected - 203.0.113.50
IP 203.0.113.50 made 15 failed login attempts to Microsoft Azure PowerShell.
This may indicate a brute force attack.
```

**Custom Details:**
- Failed login count
- Targeted accounts
- Application targeted
- Error codes
- First/last attempt timestamps

---

### 3. Password Spray Attack Detection

**File:** `rules/password-spray.bicep`

**Purpose:** Detects password spray attacks where one IP attempts to authenticate as multiple different users.

**Detection Logic:**
- Monitors SigninLogs for error code 50126 (invalid username or password)
- Counts distinct user principals per IP address
- Triggers when unique users targeted ≥ 5 from same IP within 1 hour

**Default Thresholds:**
- Targeted users: 5 unique accounts
- Lookback period: 1 hour
- Query frequency: Every 10 minutes

**Alert Example:**
```
Password Spray Attack - 198.51.100.10
IP 198.51.100.10 attempted to login to 12 different accounts with 48 total attempts.
This indicates password spraying.
```

**Why This Matters:**
Password spray attacks use a single password (or small set) against many accounts to avoid account lockouts. This is a common initial access technique.

---

### 4. App Registration Enumeration

**File:** `rules/app-enumeration.bicep`

**Purpose:** Detects excessive app registration and service principal enumeration operations, indicating reconnaissance.

**Detection Logic:**
- Monitors AuditLogs for app/service principal operations
- Tracks operations like "List applications", "Get application", "Get service principal"
- Can monitor a specific app ID or all apps
- Dynamic severity based on operation count (>50=High, >25=Medium, else Low)

**Default Thresholds:**
- Operation count: 10 operations per hour
- Lookback period: 24 hours
- Query frequency: Every 1 hour

**Alert Example:**
```
App Registration Enumeration: MyApp performed 35 operations
The service principal MyApp performed 35 operations. This may indicate reconnaissance activity.
```

**MITRE ATT&CK:**
- T1087.004 - Account Discovery: Cloud Account
- T1526 - Cloud Service Discovery

---

### 5. Cross-Tenant Service Principal Activity

**File:** `rules/cross-tenant-activity.bicep`

**Purpose:** Detects service principals accessing resources across tenant boundaries, indicating potential credential theft.

**Detection Logic:**
- Joins AADServicePrincipalSignInLogs with AuditLogs
- Correlates sign-ins with triggered audit events
- Triggers on excessive sign-ins (≥3) OR audit events (≥5)

**Default Thresholds:**
- Sign-in threshold: 3
- Audit events threshold: 5
- Lookback period: 24 hours
- Query frequency: Every 1 hour

**Alert Example:**
```
Suspicious Service Principal Activity: ContosoApp with 15 sign-ins
Service principal ContosoApp performed 15 sign-ins with 8 audit events.
Potential credential theft detected.
```

**Why This Matters:**
Stolen service principal credentials are often used to access resources in other tenants. This is a high-confidence indicator of compromise.

---

### 6. Failed Service Principal Authentications

**File:** `rules/sp-failed-auth.bicep`

**Purpose:** Detects credential stuffing or brute force attacks against service principals.

**Detection Logic:**
- Monitors AADServicePrincipalSignInLogs for failed authentications
- Groups by IP address in 1-hour bins
- Tracks unique apps targeted and failure codes
- Dynamic severity (>50=High, >20=Medium, else Low)

**Default Thresholds:**
- Failed attempts: 10
- Lookback period: 24 hours
- Query frequency: Every 1 hour

**Alert Example:**
```
Failed Authentication Attack: 42 attempts from 192.0.2.100
IP 192.0.2.100 made 42 failed authentication attempts against 3 apps.
```

---

### 7. Suspicious Service Principal Sign-In Activity

**File:** `rules/sp-signin-activity.bicep`

**Purpose:** Detects excessive sign-in activity from service principals, indicating credential abuse.

**Detection Logic:**
- Monitors AADServicePrincipalSignInLogs for sign-in volume
- Can monitor specific app ID or all service principals
- Tracks unique IPs, resources accessed, and result types
- Dynamic severity (>20 sign-ins = High, else Medium)

**Default Thresholds:**
- Sign-in threshold: 5 per hour
- Lookback period: 24 hours
- Query frequency: Every 1 hour

**Alert Example:**
```
Suspicious Sign-In Activity: BackupApp had 45 sign-ins
Service principal BackupApp performed 45 sign-ins. This may indicate credential abuse.
```

---

## MITRE ATT&CK Coverage

This rule collection provides detection coverage for the following MITRE ATT&CK techniques:

### Initial Access
- **T1078** - Valid Accounts
- **T1078.004** - Valid Accounts: Cloud Accounts

### Credential Access
- **T1110** - Brute Force
- **T1110.001** - Brute Force: Password Guessing
- **T1110.003** - Brute Force: Password Spraying

### Discovery
- **T1087** - Account Discovery
- **T1087.004** - Account Discovery: Cloud Account
- **T1526** - Cloud Service Discovery

### Persistence
- **T1098** - Account Manipulation

### Lateral Movement
- **T1550** - Use Alternate Authentication Material

### Full Coverage Matrix

| Technique | Tactic | Rule(s) |
|-----------|--------|---------|
| T1078 | Initial Access | Account Compromise, Brute Force, SP Sign-In |
| T1110 | Credential Access | Account Compromise, Brute Force, SP Failed Auth |
| T1110.001 | Credential Access | Brute Force |
| T1110.003 | Credential Access | Password Spray |
| T1087 | Discovery | Password Spray, App Enumeration |
| T1526 | Discovery | App Enumeration |
| T1098 | Persistence | Account Compromise |
| T1550 | Lateral Movement | Cross-Tenant Activity |

## Troubleshooting

### No Alerts Being Generated

1. **Check data ingestion:**
   ```kusto
   SigninLogs
   | where TimeGenerated > ago(1h)
   | summarize count()
   ```

2. **Verify diagnostic settings** are configured to send logs to your workspace

3. **Confirm Azure AD Premium licensing** for SignInLogs table

4. **Check rule is enabled** in Sentinel Analytics

### Rule Deployment Errors

Common issues and solutions:

| Error | Solution |
|-------|----------|
| Workspace not found | Verify workspace name in parameter file |
| Insufficient permissions | Ensure you have Sentinel Contributor role |
| Invalid parameter | Check parameter file syntax |

## Best Practices

1. **Start with Default Thresholds**: Deploy rules with defaults, then tune based on your environment
2. **Monitor False Positives**: Review alerts regularly and adjust thresholds accordingly
3. **Enable Gradually**: Deploy rules one at a time to baseline behavior
4. **Document Exclusions**: If you exclude specific IPs or accounts, document why
5. **Regular Review**: Review and update rules quarterly as threats evolve

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-rule`)
3. Make your changes
4. Test thoroughly in a development environment
5. Submit a pull request with:
   - Description of the detection logic
   - MITRE ATT&CK mapping
   - Sample parameter file
   - Documentation

## Support and Feedback

- **Issues**: Report bugs or request features via [GitHub Issues](https://github.com/Contoso-State/azure-sentinel-analytics-rules/issues)
- **Discussions**: Ask questions in [GitHub Discussions](https://github.com/Contoso-State/azure-sentinel-analytics-rules/discussions)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Microsoft Sentinel documentation and community
- MITRE ATT&CK framework
- Azure security community contributors

---

**Disclaimer**: These analytics rules are provided as-is for detection purposes. Always test in a non-production environment before deploying to production. Adjust thresholds based on your organization's risk tolerance and operational requirements.
