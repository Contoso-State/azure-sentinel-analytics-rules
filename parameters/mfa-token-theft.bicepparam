using '../rules/mfa-token-theft.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Comma-separated UPNs to exclude (known admin/service accounts)
// Example: '"admin@contoso.com","svc-backup@contoso.com"'
param excludedUsers = ''

// Detection thresholds
param mfaPasswordWindowMinutes = 30    // MFA change + password reset correlation window
param tokenReplayWindowMinutes = 15    // Multi-IP sign-in detection window
param multiIpThreshold = 2            // Minimum distinct IPs for token replay
param lookbackPeriodHours = 1

// Query scheduling
param queryFrequency = 'PT5M'    // Run every 5 minutes (high priority detection)
param queryPeriod = 'PT1H'      // Look back 1 hour

// Rule configuration
param severity = 'High'
param enabled = true
