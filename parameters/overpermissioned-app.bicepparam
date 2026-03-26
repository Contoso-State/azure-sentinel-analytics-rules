using '../rules/overpermissioned-app.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Comma-separated UPNs to exclude from email send detection
// Example: '"admin@contoso.com","noreply@contoso.com"'
param excludedUsers = ''

// Comma-separated app names to exclude from SP activity detection
param excludedApps = '"Microsoft Graph","Azure Portal","Microsoft Azure CLI"'

// Detection thresholds
param sensitivePermissionThreshold = 3   // Min sensitive permissions for over-permissioned alert
param emailSendThreshold = 5            // Min emails in window to trigger mass send alert
param emailSendWindowMinutes = 15       // Window for email send spike
param spSignInThreshold = 5             // Min SP API calls for bulk activity alert
param lookbackPeriodHours = 1           // Lookback for email/SP detection
param permissionLookbackDays = 7        // Lookback for permission grant detection

// Query scheduling
param queryFrequency = 'PT1H'    // Run every 1 hour
param queryPeriod = 'P7D'       // Look back 7 days (for permission grants)

// Rule configuration
param severity = 'High'
param enabled = true
