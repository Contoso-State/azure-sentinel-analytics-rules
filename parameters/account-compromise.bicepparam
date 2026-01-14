using '../rules/account-compromise.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Detection thresholds
param failedLoginsThreshold = 3
param successfulLoginsThreshold = 1
param lookbackPeriodHours = 4

// Query scheduling
param queryFrequency = 'PT5M'  // Run every 5 minutes
param queryPeriod = 'PT4H'     // Look back 4 hours

// Rule configuration
param severity = 'High'
param enabled = true
