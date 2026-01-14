using '../rules/sp-failed-auth.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Detection thresholds
param failedAttemptsThreshold = 10
param lookbackPeriodHours = 24

// Query scheduling
param queryFrequency = 'PT1H'   // Run every 1 hour
param queryPeriod = 'PT24H'     // Look back 24 hours

// Rule configuration
param severity = 'Medium'
param enabled = true
