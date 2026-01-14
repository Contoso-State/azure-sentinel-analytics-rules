using '../rules/brute-force.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Detection thresholds
param failedAttemptsThreshold = 5
param lookbackPeriodHours = 1

// Query scheduling
param queryFrequency = 'PT5M'  // Run every 5 minutes
param queryPeriod = 'PT1H'     // Look back 1 hour

// Rule configuration
param severity = 'High'
param enabled = true
