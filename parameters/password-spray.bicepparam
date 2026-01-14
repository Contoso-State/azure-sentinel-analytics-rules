using '../rules/password-spray.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Detection thresholds
param targetedUsersThreshold = 5
param lookbackPeriodHours = 1

// Query scheduling
param queryFrequency = 'PT10M'  // Run every 10 minutes
param queryPeriod = 'PT1H'      // Look back 1 hour

// Rule configuration
param severity = 'High'
param enabled = true
