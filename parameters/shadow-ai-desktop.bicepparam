using '../rules/shadow-ai-desktop.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Minimum connection count to trigger alert
param usageThreshold = 3

// Lookback period in hours
param timeWindowHours = 1

// Comma-separated excluded accounts (service accounts, admins)
param excludedUsers = ''

// Query scheduling
param queryFrequency = 'PT15M'   // Run every 15 minutes
param queryPeriod = 'PT1H'       // Look back 1 hour

// Rule configuration
param severity = 'High'
param enabled = true
