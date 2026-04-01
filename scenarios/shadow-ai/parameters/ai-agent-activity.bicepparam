using '../rules/ai-agent-activity.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Threshold for total write operations to trigger alert
param writeThreshold = 10

// Lookback period in hours
param timeWindowHours = 1

// Comma-separated excluded accounts (service accounts, admins)
param excludedUsers = ''

// Query scheduling
param queryFrequency = 'PT1H'    // Run every 1 hour
param queryPeriod = 'PT1H'       // Look back 1 hour

// Rule configuration
param severity = 'Informational'
param enabled = true
