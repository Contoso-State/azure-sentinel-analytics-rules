using '../rules/app-enumeration.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Specific app ID to monitor (leave empty to monitor all apps)
param suspiciousAppId = ''

// Detection thresholds
param operationThreshold = 10
param lookbackPeriodHours = 24

// Query scheduling
param queryFrequency = 'PT1H'   // Run every 1 hour
param queryPeriod = 'PT24H'     // Look back 24 hours

// Rule configuration
param severity = 'Medium'
param enabled = true
