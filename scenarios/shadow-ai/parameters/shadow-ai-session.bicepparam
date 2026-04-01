using '../rules/shadow-ai-session.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Minimum connection count to trigger alert (1 = any confirmed connection)
param usageThreshold = 1

// Lookback period in hours
param timeWindowHours = 1

// UPN domain suffix for SAM-to-UPN fallback
param domainSuffix = 'contoso.com'

// Comma-separated excluded accounts (service accounts, admins)
param excludedUsers = ''

// Query scheduling
param queryFrequency = 'PT15M'   // Run every 15 minutes
param queryPeriod = 'PT1H'       // Look back 1 hour

// Rule configuration
param severity = 'Medium'
param enabled = true
