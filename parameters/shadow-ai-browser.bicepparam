using '../rules/shadow-ai-browser.bicep'

// Azure region for deployment
param location = 'eastus'

// Name of existing Log Analytics workspace with Sentinel enabled
param workspaceName = 'your-sentinel-workspace'

// Minimum connection count to trigger alert (reduce for stricter policy)
param usageThreshold = 3

// Lookback period in hours
param timeWindowHours = 1

// Shadow AI domains to monitor — extend with organization-specific blocked domains
// param shadowAIDomains = '["chat.openai.com","chatgpt.com","api.openai.com","cdn.oaistatic.com","claude.ai","api.anthropic.com","gemini.google.com","bard.google.com","generativelanguage.googleapis.com","copilot.microsoft.com","sydney.bing.com","edgeservices.bing.com","chat.deepseek.com","api.deepseek.com","perplexity.ai","www.perplexity.ai","grok.com","x.ai","poe.com","www.poe.com"]'

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
