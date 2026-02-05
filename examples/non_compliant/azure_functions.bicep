// Non-compliant Azure Functions template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param functionAppName string = 'myinsecure-functions'

// Non-compliant App Service Plan for Functions
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: '${functionAppName}-plan'
  location: location
  sku: {
    name: 'Y1'
    tier: 'Dynamic'
  }
}

// Non-compliant Function App - Multiple security issues:
// - HTTPS not enforced
// - No managed identity
// - No authentication
// - Outdated runtime
// - No Application Insights
// - No private endpoints
// - Public network access enabled
// - TLS version below 1.2
resource functionApp 'Microsoft.Web/sites@2023-01-01' = {
  name: functionAppName
  location: location
  kind: 'functionapp'
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: false
    publicNetworkAccess: 'Enabled'
    siteConfig: {
      minTlsVersion: '1.0'
      appSettings: [
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~3'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'node'
        }
      ]
    }
  }
}
