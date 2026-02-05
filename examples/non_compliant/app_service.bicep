// Non-compliant Azure App Service template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param appName string = 'myinsecure-webapp'

// Non-compliant App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2023-01-01' = {
  name: '${appName}-plan'
  location: location
  sku: {
    name: 'B1'
    tier: 'Basic'
  }
}

// Non-compliant App Service - Multiple security issues:
// - HTTPS not enforced
// - TLS version below 1.2
// - No managed identity
// - FTP enabled
// - No authentication
// - Remote debugging enabled
// - No client certificates
// - No VNet integration
// - No diagnostic logs
resource webApp 'Microsoft.Web/sites@2023-01-01' = {
  name: appName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
      ftpsState: 'AllAllowed'
      remoteDebuggingEnabled: true
      http20Enabled: false
    }
    clientCertEnabled: false
  }
}
