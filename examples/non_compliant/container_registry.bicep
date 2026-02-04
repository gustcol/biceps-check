// Non-compliant Azure Container Registry template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param acrName string = 'myinsecureacr'

// Non-compliant ACR - Multiple security issues:
// - Admin user enabled
// - Basic SKU (no security features)
// - Public network access enabled
// - No content trust
// - No retention policy
// - Anonymous pull enabled
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: acrName
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: true
    publicNetworkAccess: 'Enabled'
    anonymousPullEnabled: true
    policies: {
      trustPolicy: {
        status: 'disabled'
      }
      retentionPolicy: {
        status: 'disabled'
      }
      exportPolicy: {
        status: 'enabled'
      }
    }
  }
}
