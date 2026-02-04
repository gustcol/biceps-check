// Non-compliant Azure Event Hub template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param eventHubName string = 'myinsecure-eventhub'

// Non-compliant Event Hub - Multiple security issues:
// - Public network access enabled
// - TLS 1.0 allowed
// - Local authentication enabled
// - No zone redundancy
// - Auto-inflate disabled
resource eventHub 'Microsoft.EventHub/namespaces@2023-01-01-preview' = {
  name: eventHubName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
    capacity: 1
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    minimumTlsVersion: '1.0'
    disableLocalAuth: false
    zoneRedundant: false
    isAutoInflateEnabled: false
  }
}
