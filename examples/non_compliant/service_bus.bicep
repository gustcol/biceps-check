// Non-compliant Azure Service Bus template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param serviceBusName string = 'myinsecure-servicebus'

// Non-compliant Service Bus - Multiple security issues:
// - Standard SKU (no Premium security features)
// - Public network access enabled
// - TLS 1.0 allowed
// - Local authentication enabled
// - No zone redundancy
resource serviceBus 'Microsoft.ServiceBus/namespaces@2022-10-01-preview' = {
  name: serviceBusName
  location: location
  sku: {
    name: 'Standard'
    tier: 'Standard'
  }
  properties: {
    publicNetworkAccess: 'Enabled'
    minimumTlsVersion: '1.0'
    disableLocalAuth: false
    zoneRedundant: false
  }
}
