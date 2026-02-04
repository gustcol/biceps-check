// Non-compliant Azure Data Factory template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param factoryName string = 'myinsecure-datafactory'

// Non-compliant Data Factory - Multiple security issues:
// - No managed identity
// - Public network access enabled
// - No customer-managed key encryption
// - No Git integration
resource dataFactory 'Microsoft.DataFactory/factories@2018-06-01' = {
  name: factoryName
  location: location
  properties: {
    publicNetworkAccess: 'Enabled'
  }
}
