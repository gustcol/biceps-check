// Non-compliant Azure Cache for Redis template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param redisName string = 'myinsecure-redis'

// Non-compliant Redis - Multiple security issues:
// - Basic SKU (no security features)
// - Non-SSL port enabled
// - TLS 1.0 allowed
// - Public network access enabled
// - No zone redundancy
resource redis 'Microsoft.Cache/redis@2023-08-01' = {
  name: redisName
  location: location
  properties: {
    sku: {
      name: 'Basic'
      family: 'C'
      capacity: 0
    }
    enableNonSslPort: true
    minimumTlsVersion: '1.0'
    publicNetworkAccess: 'Enabled'
    redisConfiguration: {
      'maxmemory-policy': 'volatile-lru'
    }
  }
}
