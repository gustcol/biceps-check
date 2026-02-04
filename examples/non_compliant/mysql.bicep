// Non-compliant Azure Database for MySQL template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param serverName string = 'myinsecure-mysql'

// Non-compliant MySQL - Multiple security issues:
// - Public network access enabled
// - No private endpoints
// - No Entra authentication
// - No audit logging
// - No geo-redundant backup
// - No high availability
resource mysqlServer 'Microsoft.DBforMySQL/flexibleServers@2023-06-30' = {
  name: serverName
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '8.0.21'
    administratorLogin: 'mysqladmin'
    administratorLoginPassword: 'P@ssw0rd123!'
    publicNetworkAccess: 'Enabled'
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
  }
}
