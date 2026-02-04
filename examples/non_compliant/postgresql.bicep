// Non-compliant Azure Database for PostgreSQL template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param serverName string = 'myinsecure-postgresql'

// Non-compliant PostgreSQL - Multiple security issues:
// - Public network access enabled
// - No private endpoints
// - Password authentication enabled (not Entra-only)
// - No connection/disconnection logging
// - No geo-redundant backup
resource postgresServer 'Microsoft.DBforPostgreSQL/flexibleServers@2023-03-01-preview' = {
  name: serverName
  location: location
  sku: {
    name: 'Standard_B1ms'
    tier: 'Burstable'
  }
  properties: {
    version: '15'
    administratorLogin: 'pgadmin'
    administratorLoginPassword: 'P@ssw0rd123!'
    publicNetworkAccess: 'Enabled'
    authConfig: {
      activeDirectoryAuth: 'Disabled'
      passwordAuth: 'Enabled'
    }
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: 7
      geoRedundantBackup: 'Disabled'
    }
  }
}
