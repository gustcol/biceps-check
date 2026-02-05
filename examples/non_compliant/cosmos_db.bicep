// Non-compliant Azure Cosmos DB template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param accountName string = 'myinsecure-cosmosdb'

// Non-compliant Cosmos DB - Multiple security issues:
// - No firewall rules (open to all networks)
// - Public network access enabled
// - No automatic failover
// - Local authentication enabled
// - No continuous backup
// - No diagnostic logs
// - No virtual network rules
resource cosmosDBAccount 'Microsoft.DocumentDB/databaseAccounts@2023-04-15' = {
  name: accountName
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    publicNetworkAccess: 'Enabled'
    enableAutomaticFailover: false
    disableLocalAuth: false
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
      }
    ]
    backupPolicy: {
      type: 'Periodic'
      periodicModeProperties: {
        backupIntervalInMinutes: 240
        backupRetentionIntervalInHours: 8
      }
    }
  }
}
