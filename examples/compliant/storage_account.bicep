// Compliant Storage Account Example
// This example demonstrates security best practices for Azure Storage Accounts

@description('The location for the storage account')
param location string = resourceGroup().location

@description('The name of the storage account')
param storageAccountName string

@description('Virtual Network ID for private endpoint')
param vnetId string

@description('Subnet ID for private endpoint')
param subnetId string

// Compliant storage account with all security features enabled
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS'
  }
  properties: {
    // BCK_AZURE_ST_001: HTTPS only enabled
    supportsHttpsTrafficOnly: true

    // BCK_AZURE_ST_002: Minimum TLS 1.2
    minimumTlsVersion: 'TLS1_2'

    // BCK_AZURE_ST_004: Public blob access disabled
    allowBlobPublicAccess: false

    // BCK_AZURE_ST_009: Shared key access disabled
    allowSharedKeyAccess: false

    // BCK_AZURE_ST_005: Network rules configured with default deny
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: [
        {
          id: subnetId
          action: 'Allow'
        }
      ]
      ipRules: []
    }

    // BCK_AZURE_ST_008: Infrastructure encryption enabled
    encryption: {
      requireInfrastructureEncryption: true
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
        table: {
          enabled: true
        }
        queue: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }

  tags: {
    environment: 'production'
    securityCompliance: 'CIS-Azure'
  }
}

// Blob services with soft delete enabled
resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    // BCK_AZURE_ST_006: Blob soft delete enabled
    deleteRetentionPolicy: {
      enabled: true
      days: 14
    }
    // BCK_AZURE_ST_007: Container soft delete enabled
    containerDeleteRetentionPolicy: {
      enabled: true
      days: 14
    }
    // Versioning enabled for additional protection
    isVersioningEnabled: true
  }
}

// Private endpoint for secure access
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: '${storageAccountName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${storageAccountName}-connection'
        properties: {
          privateLinkServiceId: storageAccount.id
          groupIds: [
            'blob'
          ]
        }
      }
    ]
  }
}

output storageAccountId string = storageAccount.id
output storageAccountName string = storageAccount.name
