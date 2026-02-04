// Non-Compliant Storage Account Example
// This example demonstrates common security misconfigurations

@description('The location for the storage account')
param location string = resourceGroup().location

@description('The name of the storage account')
param storageAccountName string

// INSECURE: This storage account has multiple security issues
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: storageAccountName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    // FAIL BCK_AZURE_ST_001: HTTPS not enforced
    supportsHttpsTrafficOnly: false

    // FAIL BCK_AZURE_ST_002: Using weak TLS version
    minimumTlsVersion: 'TLS1_0'

    // FAIL BCK_AZURE_ST_004: Public blob access enabled
    allowBlobPublicAccess: true

    // FAIL BCK_AZURE_ST_009: Shared key access enabled
    allowSharedKeyAccess: true

    // FAIL BCK_AZURE_ST_005: No network restrictions
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'None'
      virtualNetworkRules: []
      ipRules: []
    }

    // FAIL BCK_AZURE_ST_008: No infrastructure encryption
    encryption: {
      requireInfrastructureEncryption: false
      services: {
        blob: {
          enabled: true
        }
      }
      keySource: 'Microsoft.Storage'
    }
  }
}

// Blob services without soft delete
resource blobServices 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageAccount
  name: 'default'
  properties: {
    // FAIL BCK_AZURE_ST_006: Blob soft delete disabled
    deleteRetentionPolicy: {
      enabled: false
    }
    // FAIL BCK_AZURE_ST_007: Container soft delete disabled
    containerDeleteRetentionPolicy: {
      enabled: false
    }
  }
}

// FAIL BCK_AZURE_BLOB_001: Public container
resource publicContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobServices
  name: 'public-container'
  properties: {
    publicAccess: 'Container'
  }
}

output storageAccountId string = storageAccount.id
