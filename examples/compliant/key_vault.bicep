// Compliant Key Vault Example
// This example demonstrates security best practices for Azure Key Vault

@description('The location for the Key Vault')
param location string = resourceGroup().location

@description('The name of the Key Vault')
param keyVaultName string

@description('Subnet ID for private endpoint')
param subnetId string

@description('Tenant ID')
param tenantId string = subscription().tenantId

// Compliant Key Vault with all security features enabled
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    tenantId: tenantId

    // BCK_AZURE_KV_003: Using RBAC for access control
    enableRbacAuthorization: true

    // BCK_AZURE_KV_002: Soft delete enabled
    enableSoftDelete: true
    softDeleteRetentionInDays: 90

    // BCK_AZURE_KV_001: Purge protection enabled
    enablePurgeProtection: true

    // BCK_AZURE_KV_005: Public network access disabled (for private endpoint)
    publicNetworkAccess: 'Disabled'

    // BCK_AZURE_KV_004: Network rules with default deny
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
      virtualNetworkRules: []
      ipRules: []
    }

    sku: {
      family: 'A'
      name: 'premium'  // Premium SKU for HSM-backed keys
    }
  }

  tags: {
    environment: 'production'
    compliance: 'CIS-Azure'
  }
}

// Private endpoint for secure access
resource privateEndpoint 'Microsoft.Network/privateEndpoints@2023-05-01' = {
  name: '${keyVaultName}-pe'
  location: location
  properties: {
    subnet: {
      id: subnetId
    }
    privateLinkServiceConnections: [
      {
        name: '${keyVaultName}-connection'
        properties: {
          privateLinkServiceId: keyVault.id
          groupIds: [
            'vault'
          ]
        }
      }
    ]
  }
}

// Diagnostic settings for audit logging
resource diagnosticSettings 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  name: '${keyVaultName}-diagnostics'
  scope: keyVault
  properties: {
    logs: [
      {
        category: 'AuditEvent'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 365
        }
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
        retentionPolicy: {
          enabled: true
          days: 90
        }
      }
    ]
  }
}

output keyVaultId string = keyVault.id
output keyVaultUri string = keyVault.properties.vaultUri
