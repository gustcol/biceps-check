// Non-Compliant Network Security Group Example
// This example demonstrates common NSG security misconfigurations

@description('The location for the NSG')
param location string = resourceGroup().location

@description('The name of the NSG')
param nsgName string

// INSECURE: This NSG has multiple security issues
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: nsgName
  location: location
  properties: {
    securityRules: [
      // FAIL BCK_AZURE_NSG_001: SSH open to internet
      {
        name: 'Allow-SSH-From-Internet'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          // FAIL BCK_AZURE_NSG_006: Missing description
        }
      }
      // FAIL BCK_AZURE_NSG_002: RDP open to internet
      {
        name: 'Allow-RDP-From-Internet'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '0.0.0.0/0'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
        }
      }
      // FAIL BCK_AZURE_NSG_003: All ports open to internet
      {
        name: 'Allow-All-From-Internet'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: '*'
          sourceAddressPrefix: 'Internet'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
      // FAIL BCK_AZURE_NSG_005: Database port open to internet
      {
        name: 'Allow-SQL-From-Internet'
        properties: {
          priority: 130
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '1433'
        }
      }
    ]
  }
  // FAIL BCK_AZURE_NSG_007: No explicit default deny rule
}

output nsgId string = nsg.id
