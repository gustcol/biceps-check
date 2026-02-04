// Non-compliant Virtual Machine template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param vmName string = 'myInsecureVM'
param adminUsername string = 'adminUser'
@secure()
param adminPassword string

// Non-compliant VM - Multiple security issues:
// - No managed identity
// - No boot diagnostics
// - No disk encryption
// - No secure boot/vTPM
// - Password authentication enabled for Linux
resource vm 'Microsoft.Compute/virtualMachines@2023-07-01' = {
  name: vmName
  location: location
  properties: {
    hardwareProfile: {
      vmSize: 'Standard_D2s_v3'
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: {
        disablePasswordAuthentication: false
        patchSettings: {
          patchMode: 'Manual'
        }
      }
      allowExtensionOperations: false
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: 'UbuntuServer'
        sku: '18.04-LTS'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'Standard_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterface.id
        }
      ]
    }
  }
}

// Public IP - Direct exposure
resource publicIP 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${vmName}-pip'
  location: location
  properties: {
    publicIPAllocationMethod: 'Static'
  }
}

// Network interface with public IP
resource networkInterface 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${vmName}-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: '/subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Network/virtualNetworks/xxx/subnets/xxx'
          }
          publicIPAddress: {
            id: publicIP.id
          }
        }
      }
    ]
  }
}
