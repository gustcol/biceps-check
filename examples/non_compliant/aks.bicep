// Non-compliant Azure Kubernetes Service template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param clusterName string = 'myinsecure-aks'

// Non-compliant AKS - Multiple security issues:
// - RBAC disabled
// - No network policy
// - Public cluster (not private)
// - No managed identity
// - No Azure AD integration
// - No API server authorized IP ranges
// - No Defender profile
// - Local accounts enabled
// - No Azure Policy add-on
// - HTTP application routing enabled
resource aksCluster 'Microsoft.ContainerService/managedClusters@2023-07-01' = {
  name: clusterName
  location: location
  properties: {
    dnsPrefix: clusterName
    enableRBAC: false
    kubernetesVersion: '1.27.3'
    agentPoolProfiles: [
      {
        name: 'agentpool'
        count: 3
        vmSize: 'Standard_D2s_v3'
        osType: 'Linux'
        mode: 'System'
      }
    ]
    networkProfile: {
      networkPlugin: 'azure'
    }
    apiServerAccessProfile: {
      enablePrivateCluster: false
    }
    addonProfiles: {
      httpApplicationRouting: {
        enabled: true
      }
    }
  }
}
