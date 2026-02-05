// Non-compliant Azure SQL Server template
// This template demonstrates security misconfigurations

param location string = resourceGroup().location
param serverName string = 'myinsecure-sqlserver'

// Non-compliant SQL Server - Multiple security issues:
// - No Azure AD admin configured
// - No auditing
// - No threat detection
// - TLS version below 1.2
// - Public network access enabled
// - Local authentication (no Azure AD-only auth)
// - No vulnerability assessment
resource sqlServer 'Microsoft.Sql/servers@2023-05-01-preview' = {
  name: serverName
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    administratorLoginPassword: 'P@ssw0rd123!'
    minimalTlsVersion: '1.0'
    publicNetworkAccess: 'Enabled'
  }
}

// SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-05-01-preview' = {
  parent: sqlServer
  name: 'myinsecure-database'
  location: location
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
}

// Firewall rule allowing all Azure IPs (overly permissive)
resource firewallRule 'Microsoft.Sql/servers/firewallRules@2023-05-01-preview' = {
  parent: sqlServer
  name: 'AllowAllAzureIPs'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}
