# Biceps-Check: Azure Bicep Security Scanner - Project TODO

> A comprehensive security scanning tool for Azure Bicep templates, inspired by Checkov's approach to infrastructure-as-code security.

---

## 📋 Table of Contents

1. [Project Overview](#project-overview)
2. [Phase 1: Project Foundation](#phase-1-project-foundation)
3. [Phase 2: Core Engine Development](#phase-2-core-engine-development)
4. [Phase 3: Security Rules Implementation](#phase-3-security-rules-implementation)
5. [Phase 4: Azure Resource Coverage](#phase-4-azure-resource-coverage)
6. [Phase 5: Testing & Quality Assurance](#phase-5-testing--quality-assurance)
7. [Phase 6: Documentation](#phase-6-documentation)
8. [Phase 7: CI/CD Integration](#phase-7-cicd-integration)
9. [Phase 8: Advanced Features](#phase-8-advanced-features)

---

## Project Overview

### Goals
- Create a Python-based CLI tool for scanning Azure Bicep files
- Implement 500+ security rules covering all Azure resource types
- Provide clear, actionable remediation guidance
- Support multiple output formats (CLI, JSON, SARIF, JUnit)
- Enable CI/CD pipeline integration
- Maintain comprehensive documentation

### Architecture
```
biceps-check/
├── src/
│   └── biceps_check/
│       ├── __init__.py
│       ├── cli.py                 # CLI entry point
│       ├── runner.py              # Main scanner orchestrator
│       ├── parser/                # Bicep file parsing
│       ├── rules/                 # Security rules engine
│       ├── checks/                # Individual security checks
│       ├── output/                # Output formatters
│       └── utils/                 # Utility functions
├── tests/
├── docs/
├── examples/
└── rules_catalog/
```

---

## Phase 1: Project Foundation

### 1.1 Repository Setup
- [ ] Initialize Python project structure with `pyproject.toml`
- [ ] Configure Poetry/pip for dependency management
- [ ] Set up pre-commit hooks (black, isort, flake8, mypy)
- [ ] Create `.gitignore` for Python projects
- [ ] Set up GitHub Actions workflow skeleton
- [ ] Configure EditorConfig for consistent formatting
- [ ] Create CONTRIBUTING.md guidelines
- [ ] Set up issue and PR templates

### 1.2 Core Dependencies
- [ ] Select and configure Bicep parser library
- [ ] Add CLI framework (Click or Typer)
- [ ] Add logging framework (structlog)
- [ ] Add testing framework (pytest)
- [ ] Add type checking (mypy)
- [ ] Add code coverage (pytest-cov)

### 1.3 Project Configuration
- [ ] Define configuration file format (YAML/TOML)
- [ ] Implement configuration loading
- [ ] Support environment variable overrides
- [ ] Create default configuration template
- [ ] Document all configuration options

---

## Phase 2: Core Engine Development

### 2.1 Bicep Parser
- [ ] Implement Bicep file reader
- [ ] Parse resource declarations
- [ ] Extract resource properties
- [ ] Handle module references
- [ ] Support parameter files
- [ ] Handle variable substitution
- [ ] Parse conditional deployments
- [ ] Support loops and iterations
- [ ] Handle nested resources
- [ ] Extract output definitions

### 2.2 Rule Engine
- [ ] Design rule base class/interface
- [ ] Implement rule registry
- [ ] Create rule loading mechanism
- [ ] Support rule severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- [ ] Implement rule categorization (tags)
- [ ] Support custom rule definitions
- [ ] Implement rule enable/disable mechanism
- [ ] Create rule skip annotations support
- [ ] Implement rule inheritance

### 2.3 Scanner Runner
- [ ] Implement file discovery (recursive scanning)
- [ ] Create parallel scanning support
- [ ] Implement result aggregation
- [ ] Add progress reporting
- [ ] Support incremental scanning
- [ ] Implement caching mechanism
- [ ] Add scan statistics collection

### 2.4 Output Formatters
- [ ] CLI formatter (colored, table format)
- [ ] JSON formatter
- [ ] SARIF formatter (for GitHub Security)
- [ ] JUnit XML formatter
- [ ] CSV formatter
- [ ] HTML report formatter
- [ ] Markdown formatter
- [ ] GitLab Code Quality formatter

---

## Phase 3: Security Rules Implementation

### 3.1 Rule Categories
Each rule should include:
- Unique ID (e.g., `BCK_AZURE_001`)
- Title and description
- Severity level
- Affected resource types
- Detection logic
- Remediation guidance
- References (CIS, NIST, Azure Well-Architected)
- Compliant and non-compliant examples

### 3.2 Rule Severity Definitions
| Severity | Description |
|----------|-------------|
| CRITICAL | Immediate security risk, data exposure, or compliance violation |
| HIGH | Significant security weakness requiring prompt attention |
| MEDIUM | Security best practice violation with moderate risk |
| LOW | Minor security improvement recommendation |
| INFO | Informational finding or best practice suggestion |

### 3.3 Compliance Frameworks Mapping
- [ ] CIS Azure Foundations Benchmark
- [ ] NIST 800-53
- [ ] PCI DSS
- [ ] HIPAA
- [ ] SOC 2
- [ ] ISO 27001
- [ ] Azure Security Benchmark
- [ ] GDPR

---

## Phase 4: Azure Resource Coverage

### 4.1 Compute Resources
#### Virtual Machines (`Microsoft.Compute/virtualMachines`)
- [ ] BCK_AZURE_VM_001: VM should have managed disks enabled
- [ ] BCK_AZURE_VM_002: VM disk encryption should be enabled
- [ ] BCK_AZURE_VM_003: VM should not use basic public IP
- [ ] BCK_AZURE_VM_004: VM should have boot diagnostics enabled
- [ ] BCK_AZURE_VM_005: VM should use managed identity
- [ ] BCK_AZURE_VM_006: VM should not have public IP directly attached
- [ ] BCK_AZURE_VM_007: VM extensions should be monitored
- [ ] BCK_AZURE_VM_008: VM should have automatic OS updates enabled
- [ ] BCK_AZURE_VM_009: VM should use Azure Hybrid Benefit where applicable
- [ ] BCK_AZURE_VM_010: VM should have endpoint protection installed

#### Virtual Machine Scale Sets (`Microsoft.Compute/virtualMachineScaleSets`)
- [ ] BCK_AZURE_VMSS_001: VMSS should have automatic OS upgrades enabled
- [ ] BCK_AZURE_VMSS_002: VMSS should use managed disks
- [ ] BCK_AZURE_VMSS_003: VMSS should have health probes configured
- [ ] BCK_AZURE_VMSS_004: VMSS instances should use managed identity
- [ ] BCK_AZURE_VMSS_005: VMSS should have encryption at host enabled

#### App Service (`Microsoft.Web/sites`)
- [ ] BCK_AZURE_APP_001: App Service should use HTTPS only
- [ ] BCK_AZURE_APP_002: App Service should use latest TLS version
- [ ] BCK_AZURE_APP_003: App Service should have managed identity enabled
- [ ] BCK_AZURE_APP_004: App Service should disable FTP
- [ ] BCK_AZURE_APP_005: App Service should use latest runtime version
- [ ] BCK_AZURE_APP_006: App Service should have authentication enabled
- [ ] BCK_AZURE_APP_007: App Service should not be accessible from internet (if internal)
- [ ] BCK_AZURE_APP_008: App Service should have diagnostic logs enabled
- [ ] BCK_AZURE_APP_009: App Service should use private endpoints
- [ ] BCK_AZURE_APP_010: App Service should have client certificates enabled
- [ ] BCK_AZURE_APP_011: App Service should use VNET integration
- [ ] BCK_AZURE_APP_012: App Service should have remote debugging disabled
- [ ] BCK_AZURE_APP_013: App Service should have minimum TLS 1.2
- [ ] BCK_AZURE_APP_014: App Service should restrict CORS origins
- [ ] BCK_AZURE_APP_015: App Service slots should have same security config

#### App Service Plan (`Microsoft.Web/serverfarms`)
- [ ] BCK_AZURE_ASP_001: App Service Plan should not be Free/Shared tier for production
- [ ] BCK_AZURE_ASP_002: App Service Plan should have zone redundancy enabled
- [ ] BCK_AZURE_ASP_003: App Service Plan should have auto-scale configured

#### Azure Functions (`Microsoft.Web/sites` kind: functionapp)
- [ ] BCK_AZURE_FUNC_001: Function App should use HTTPS only
- [ ] BCK_AZURE_FUNC_002: Function App should use managed identity
- [ ] BCK_AZURE_FUNC_003: Function App should have authentication enabled
- [ ] BCK_AZURE_FUNC_004: Function App should use latest runtime
- [ ] BCK_AZURE_FUNC_005: Function App should have application insights enabled
- [ ] BCK_AZURE_FUNC_006: Function App should use private endpoints
- [ ] BCK_AZURE_FUNC_007: Function App should disable public network access

#### Container Instances (`Microsoft.ContainerInstance/containerGroups`)
- [ ] BCK_AZURE_ACI_001: Container should not run as root
- [ ] BCK_AZURE_ACI_002: Container should use private registry
- [ ] BCK_AZURE_ACI_003: Container should have resource limits defined
- [ ] BCK_AZURE_ACI_004: Container should not expose unnecessary ports
- [ ] BCK_AZURE_ACI_005: Container should use secure environment variables
- [ ] BCK_AZURE_ACI_006: Container should use VNET integration

#### Azure Kubernetes Service (`Microsoft.ContainerService/managedClusters`)
- [ ] BCK_AZURE_AKS_001: AKS should have RBAC enabled
- [ ] BCK_AZURE_AKS_002: AKS should use Azure CNI networking
- [ ] BCK_AZURE_AKS_003: AKS should have network policy enabled
- [ ] BCK_AZURE_AKS_004: AKS should have Azure Policy add-on enabled
- [ ] BCK_AZURE_AKS_005: AKS should have private cluster enabled
- [ ] BCK_AZURE_AKS_006: AKS should use managed identity
- [ ] BCK_AZURE_AKS_007: AKS should have API server authorized IP ranges
- [ ] BCK_AZURE_AKS_008: AKS should have Azure AD integration enabled
- [ ] BCK_AZURE_AKS_009: AKS should have disk encryption set configured
- [ ] BCK_AZURE_AKS_010: AKS should have auto-upgrade channel configured
- [ ] BCK_AZURE_AKS_011: AKS should have defender profile enabled
- [ ] BCK_AZURE_AKS_012: AKS should disable local accounts
- [ ] BCK_AZURE_AKS_013: AKS node pools should have encryption at host
- [ ] BCK_AZURE_AKS_014: AKS should have HTTP application routing disabled
- [ ] BCK_AZURE_AKS_015: AKS should have secrets store CSI driver enabled

#### Container Registry (`Microsoft.ContainerRegistry/registries`)
- [ ] BCK_AZURE_ACR_001: ACR should have admin user disabled
- [ ] BCK_AZURE_ACR_002: ACR should use private endpoints
- [ ] BCK_AZURE_ACR_003: ACR should have content trust enabled
- [ ] BCK_AZURE_ACR_004: ACR should have public network access disabled
- [ ] BCK_AZURE_ACR_005: ACR should have SKU Premium for security features
- [ ] BCK_AZURE_ACR_006: ACR should have retention policy enabled
- [ ] BCK_AZURE_ACR_007: ACR should have vulnerability scanning enabled
- [ ] BCK_AZURE_ACR_008: ACR should use zone redundancy
- [ ] BCK_AZURE_ACR_009: ACR should have export policy disabled
- [ ] BCK_AZURE_ACR_010: ACR should have anonymous pull disabled

### 4.2 Storage Resources
#### Storage Account (`Microsoft.Storage/storageAccounts`)
- [ ] BCK_AZURE_ST_001: Storage account should enforce HTTPS
- [ ] BCK_AZURE_ST_002: Storage account should use minimum TLS 1.2
- [ ] BCK_AZURE_ST_003: Storage account should have secure transfer enabled
- [ ] BCK_AZURE_ST_004: Storage account should deny public blob access
- [ ] BCK_AZURE_ST_005: Storage account should use private endpoints
- [ ] BCK_AZURE_ST_006: Storage account should have network rules configured
- [ ] BCK_AZURE_ST_007: Storage account should have blob soft delete enabled
- [ ] BCK_AZURE_ST_008: Storage account should have container soft delete enabled
- [ ] BCK_AZURE_ST_009: Storage account should have versioning enabled
- [ ] BCK_AZURE_ST_010: Storage account should use customer-managed keys
- [ ] BCK_AZURE_ST_011: Storage account should have infrastructure encryption
- [ ] BCK_AZURE_ST_012: Storage account should disable shared key access
- [ ] BCK_AZURE_ST_013: Storage account should have blob encryption enabled
- [ ] BCK_AZURE_ST_014: Storage account should have file encryption enabled
- [ ] BCK_AZURE_ST_015: Storage account should have table encryption enabled
- [ ] BCK_AZURE_ST_016: Storage account should have queue encryption enabled
- [ ] BCK_AZURE_ST_017: Storage account should enable Azure Defender
- [ ] BCK_AZURE_ST_018: Storage account should have logging enabled
- [ ] BCK_AZURE_ST_019: Storage account should have metrics enabled
- [ ] BCK_AZURE_ST_020: Storage account should have immutability policy

#### Blob Container (`Microsoft.Storage/storageAccounts/blobServices/containers`)
- [ ] BCK_AZURE_BLOB_001: Blob container should not have public access
- [ ] BCK_AZURE_BLOB_002: Blob container should have immutability policy
- [ ] BCK_AZURE_BLOB_003: Blob container should have legal hold when required

#### File Share (`Microsoft.Storage/storageAccounts/fileServices/shares`)
- [ ] BCK_AZURE_FILE_001: File share should have SMB encryption enabled
- [ ] BCK_AZURE_FILE_002: File share should have secure transfer required
- [ ] BCK_AZURE_FILE_003: File share should use private endpoints

#### Data Lake Storage (`Microsoft.Storage/storageAccounts` with hierarchicalNamespace)
- [ ] BCK_AZURE_ADLS_001: ADLS should have firewall rules configured
- [ ] BCK_AZURE_ADLS_002: ADLS should have ACLs properly configured
- [ ] BCK_AZURE_ADLS_003: ADLS should have encryption enabled

### 4.3 Networking Resources
#### Virtual Network (`Microsoft.Network/virtualNetworks`)
- [ ] BCK_AZURE_VNET_001: VNet should have DDoS protection enabled
- [ ] BCK_AZURE_VNET_002: VNet should have appropriate address space
- [ ] BCK_AZURE_VNET_003: VNet should have DNS servers configured
- [ ] BCK_AZURE_VNET_004: VNet should enable flow logs
- [ ] BCK_AZURE_VNET_005: VNet peering should not allow gateway transit from untrusted networks

#### Subnet (`Microsoft.Network/virtualNetworks/subnets`)
- [ ] BCK_AZURE_SUBNET_001: Subnet should have NSG associated
- [ ] BCK_AZURE_SUBNET_002: Subnet should have service endpoints configured
- [ ] BCK_AZURE_SUBNET_003: Subnet should have private endpoint policies
- [ ] BCK_AZURE_SUBNET_004: Subnet delegation should be appropriate
- [ ] BCK_AZURE_SUBNET_005: Gateway subnet should not have NSG

#### Network Security Group (`Microsoft.Network/networkSecurityGroups`)
- [ ] BCK_AZURE_NSG_001: NSG should not allow inbound from any source to SSH (22)
- [ ] BCK_AZURE_NSG_002: NSG should not allow inbound from any source to RDP (3389)
- [ ] BCK_AZURE_NSG_003: NSG should not allow inbound from any source on all ports
- [ ] BCK_AZURE_NSG_004: NSG should have diagnostic logs enabled
- [ ] BCK_AZURE_NSG_005: NSG should have flow logs enabled
- [ ] BCK_AZURE_NSG_006: NSG should not allow UDP from internet
- [ ] BCK_AZURE_NSG_007: NSG should not allow inbound ICMP from internet
- [ ] BCK_AZURE_NSG_008: NSG should restrict database ports (1433, 3306, 5432, 27017)
- [ ] BCK_AZURE_NSG_009: NSG should have default deny rule
- [ ] BCK_AZURE_NSG_010: NSG rules should have descriptions

#### Application Security Group (`Microsoft.Network/applicationSecurityGroups`)
- [ ] BCK_AZURE_ASG_001: ASG should be used in NSG rules instead of IP addresses

#### Public IP (`Microsoft.Network/publicIPAddresses`)
- [ ] BCK_AZURE_PIP_001: Public IP should have DDoS protection enabled
- [ ] BCK_AZURE_PIP_002: Public IP should use Standard SKU
- [ ] BCK_AZURE_PIP_003: Public IP should have diagnostic logs enabled
- [ ] BCK_AZURE_PIP_004: Public IP should be zone redundant

#### Load Balancer (`Microsoft.Network/loadBalancers`)
- [ ] BCK_AZURE_LB_001: Load Balancer should use Standard SKU
- [ ] BCK_AZURE_LB_002: Load Balancer should have health probes configured
- [ ] BCK_AZURE_LB_003: Load Balancer should have diagnostic logs enabled
- [ ] BCK_AZURE_LB_004: Internal Load Balancer should be used where possible

#### Application Gateway (`Microsoft.Network/applicationGateways`)
- [ ] BCK_AZURE_AGW_001: App Gateway should have WAF enabled
- [ ] BCK_AZURE_AGW_002: App Gateway WAF should be in prevention mode
- [ ] BCK_AZURE_AGW_003: App Gateway should use HTTPS listeners
- [ ] BCK_AZURE_AGW_004: App Gateway should have minimum TLS 1.2
- [ ] BCK_AZURE_AGW_005: App Gateway should have diagnostic logs enabled
- [ ] BCK_AZURE_AGW_006: App Gateway should use WAF v2 SKU
- [ ] BCK_AZURE_AGW_007: App Gateway should have SSL policy configured
- [ ] BCK_AZURE_AGW_008: App Gateway should have end-to-end TLS
- [ ] BCK_AZURE_AGW_009: App Gateway should have request body inspection enabled
- [ ] BCK_AZURE_AGW_010: App Gateway should have zone redundancy

#### Azure Firewall (`Microsoft.Network/azureFirewalls`)
- [ ] BCK_AZURE_FW_001: Firewall should have threat intelligence enabled
- [ ] BCK_AZURE_FW_002: Firewall should use Premium SKU for IDPS
- [ ] BCK_AZURE_FW_003: Firewall should have diagnostic logs enabled
- [ ] BCK_AZURE_FW_004: Firewall should have DNS proxy enabled
- [ ] BCK_AZURE_FW_005: Firewall should have TLS inspection enabled
- [ ] BCK_AZURE_FW_006: Firewall policy should deny by default

#### Azure Firewall Policy (`Microsoft.Network/firewallPolicies`)
- [ ] BCK_AZURE_FWP_001: Firewall Policy should have threat intelligence mode set to deny
- [ ] BCK_AZURE_FWP_002: Firewall Policy should have IDPS enabled
- [ ] BCK_AZURE_FWP_003: Firewall Policy should use TLS inspection

#### VPN Gateway (`Microsoft.Network/virtualNetworkGateways`)
- [ ] BCK_AZURE_VPN_001: VPN Gateway should use VpnGw2 or higher SKU
- [ ] BCK_AZURE_VPN_002: VPN Gateway should have active-active enabled
- [ ] BCK_AZURE_VPN_003: VPN Gateway should use IKEv2 protocol
- [ ] BCK_AZURE_VPN_004: VPN Gateway should have diagnostic logs enabled
- [ ] BCK_AZURE_VPN_005: VPN Gateway should use zone redundancy

#### ExpressRoute (`Microsoft.Network/expressRouteCircuits`)
- [ ] BCK_AZURE_ER_001: ExpressRoute should have Global Reach disabled if not needed
- [ ] BCK_AZURE_ER_002: ExpressRoute should have private peering
- [ ] BCK_AZURE_ER_003: ExpressRoute should have diagnostic logs enabled

#### Private Endpoint (`Microsoft.Network/privateEndpoints`)
- [ ] BCK_AZURE_PE_001: Private Endpoint should have network policies enabled
- [ ] BCK_AZURE_PE_002: Private Endpoint should be in appropriate subnet
- [ ] BCK_AZURE_PE_003: Private DNS zone should be linked to VNet

#### Private DNS Zone (`Microsoft.Network/privateDnsZones`)
- [ ] BCK_AZURE_PDNS_001: Private DNS Zone should have VNet links
- [ ] BCK_AZURE_PDNS_002: Private DNS Zone should have auto-registration disabled for most zones

#### Front Door (`Microsoft.Network/frontDoors`)
- [ ] BCK_AZURE_FD_001: Front Door should have WAF policy attached
- [ ] BCK_AZURE_FD_002: Front Door should enforce HTTPS
- [ ] BCK_AZURE_FD_003: Front Door should have minimum TLS 1.2
- [ ] BCK_AZURE_FD_004: Front Door should have diagnostic logs enabled
- [ ] BCK_AZURE_FD_005: Front Door should use managed certificates

#### CDN (`Microsoft.Cdn/profiles`)
- [ ] BCK_AZURE_CDN_001: CDN should enforce HTTPS
- [ ] BCK_AZURE_CDN_002: CDN should have diagnostic logs enabled
- [ ] BCK_AZURE_CDN_003: CDN should have WAF enabled

#### Traffic Manager (`Microsoft.Network/trafficmanagerprofiles`)
- [ ] BCK_AZURE_TM_001: Traffic Manager should have diagnostic logs enabled
- [ ] BCK_AZURE_TM_002: Traffic Manager endpoints should be monitored

#### NAT Gateway (`Microsoft.Network/natGateways`)
- [ ] BCK_AZURE_NAT_001: NAT Gateway should be associated with subnet
- [ ] BCK_AZURE_NAT_002: NAT Gateway should have idle timeout configured

#### Bastion (`Microsoft.Network/bastionHosts`)
- [ ] BCK_AZURE_BASTION_001: Bastion should use Standard SKU
- [ ] BCK_AZURE_BASTION_002: Bastion should have copy-paste disabled if required
- [ ] BCK_AZURE_BASTION_003: Bastion should have file transfer disabled if required
- [ ] BCK_AZURE_BASTION_004: Bastion should have IP-based connection disabled

### 4.4 Database Resources
#### Azure SQL Server (`Microsoft.Sql/servers`)
- [ ] BCK_AZURE_SQL_001: SQL Server should have Azure AD admin configured
- [ ] BCK_AZURE_SQL_002: SQL Server should have auditing enabled
- [ ] BCK_AZURE_SQL_003: SQL Server should have threat detection enabled
- [ ] BCK_AZURE_SQL_004: SQL Server should have TDE enabled
- [ ] BCK_AZURE_SQL_005: SQL Server should have minimum TLS 1.2
- [ ] BCK_AZURE_SQL_006: SQL Server should deny public network access
- [ ] BCK_AZURE_SQL_007: SQL Server should have firewall rules configured
- [ ] BCK_AZURE_SQL_008: SQL Server should use private endpoints
- [ ] BCK_AZURE_SQL_009: SQL Server should have vulnerability assessment enabled
- [ ] BCK_AZURE_SQL_010: SQL Server should have Azure AD-only authentication
- [ ] BCK_AZURE_SQL_011: SQL Server should have outbound network access restricted

#### Azure SQL Database (`Microsoft.Sql/servers/databases`)
- [ ] BCK_AZURE_SQLDB_001: SQL Database should have TDE enabled
- [ ] BCK_AZURE_SQLDB_002: SQL Database should have long-term backup retention
- [ ] BCK_AZURE_SQLDB_003: SQL Database should have geo-redundant backup
- [ ] BCK_AZURE_SQLDB_004: SQL Database should have zone redundancy enabled
- [ ] BCK_AZURE_SQLDB_005: SQL Database should have ledger enabled for sensitive data
- [ ] BCK_AZURE_SQLDB_006: SQL Database should use customer-managed keys

#### SQL Managed Instance (`Microsoft.Sql/managedInstances`)
- [ ] BCK_AZURE_SQLMI_001: SQL MI should have public endpoint disabled
- [ ] BCK_AZURE_SQLMI_002: SQL MI should have TDE with customer-managed key
- [ ] BCK_AZURE_SQLMI_003: SQL MI should have vulnerability assessment enabled
- [ ] BCK_AZURE_SQLMI_004: SQL MI should have Azure AD admin configured
- [ ] BCK_AZURE_SQLMI_005: SQL MI should have minimum TLS 1.2

#### Cosmos DB (`Microsoft.DocumentDB/databaseAccounts`)
- [ ] BCK_AZURE_COSMOS_001: Cosmos DB should have firewall rules configured
- [ ] BCK_AZURE_COSMOS_002: Cosmos DB should have private endpoints
- [ ] BCK_AZURE_COSMOS_003: Cosmos DB should disable public network access
- [ ] BCK_AZURE_COSMOS_004: Cosmos DB should have automatic failover enabled
- [ ] BCK_AZURE_COSMOS_005: Cosmos DB should have customer-managed keys
- [ ] BCK_AZURE_COSMOS_006: Cosmos DB should have continuous backup enabled
- [ ] BCK_AZURE_COSMOS_007: Cosmos DB should restrict default network access
- [ ] BCK_AZURE_COSMOS_008: Cosmos DB should have local authentication disabled
- [ ] BCK_AZURE_COSMOS_009: Cosmos DB should have multiple write locations if needed
- [ ] BCK_AZURE_COSMOS_010: Cosmos DB should have diagnostic logs enabled

#### MySQL (`Microsoft.DBforMySQL/servers` and `flexibleServers`)
- [ ] BCK_AZURE_MYSQL_001: MySQL should have SSL enforcement enabled
- [ ] BCK_AZURE_MYSQL_002: MySQL should have firewall rules configured
- [ ] BCK_AZURE_MYSQL_003: MySQL should use private endpoints
- [ ] BCK_AZURE_MYSQL_004: MySQL should have geo-redundant backup enabled
- [ ] BCK_AZURE_MYSQL_005: MySQL should have threat detection enabled
- [ ] BCK_AZURE_MYSQL_006: MySQL should have infrastructure encryption enabled
- [ ] BCK_AZURE_MYSQL_007: MySQL should deny public network access
- [ ] BCK_AZURE_MYSQL_008: MySQL should have minimum TLS 1.2
- [ ] BCK_AZURE_MYSQL_009: MySQL should have audit logging enabled

#### PostgreSQL (`Microsoft.DBforPostgreSQL/servers` and `flexibleServers`)
- [ ] BCK_AZURE_PSQL_001: PostgreSQL should have SSL enforcement enabled
- [ ] BCK_AZURE_PSQL_002: PostgreSQL should have firewall rules configured
- [ ] BCK_AZURE_PSQL_003: PostgreSQL should use private endpoints
- [ ] BCK_AZURE_PSQL_004: PostgreSQL should have geo-redundant backup enabled
- [ ] BCK_AZURE_PSQL_005: PostgreSQL should have threat detection enabled
- [ ] BCK_AZURE_PSQL_006: PostgreSQL should have infrastructure encryption
- [ ] BCK_AZURE_PSQL_007: PostgreSQL should deny public network access
- [ ] BCK_AZURE_PSQL_008: PostgreSQL should have minimum TLS 1.2
- [ ] BCK_AZURE_PSQL_009: PostgreSQL should have connection throttling enabled
- [ ] BCK_AZURE_PSQL_010: PostgreSQL should have log checkpoints enabled
- [ ] BCK_AZURE_PSQL_011: PostgreSQL should have log connections enabled

#### MariaDB (`Microsoft.DBforMariaDB/servers`)
- [ ] BCK_AZURE_MARIA_001: MariaDB should have SSL enforcement enabled
- [ ] BCK_AZURE_MARIA_002: MariaDB should have firewall rules configured
- [ ] BCK_AZURE_MARIA_003: MariaDB should use private endpoints
- [ ] BCK_AZURE_MARIA_004: MariaDB should have geo-redundant backup enabled

#### Redis Cache (`Microsoft.Cache/redis`)
- [ ] BCK_AZURE_REDIS_001: Redis should have SSL/TLS enabled
- [ ] BCK_AZURE_REDIS_002: Redis should have firewall rules configured
- [ ] BCK_AZURE_REDIS_003: Redis should use private endpoints
- [ ] BCK_AZURE_REDIS_004: Redis should have non-SSL port disabled
- [ ] BCK_AZURE_REDIS_005: Redis should use minimum TLS 1.2
- [ ] BCK_AZURE_REDIS_006: Redis should have authentication enabled
- [ ] BCK_AZURE_REDIS_007: Redis should have persistence enabled
- [ ] BCK_AZURE_REDIS_008: Redis should have patching schedule configured
- [ ] BCK_AZURE_REDIS_009: Redis should use Premium tier for production
- [ ] BCK_AZURE_REDIS_010: Redis should have data encryption enabled

### 4.5 Identity & Security Resources
#### Key Vault (`Microsoft.KeyVault/vaults`)
- [ ] BCK_AZURE_KV_001: Key Vault should have purge protection enabled
- [ ] BCK_AZURE_KV_002: Key Vault should have soft delete enabled
- [ ] BCK_AZURE_KV_003: Key Vault should use RBAC for access
- [ ] BCK_AZURE_KV_004: Key Vault should have firewall rules configured
- [ ] BCK_AZURE_KV_005: Key Vault should use private endpoints
- [ ] BCK_AZURE_KV_006: Key Vault should deny public network access
- [ ] BCK_AZURE_KV_007: Key Vault should have diagnostic logs enabled
- [ ] BCK_AZURE_KV_008: Key Vault secrets should have expiration dates
- [ ] BCK_AZURE_KV_009: Key Vault keys should have expiration dates
- [ ] BCK_AZURE_KV_010: Key Vault certificates should have expiration alerts
- [ ] BCK_AZURE_KV_011: Key Vault should not allow bypass for Azure services unless needed
- [ ] BCK_AZURE_KV_012: Key Vault keys should use RSA or EC with appropriate size
- [ ] BCK_AZURE_KV_013: Key Vault should have recovery enabled

#### Managed Identity (`Microsoft.ManagedIdentity/userAssignedIdentities`)
- [ ] BCK_AZURE_MI_001: User-assigned managed identity should be used instead of system-assigned where appropriate
- [ ] BCK_AZURE_MI_002: Managed identity should be associated with resource

#### Role Assignments (`Microsoft.Authorization/roleAssignments`)
- [ ] BCK_AZURE_RBAC_001: Role assignment should not use Owner role at subscription level
- [ ] BCK_AZURE_RBAC_002: Role assignment should use least privilege principle
- [ ] BCK_AZURE_RBAC_003: Role assignment should not use deprecated roles
- [ ] BCK_AZURE_RBAC_004: Role assignment should have condition where supported
- [ ] BCK_AZURE_RBAC_005: Role assignment should not be to User type (prefer groups)

#### Policy Assignments (`Microsoft.Authorization/policyAssignments`)
- [ ] BCK_AZURE_POLICY_001: Policy assignment should have managed identity for remediation
- [ ] BCK_AZURE_POLICY_002: Policy assignment should not be disabled
- [ ] BCK_AZURE_POLICY_003: Policy should have appropriate enforcement mode

#### Microsoft Defender for Cloud (`Microsoft.Security/*`)
- [ ] BCK_AZURE_MDC_001: Defender for Cloud should be enabled for all resource types
- [ ] BCK_AZURE_MDC_002: Auto-provisioning of agents should be enabled
- [ ] BCK_AZURE_MDC_003: Security contacts should be configured
- [ ] BCK_AZURE_MDC_004: Email notifications should be enabled for high severity alerts

### 4.6 Monitoring & Logging Resources
#### Log Analytics Workspace (`Microsoft.OperationalInsights/workspaces`)
- [ ] BCK_AZURE_LAW_001: Log Analytics should have appropriate retention period
- [ ] BCK_AZURE_LAW_002: Log Analytics should have daily cap configured
- [ ] BCK_AZURE_LAW_003: Log Analytics should use customer-managed keys
- [ ] BCK_AZURE_LAW_004: Log Analytics should have internet ingestion disabled
- [ ] BCK_AZURE_LAW_005: Log Analytics should have internet query disabled

#### Application Insights (`Microsoft.Insights/components`)
- [ ] BCK_AZURE_APPI_001: App Insights should have workspace-based configuration
- [ ] BCK_AZURE_APPI_002: App Insights should disable public ingestion
- [ ] BCK_AZURE_APPI_003: App Insights should have retention configured

#### Diagnostic Settings (`Microsoft.Insights/diagnosticSettings`)
- [ ] BCK_AZURE_DIAG_001: Diagnostic settings should send to Log Analytics
- [ ] BCK_AZURE_DIAG_002: Diagnostic settings should capture all required logs
- [ ] BCK_AZURE_DIAG_003: Diagnostic settings should have appropriate retention

#### Activity Log Alert (`Microsoft.Insights/activityLogAlerts`)
- [ ] BCK_AZURE_ALERT_001: Alert should be configured for security policy changes
- [ ] BCK_AZURE_ALERT_002: Alert should be configured for NSG changes
- [ ] BCK_AZURE_ALERT_003: Alert should be configured for key vault changes
- [ ] BCK_AZURE_ALERT_004: Alert should have appropriate action groups

#### Action Groups (`Microsoft.Insights/actionGroups`)
- [ ] BCK_AZURE_AG_001: Action group should have multiple notification channels
- [ ] BCK_AZURE_AG_002: Action group should be used by alerts

### 4.7 Messaging & Integration Resources
#### Service Bus (`Microsoft.ServiceBus/namespaces`)
- [ ] BCK_AZURE_SB_001: Service Bus should use Premium tier for production
- [ ] BCK_AZURE_SB_002: Service Bus should have firewall rules configured
- [ ] BCK_AZURE_SB_003: Service Bus should use private endpoints
- [ ] BCK_AZURE_SB_004: Service Bus should disable public network access
- [ ] BCK_AZURE_SB_005: Service Bus should have minimum TLS 1.2
- [ ] BCK_AZURE_SB_006: Service Bus should disable local authentication
- [ ] BCK_AZURE_SB_007: Service Bus should have diagnostic logs enabled
- [ ] BCK_AZURE_SB_008: Service Bus should have zone redundancy enabled

#### Event Hub (`Microsoft.EventHub/namespaces`)
- [ ] BCK_AZURE_EH_001: Event Hub should have firewall rules configured
- [ ] BCK_AZURE_EH_002: Event Hub should use private endpoints
- [ ] BCK_AZURE_EH_003: Event Hub should disable public network access
- [ ] BCK_AZURE_EH_004: Event Hub should have minimum TLS 1.2
- [ ] BCK_AZURE_EH_005: Event Hub should disable local authentication
- [ ] BCK_AZURE_EH_006: Event Hub should have auto-inflate enabled
- [ ] BCK_AZURE_EH_007: Event Hub should have zone redundancy enabled
- [ ] BCK_AZURE_EH_008: Event Hub should have capture enabled for retention

#### Event Grid (`Microsoft.EventGrid/topics` and `domains`)
- [ ] BCK_AZURE_EG_001: Event Grid should use private endpoints
- [ ] BCK_AZURE_EG_002: Event Grid should disable public network access
- [ ] BCK_AZURE_EG_003: Event Grid should disable local authentication
- [ ] BCK_AZURE_EG_004: Event Grid should have managed identity enabled
- [ ] BCK_AZURE_EG_005: Event Grid should have input schema configured

#### API Management (`Microsoft.ApiManagement/service`)
- [ ] BCK_AZURE_APIM_001: APIM should have VNet integration
- [ ] BCK_AZURE_APIM_002: APIM should use private endpoints
- [ ] BCK_AZURE_APIM_003: APIM should have client certificate validation
- [ ] BCK_AZURE_APIM_004: APIM should have minimum TLS 1.2
- [ ] BCK_AZURE_APIM_005: APIM should disable management API
- [ ] BCK_AZURE_APIM_006: APIM should have rate limiting policies
- [ ] BCK_AZURE_APIM_007: APIM should have authentication policies
- [ ] BCK_AZURE_APIM_008: APIM should not expose backend URL in errors
- [ ] BCK_AZURE_APIM_009: APIM should have named values encrypted
- [ ] BCK_AZURE_APIM_010: APIM should have diagnostic logs enabled

#### Logic Apps (`Microsoft.Logic/workflows`)
- [ ] BCK_AZURE_LA_001: Logic App should have access control configured
- [ ] BCK_AZURE_LA_002: Logic App should use managed connectors
- [ ] BCK_AZURE_LA_003: Logic App should have diagnostic logs enabled
- [ ] BCK_AZURE_LA_004: Logic App should have run history restricted
- [ ] BCK_AZURE_LA_005: Logic App should use integration service environment

### 4.8 Analytics & AI Resources
#### Synapse Analytics (`Microsoft.Synapse/workspaces`)
- [ ] BCK_AZURE_SYN_001: Synapse should have managed VNet enabled
- [ ] BCK_AZURE_SYN_002: Synapse should use private endpoints
- [ ] BCK_AZURE_SYN_003: Synapse should have data exfiltration protection
- [ ] BCK_AZURE_SYN_004: Synapse should have Azure AD-only authentication
- [ ] BCK_AZURE_SYN_005: Synapse should have vulnerability assessment enabled
- [ ] BCK_AZURE_SYN_006: Synapse should have auditing enabled
- [ ] BCK_AZURE_SYN_007: Synapse should use customer-managed keys

#### Data Factory (`Microsoft.DataFactory/factories`)
- [ ] BCK_AZURE_ADF_001: Data Factory should use managed VNet
- [ ] BCK_AZURE_ADF_002: Data Factory should have private endpoints
- [ ] BCK_AZURE_ADF_003: Data Factory should have public network access disabled
- [ ] BCK_AZURE_ADF_004: Data Factory should use managed identity
- [ ] BCK_AZURE_ADF_005: Data Factory should have diagnostic logs enabled
- [ ] BCK_AZURE_ADF_006: Data Factory should have Git integration enabled
- [ ] BCK_AZURE_ADF_007: Data Factory linked services should use Key Vault

#### Databricks (`Microsoft.Databricks/workspaces`)
- [ ] BCK_AZURE_DBR_001: Databricks should have VNet injection enabled
- [ ] BCK_AZURE_DBR_002: Databricks should have no public IP enabled
- [ ] BCK_AZURE_DBR_003: Databricks should use premium SKU for security features
- [ ] BCK_AZURE_DBR_004: Databricks should have customer-managed keys
- [ ] BCK_AZURE_DBR_005: Databricks should have private link enabled
- [ ] BCK_AZURE_DBR_006: Databricks should disable public network access

#### Machine Learning (`Microsoft.MachineLearningServices/workspaces`)
- [ ] BCK_AZURE_ML_001: ML workspace should use private endpoints
- [ ] BCK_AZURE_ML_002: ML workspace should have public network access disabled
- [ ] BCK_AZURE_ML_003: ML workspace should use customer-managed keys
- [ ] BCK_AZURE_ML_004: ML workspace should have high business impact enabled
- [ ] BCK_AZURE_ML_005: ML compute should have local authentication disabled
- [ ] BCK_AZURE_ML_006: ML compute should have SSH access disabled

#### Cognitive Services (`Microsoft.CognitiveServices/accounts`)
- [ ] BCK_AZURE_COG_001: Cognitive Services should have firewall rules configured
- [ ] BCK_AZURE_COG_002: Cognitive Services should use private endpoints
- [ ] BCK_AZURE_COG_003: Cognitive Services should disable public network access
- [ ] BCK_AZURE_COG_004: Cognitive Services should use managed identity
- [ ] BCK_AZURE_COG_005: Cognitive Services should use customer-managed keys
- [ ] BCK_AZURE_COG_006: Cognitive Services should disable local authentication
- [ ] BCK_AZURE_COG_007: Cognitive Services should have diagnostic logs enabled

#### Search Service (`Microsoft.Search/searchServices`)
- [ ] BCK_AZURE_SEARCH_001: Search should have firewall rules configured
- [ ] BCK_AZURE_SEARCH_002: Search should use private endpoints
- [ ] BCK_AZURE_SEARCH_003: Search should disable public network access
- [ ] BCK_AZURE_SEARCH_004: Search should use managed identity
- [ ] BCK_AZURE_SEARCH_005: Search should have API key authentication disabled
- [ ] BCK_AZURE_SEARCH_006: Search should have minimum TLS 1.2

#### Stream Analytics (`Microsoft.StreamAnalytics/streamingjobs`)
- [ ] BCK_AZURE_ASA_001: Stream Analytics should have diagnostic logs enabled
- [ ] BCK_AZURE_ASA_002: Stream Analytics should use managed identity

### 4.9 Web & Mobile Resources
#### Static Web Apps (`Microsoft.Web/staticSites`)
- [ ] BCK_AZURE_SWA_001: Static Web App should have staging environments configured
- [ ] BCK_AZURE_SWA_002: Static Web App should have custom domain with managed certificate
- [ ] BCK_AZURE_SWA_003: Static Web App should have linked backend configured securely

#### SignalR Service (`Microsoft.SignalRService/SignalR`)
- [ ] BCK_AZURE_SIGNALR_001: SignalR should use private endpoints
- [ ] BCK_AZURE_SIGNALR_002: SignalR should disable public network access
- [ ] BCK_AZURE_SIGNALR_003: SignalR should disable local authentication
- [ ] BCK_AZURE_SIGNALR_004: SignalR should have managed identity enabled

#### Notification Hub (`Microsoft.NotificationHubs/namespaces`)
- [ ] BCK_AZURE_NH_001: Notification Hub should have appropriate SKU
- [ ] BCK_AZURE_NH_002: Notification Hub should have diagnostic logs enabled

### 4.10 DevOps & Management Resources
#### Automation Account (`Microsoft.Automation/automationAccounts`)
- [ ] BCK_AZURE_AUTO_001: Automation Account should use managed identity
- [ ] BCK_AZURE_AUTO_002: Automation Account should have public network access disabled
- [ ] BCK_AZURE_AUTO_003: Automation Account should have diagnostic logs enabled
- [ ] BCK_AZURE_AUTO_004: Automation Account should use encrypted variables
- [ ] BCK_AZURE_AUTO_005: Automation Account webhooks should be secured

#### Batch Account (`Microsoft.Batch/batchAccounts`)
- [ ] BCK_AZURE_BATCH_001: Batch Account should use private endpoints
- [ ] BCK_AZURE_BATCH_002: Batch Account should disable public network access
- [ ] BCK_AZURE_BATCH_003: Batch Account should use customer-managed keys
- [ ] BCK_AZURE_BATCH_004: Batch Account should have diagnostic logs enabled

#### Recovery Services Vault (`Microsoft.RecoveryServices/vaults`)
- [ ] BCK_AZURE_RSV_001: Recovery Vault should use customer-managed keys
- [ ] BCK_AZURE_RSV_002: Recovery Vault should have soft delete enabled
- [ ] BCK_AZURE_RSV_003: Recovery Vault should have cross-region restore enabled
- [ ] BCK_AZURE_RSV_004: Recovery Vault should have private endpoints
- [ ] BCK_AZURE_RSV_005: Recovery Vault should disable public network access
- [ ] BCK_AZURE_RSV_006: Recovery Vault should have immutability enabled

#### Backup Policies (`Microsoft.RecoveryServices/vaults/backupPolicies`)
- [ ] BCK_AZURE_BP_001: Backup Policy should have appropriate retention
- [ ] BCK_AZURE_BP_002: Backup Policy should have instant restore configured

---

## Phase 5: Testing & Quality Assurance

### 5.1 Unit Testing
- [ ] Test Bicep parser with various file structures
- [ ] Test rule engine with mock data
- [ ] Test each security rule individually
- [ ] Test output formatters with sample data
- [ ] Test configuration loading
- [ ] Achieve 80%+ code coverage

### 5.2 Integration Testing
- [ ] Test end-to-end scanning workflow
- [ ] Test with real Azure Bicep templates
- [ ] Test with Azure Quickstart Templates
- [ ] Test CLI commands and flags
- [ ] Test multiple file scanning
- [ ] Test recursive directory scanning

### 5.3 Performance Testing
- [ ] Benchmark scanning speed
- [ ] Test with large Bicep files (1000+ lines)
- [ ] Test with large number of files (100+)
- [ ] Profile memory usage
- [ ] Optimize bottlenecks

### 5.4 Sample Templates
- [ ] Create compliant template examples for each resource type
- [ ] Create non-compliant template examples for each rule
- [ ] Create mixed compliance templates for testing
- [ ] Create complex multi-resource templates

---

## Phase 6: Documentation

### 6.1 User Documentation
- [ ] README.md with quick start guide
- [ ] Installation instructions (pip, brew, docker)
- [ ] CLI usage documentation
- [ ] Configuration file documentation
- [ ] CI/CD integration guides (GitHub Actions, Azure DevOps, GitLab CI)

### 6.2 Developer Documentation
- [ ] Architecture overview
- [ ] Contributing guidelines
- [ ] Code style guide
- [ ] PR and issue templates
- [ ] Release process documentation

### 6.3 Rule Documentation
- [ ] Complete rule catalog with:
  - [ ] Rule ID and title
  - [ ] Description and rationale
  - [ ] Severity and impact
  - [ ] Affected resource types
  - [ ] Compliant example
  - [ ] Non-compliant example
  - [ ] Remediation steps
  - [ ] References (CIS, NIST, Azure docs)
- [ ] Compliance mapping documentation
- [ ] Custom rule creation guide

### 6.4 API Documentation
- [ ] Generate API docs with Sphinx/MkDocs
- [ ] Document public interfaces
- [ ] Document configuration schema
- [ ] Document output formats

---

## Phase 7: CI/CD Integration

### 7.1 GitHub Actions
- [ ] Create reusable GitHub Action
- [ ] Support PR comments with findings
- [ ] Support SARIF upload to GitHub Security
- [ ] Create marketplace listing
- [ ] Document usage examples

### 7.2 Azure DevOps
- [ ] Create Azure Pipelines task
- [ ] Support build breaking on findings
- [ ] Create extension for marketplace
- [ ] Document pipeline integration

### 7.3 GitLab CI
- [ ] Create GitLab CI template
- [ ] Support Code Quality reports
- [ ] Support merge request comments
- [ ] Document integration steps

### 7.4 Other Integrations
- [ ] Jenkins plugin/pipeline steps
- [ ] Terraform Cloud/Enterprise integration
- [ ] Pre-commit hook
- [ ] VS Code extension (future)

---

## Phase 8: Advanced Features

### 8.1 Custom Rules
- [ ] Support custom rule definitions in YAML/Python
- [ ] Rule templating system
- [ ] Rule testing framework
- [ ] Rule sharing/community repository

### 8.2 Suppressions & Exceptions
- [ ] Inline comment suppressions (`// biceps-check:disable=BCK_AZURE_001`)
- [ ] File-level suppressions
- [ ] Global suppressions in config
- [ ] Suppression audit trail

### 8.3 Auto-Remediation
- [ ] Generate fix suggestions
- [ ] Auto-fix capability for simple issues
- [ ] Git patch generation
- [ ] Pull request creation with fixes

### 8.4 Reporting & Analytics
- [ ] Historical trend tracking
- [ ] Security posture dashboard
- [ ] Export to SIEM systems
- [ ] Compliance reporting

### 8.5 Advanced Analysis
- [ ] Cross-resource dependency analysis
- [ ] Network topology visualization
- [ ] IAM permission analysis
- [ ] Cost impact estimation

---

## 📊 Progress Tracking

### Milestones

| Milestone | Description | Target Date | Status |
|-----------|-------------|-------------|--------|
| M1 | Project setup and core engine | TBD | 🔴 Not Started |
| M2 | First 100 security rules | TBD | 🔴 Not Started |
| M3 | CLI and output formatters | TBD | 🔴 Not Started |
| M4 | Complete rule coverage (500+) | TBD | 🔴 Not Started |
| M5 | Documentation complete | TBD | 🔴 Not Started |
| M6 | CI/CD integrations | TBD | 🔴 Not Started |
| M7 | v1.0 Release | TBD | 🔴 Not Started |

### Statistics

- Total Security Rules Planned: **500+**
- Azure Resource Types Covered: **80+**
- Compliance Frameworks: **8**

---

## 📚 References

- [Checkov Documentation](https://www.checkov.io/1.Welcome/What%20is%20Checkov.html)
- [Azure Bicep Documentation](https://docs.microsoft.com/azure/azure-resource-manager/bicep/)
- [CIS Azure Foundations Benchmark](https://www.cisecurity.org/benchmark/azure)
- [Azure Security Benchmark](https://docs.microsoft.com/azure/security/benchmarks/)
- [NIST 800-53](https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final)
- [Azure Well-Architected Framework - Security](https://docs.microsoft.com/azure/architecture/framework/security/)

---

## 📝 Notes

- Rule IDs follow the pattern: `BCK_AZURE_{RESOURCE}_{NUMBER}`
- Each rule should have unit tests with compliant and non-compliant examples
- Documentation should be generated automatically where possible
- Keep the tool extensible for future Azure resource types
- Consider performance for enterprise-scale repositories

---

*Last Updated: 2026-02-04*
