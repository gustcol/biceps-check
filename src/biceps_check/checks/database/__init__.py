"""
Security checks for Azure Database resources.

This module contains security rules for:
- SQL Server (Microsoft.Sql/servers)
- SQL Database (Microsoft.Sql/servers/databases)
- Cosmos DB (Microsoft.DocumentDB/databaseAccounts)
- MySQL (Microsoft.DBforMySQL/servers, flexibleServers)
- PostgreSQL (Microsoft.DBforPostgreSQL/servers, flexibleServers)
- Redis Cache (Microsoft.Cache/redis)
"""

from biceps_check.checks.database.cosmos_db import *
from biceps_check.checks.database.mysql import *
from biceps_check.checks.database.postgresql import *
from biceps_check.checks.database.redis_cache import *
from biceps_check.checks.database.sql_server import *
