"""
Security checks for Azure Storage resources.

This module contains security rules for:
- Storage Accounts (Microsoft.Storage/storageAccounts)
- Blob Containers (Microsoft.Storage/storageAccounts/blobServices/containers)
- File Shares (Microsoft.Storage/storageAccounts/fileServices/shares)
- Data Lake Storage
"""

from biceps_check.checks.storage.storage_account import *
