# MicroBurst

**Tags:** `#microburst` `#azure` `#cloud` `#enumeration` `#powershell` `#storageaccount` `#keyvault` `#privesc`

PowerShell Azure attack toolkit from NetSPI — the closest Azure equivalent to Pacu for resource-level enumeration. Covers storage accounts, Key Vault secrets, service principals, Azure Functions, app service configs, and finding cleartext credentials baked into deployments. Complements AADInternals (identity-focused) with Azure resource-level coverage.

**Source:** https://github.com/NetSPI/MicroBurst
**Install:**
```powershell
git clone https://github.com/NetSPI/MicroBurst
Import-Module .\MicroBurst.psm1

# Requires Az module
Install-Module Az -Scope CurrentUser
Connect-AzAccount
```

> [!note] **MicroBurst vs AADInternals** — AADInternals focuses on Entra ID / identity attacks (users, tokens, PRT, AD Connect). MicroBurst focuses on Azure resource enumeration and credential harvesting from storage, Key Vault, app configs. Use both on Azure engagements.

---

## Credential Hunting

The main reason to use MicroBurst — finds passwords, secrets, and keys left in Azure resources.

```powershell
# The big one — dumps secrets from all accessible Azure resources
# Checks: Key Vault, Storage Account keys, App Service configs, Automation accounts,
#         Container registries, API Management, App registrations
Get-AzPasswords
Get-AzPasswords -Verbose

# Key Vault secrets
Get-AzKeyVaultSecrets
Get-AzKeyVaultSecrets -Subscription <sub-id>

# Storage account keys (allows full storage access)
Get-AzStorageKeys
Get-AzStorageKeys -Subscription <sub-id>

# App Service / Function App env vars (often contain DB strings, API keys)
Get-AzAppSecrets
Get-AzFunctionAppSecrets

# Automation Account runbook credentials
Get-AzAutomationCredentials

# Container registry credentials
Get-AzContainerRegistryCredentials
```

---

## Storage Enumeration

```powershell
# Find all storage accounts
Get-AzStorageAccounts

# Find publicly accessible storage containers/blobs (unauthenticated)
Invoke-EnumerateAzureBlobs -Base <company-name>
# Tries: <company>backup, <company>dev, <company>prod, <company>data, etc.

# List blobs in a container
Get-AzStorageAccountContents -StorageAccount <name> -StorageKey <key>

# Search blobs for interesting content
Get-MicroBurstAzureBlobs -StorageAccount <name> -StorageKey <key>
```

---

## Resource Enumeration

```powershell
# Full subscription recon
Get-AzDomainInfo
# Returns: VMs, storage accounts, Key Vaults, web apps, SQL servers, NSG rules

# Network exposure — find externally accessible resources
Get-AzNetworkInfo
Get-AzPublicIPs

# Virtual machines
Get-AzVMs

# SQL servers and databases
Get-AzSQLServers

# Web apps and Function apps
Get-AzWebApps
Get-AzFunctionApps

# VMs with script extensions (potential code exec / lateral movement)
Get-AzVMExtensions
```

---

## Privilege Escalation

```powershell
# Find over-permissive role assignments
Get-AzRoleAssignments

# Check current user permissions
Get-AzPermissions

# Find managed identities with high privileges
Get-AzManagedIdentities

# VM Run Command — execute commands if Microsoft.Compute/.../runCommand allowed
Invoke-AzVMCommand -ResourceGroupName <rg> -VMName <vm> -Command 'whoami /all'
```

---

## Unauthenticated Storage Brute Force

```powershell
# Find open/public Azure storage accounts by guessing names (no auth needed)
Invoke-EnumerateAzureBlobs -Base <company-name>
Invoke-EnumerateAzureSubDomains -Base <company-name>
# Checks: blobs, files, tables, queues, static sites
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
