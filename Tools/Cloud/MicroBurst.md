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

> [!warning] **Verified against the module (2026-08).** MicroBurst does **not** expose granular `Get-AzKeyVaultSecrets` / `Get-AzStorageKeys` / `Get-AzAppSecrets` / `Get-AzVMs` / `Get-AzPermissions` etc. — those were invented in older notes. Almost everything funnels through **two flagship functions**: `Get-AzPasswords` (all credential stores) and `Get-AzDomainInfo` (all resources). Confirm with `Get-Command -Module MicroBurst`.

---

## Credential Hunting — `Get-AzPasswords`

The main reason to use MicroBurst. **One function** dumps every reachable credential store — Key Vault secrets/keys/certs, Storage Account keys, App Service & Function configs, Automation account credentials + connection strings, Container Registry admin creds, and more.

```powershell
# Dump everything (runs all sub-modules by default)
Get-AzPasswords -Verbose
Get-AzPasswords -Subscription <sub-id>          # scope to one subscription
Get-AzPasswords -Verbose | Out-File creds.txt   # capture — output is long

# Related credential grabbers
Get-AzWebAppTokens               # managed-identity / app tokens from App Services
Get-AzKeyVaultsAutomation        # Key Vault access via Automation account context
Get-AzArcCertificates            # Azure Arc-connected machine certs
Get-AzMachineLearningCredentials # AML workspace secrets
```

---

## Resource Enumeration — `Get-AzDomainInfo`

```powershell
# Full subscription recon in one shot — dumps to CSV/HTML under the output folder:
# VMs, NICs/public IPs & NSG rules, storage accounts + keys, Key Vaults, web/function apps,
# SQL servers/DBs, RBAC role assignments, users/groups, etc.
Get-AzDomainInfo -Verbose
Get-AzDomainInfo -Subscription <sub-id>
Get-AzDomainInfoREST              # REST-based variant (no Az module dependency)
```

---

## Command Execution & Lateral Movement

```powershell
# Run a command on EVERY VM you can reach (needs Microsoft.Compute/.../runCommand)
Invoke-AzVMBulkCMD -Script "whoami" -output results.txt
Invoke-AzVMCommandREST -Script "whoami"          # REST variant

# App Service / Kudu command execution (webshell-equivalent on a web app)
Invoke-AzAppServicesCMD -command "whoami" -appName <app-name>
Invoke-AzAppServKuduCMDExec -appName <app-name>

# Run a rogue Automation runbook (exec as the Automation account's identity)
Invoke-AzRunbook -Verbose

# Azure Bastion shareable-link abuse (persistent RDP/SSH exposure)
Get-AzRestBastionShareableLink
```

---

## Privilege Escalation

```powershell
# The classic MicroBurst privesc: if you hold User Access Administrator eligibility,
# toggle "Access management for Azure resources" ON to grant yourself Owner over ALL
# subscriptions in the tenant (root-scope elevation).
Invoke-AzElevatedAccessToggle

# ACR token generation (registry access → pull/push malicious images)
Invoke-AzACRTokenGenerator
```

---

## Unauthenticated Storage Brute Force

```powershell
# Find open/public Azure storage by guessing account names (no auth needed)
Invoke-EnumerateAzureBlobs      -Base <company-name>    # blobs in a named account
Invoke-EnumerateAzureSubDomains -Base <company-name>    # *.blob/file/table/queue/web/etc.
```

---

> [!note] **See also** — pair with [[Tools/Cloud/AADInternals|AADInternals]] (identity/Entra side) and [[Tools/Cloud/ScoutSuite|ScoutSuite]] (misconfig audit); the ARM-token abuse primitives overlap [[Tools/Cloud/BARK|BARK]]'s `*-AzureRM*` functions.

---

*Created: 2026-03-06*
*Updated: 2026-08-27*
*Model: claude-opus-5*
