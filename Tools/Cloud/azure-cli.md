# azure-cli

**Tags:** #Cloud #Azure #ARM #EntraID #enumeration #privesc

Microsoft's official cross-platform CLI for Azure (`az`). Primarily an administration tool, it's equally an offensive one: it authenticates with stolen service-principal secrets, managed-identity tokens or a user's refresh token, and drives the **ARM resource plane** (`management.azure.com`) — subscriptions, VMs, storage, Key Vault, role assignments. On an engagement it's the fastest way to enumerate and abuse Azure RBAC once you hold any credential, and it wraps several escalation primitives (`elevateAccess`, `vm run-command`) behind one command.

**Source:** https://github.com/Azure/azure-cli · docs https://learn.microsoft.com/cli/azure/
**Install:** `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash` (Debian/Kali) or `pipx install azure-cli`

```bash
# --- Authenticate ---
az login                                                        # interactive / device code
az login --service-principal -u <app-id> -p <secret> --tenant <tenant-id>
az login --identity                                            # use the host VM's managed identity (IMDS)

# --- Enumerate what you can reach ---
az account list -o table                                       # subscriptions in scope
az role assignment list --all -o table                         # every RBAC assignment you can see
az role assignment list --assignee <oid> --all -o table        # a specific principal's roles
az resource list -o table

# --- Escalation primitives ---
# Global Admin → User Access Administrator at root scope (/)
az rest --method post --url "/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"
# Code execution as SYSTEM/root on a VM through ARM (no guest network path needed)
az vm run-command invoke -g <rg> -n <vm> --command-id RunShellScript --scripts "id"

# --- Raw ARM/Graph calls when there's no dedicated command ---
az rest --method get --url "https://graph.microsoft.com/v1.0/users?\$top=999"
```

> [!warning] `az` writes tokens to `~/.azure/` in cleartext (`accessTokens.json` / `msal_token_cache.json` on older/newer versions). On a compromised admin workstation that directory is itself a credential to loot; on your own box, clear it after an engagement.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/Entra ID|Entra ID]] — service-principal auth, `elevateAccess`, IMDS token use, and VM RunCommand for the identity→resource-plane pivot. [[Services/Web Services/Azure DevOps|Azure DevOps]] — `az devops`/`az pipelines` enumeration of repos, pipelines, service connections and variable groups with a PAT.
> Related tooling: [[Tools/Cloud/MicroBurst|MicroBurst]] (automates the IMDS/RunCommand/storage sweep `az` does by hand), [[Tools/Cloud/AADInternals|AADInternals]] (the identity/Entra side), [[Tools/Cloud/BARK|BARK]] (`*-AzureRM*` primitives over the same ARM API), [[Tools/Cloud/ROADtools|ROADtools]] (token manipulation feeding `az login`).

---

*Created: 2026-09-22*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
