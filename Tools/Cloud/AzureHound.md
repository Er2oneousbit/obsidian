# AzureHound

**Tags:** `#azurehound` `#bloodhound` `#entraid` `#azuread` `#cloud` `#enumeration` `#attackpaths`

Go-based BloodHound data collector for Entra ID and Azure RBAC — the cloud counterpart to on-prem SharpHound. Walks the tenant's users, groups, applications, service principals, devices, directory roles, and Azure resource role assignments, then outputs BloodHound-compatible JSON for attack-path analysis. Pairs with [[Tools/Cloud/BARK|BARK]]: collect the graph with AzureHound, identify a path in BloodHound, execute each hop with the matching BARK primitive.

**Source:** https://github.com/BloodHoundAD/AzureHound
**Install:** download a prebuilt binary from releases, or `go install github.com/bloodhoundad/azurehound/v2@latest`

```bash
# Collect everything with credentials
./azurehound -u "user@company.com" -p "Password1" list --tenant "<tenant-id>" -o output.json

# Collect with an existing access token instead
./azurehound -j "<access-token>" list --tenant "<tenant-id>" -o output.json

# Narrower collections
./azurehound list users --tenant "<tenant-id>"
./azurehound list az-role-assignments --tenant "<tenant-id>"

# Import output.json into the BloodHound UI
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] for the broader attack methodology, and [[Tools/Cloud/BARK|BARK]] for executing abuse primitives once a path is identified.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
