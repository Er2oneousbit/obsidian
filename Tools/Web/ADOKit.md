# ADOKit

**Tags:** `#ADOKit` `#AzureDevOps` `#ADO` `#recon` `#privesc` `#persistence` `#redteam`

Azure DevOps Services attack toolkit (X-Force Red / `xforcered`, C#) that wraps the ADO REST API into named attack modules — reconnaissance, privilege escalation, and persistence — driven by a valid PAT or a stolen authentication cookie. Modular by design so new modules can be added. Presented at Black Hat USA 2024 Arsenal. Pairs with hand-rolled [[Tools/File Transfer/cURL|cURL]] REST calls and native [[Tools/Cloud/azure-cli|azure-cli]] (`az devops`) enumeration.

**Source:** https://github.com/xforcered/ADOKit
**Install:** Build the C# solution (`ADOKit.sln`) in Visual Studio, or grab a release binary; run the resulting `ADOKit.exe`.

```bash
# Validate a stolen PAT / cookie against an org
ADOKit.exe validatecred /credential:<PAT> /url:https://dev.azure.com/<org>

# Recon: search code across the org for secrets; enumerate orgs from a token
ADOKit.exe searchcode /credential:<PAT> /url:https://dev.azure.com/<org> /search:password
ADOKit.exe listorgs   /credential:<PAT>
```

Module categories: **recon** (users, groups, repos, pipelines, service connections, code/secret search, `listorgs`), **privesc** (add self to admin groups, PAT creation), **persistence** (create PATs / service accounts).

---

> [!note] **See also** — [[Services/Web Services/Azure DevOps|Azure DevOps]] — automates the REST-API recon/privesc/persistence this note documents by hand (PAT discovery, service-connection abuse, pipeline secret extraction).

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
