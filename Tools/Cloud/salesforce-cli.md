# salesforce-cli

**Tags:** #Salesforce #CRM #SaaS #cloud #SOQL #enumeration

The official Salesforce command-line tool (`sf`, formerly `sfdx`). It authenticates to an org (interactive web login, JWT, or an access token) and drives the REST/Tooling/Metadata APIs — running SOQL queries, describing objects, executing anonymous Apex, and pulling metadata. On an engagement it's the fastest authenticated client once you hold valid credentials or a token, replacing hand-built curl calls against `/services/data/`.

**Source:** https://developer.salesforce.com/tools/salesforcecli
**Install:** `npm install -g @salesforce/cli`

```bash
sf org login web --instance-url https://<instance>.my.salesforce.com   # interactive
sf data query --query "SELECT Id,Name,Email FROM User" --target-org <alias>
sf data query --query "SELECT Id,DeveloperName,Endpoint FROM NamedCredential" --target-org <alias>
sf apex run --file exploit.apex --target-org <alias>                    # anonymous Apex
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Salesforce|Salesforce]] — authenticated SOQL/Tooling enumeration.
> Related tooling: [[Tools/Scanning/nuclei|nuclei]] (org fingerprinting), [[Tools/Web/Burpsuite|Burp Suite]] (manual Aura testing), [[Tools/File Transfer/cURL|cURL]] (raw REST).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
