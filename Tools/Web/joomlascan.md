# JoomlaScan

**Tags:** `#joomlascan` `#joomla` `#cms` `#webenumeration` `#web`

Joomla component and vulnerability scanner. Enumerates installed components, modules, plugins, and templates, then cross-references findings against a vulnerability database. Built from the ashes of joomscan, with an updated component list and vulnerability database.

**Source:** https://github.com/drego85/JoomlaScan
**Install:**
```bash
git clone https://github.com/drego85/JoomlaScan.git
cd JoomlaScan
pip install -r requirements.txt
python joomlascan.py
```

```bash
python joomlascan.py -u http://target.com
```

> [!note]
> Also consider `joomscan` (OWASP, `sudo apt install joomscan`) — older but pre-installed on Kali. JoomlaScan has a larger component database. Both are passive scanners — they probe paths to detect components, no active exploitation. After identifying components, cross-reference with ExploitDB.

---

## Basic Usage

```bash
# Scan target
python joomlascan.py -u http://target.com

# With threads
python joomlascan.py -u http://target.com -t 10

# Specify port
python joomlascan.py -u http://target.com -p 8080

# User agent
python joomlascan.py -u http://target.com -a "Mozilla/5.0"
```

---

## joomscan (OWASP — pre-installed on Kali)

```bash
# Basic scan
joomscan -u http://target.com

# With proxy
joomscan -u http://target.com --proxy http://127.0.0.1:8080

# Enumerate components
joomscan -u http://target.com --enumerate-components

# Brute force admin
joomscan -u http://target.com --brute-force-login

# Output to file
joomscan -u http://target.com -ec --output report.txt
```

---

## What It Checks

| Category | Detail |
|---|---|
| Version | Joomla core version (from meta tags, XML manifests) |
| Components | com_* extensions by path probing |
| Modules | mod_* sidebar/widget modules |
| Plugins | System, content, authentication plugins |
| Templates | Installed templates |
| Config | Configuration exposure (configuration.php~, .bak) |
| Admin | /administrator/ login page detection |
| Vulnerabilities | CVE cross-reference per detected version/component |

---

## Post-Scan Actions

```bash
# Version disclosure
curl http://target.com/administrator/manifests/files/joomla.xml
curl http://target.com/language/en-GB/en-GB.xml

# Admin login
http://target.com/administrator/

# Default/weak credentials
# admin:admin, admin:password, admin:joomla

# Search for component vulns
searchsploit joomla com_[component_name]
searchsploit joomla 3.x
searchsploit joomla 4.x

# Config exposure
curl http://target.com/configuration.php~
curl http://target.com/configuration.php.bak

# Notable Joomla CVEs
# CVE-2023-23752 — Joomla 4.0.0-4.2.7 — unauthenticated info disclosure (API)
# CVE-2015-8562 — Joomla < 3.4.6 — PHP object injection RCE
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
