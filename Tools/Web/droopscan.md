# droopscan

**Tags:** `#droopscan` `#cms` `#drupal` `#joomla` `#webenumeration` `#web`

Plugin-based CMS scanner focused on Drupal and SilverStripe (with limited Joomla/WordPress support). Identifies CMS version, installed plugins/themes, and interesting URLs. The go-to tool for Drupal fingerprinting, which is notoriously difficult to do manually.

**Source:** https://github.com/SamJoan/droopescan
**Install:** `pip install droopescan` or `sudo apt install droopescan`

```bash
droopescan scan drupal -u http://target.com
```

> [!note]
> droopscan is the primary tool for Drupal. For Joomla, JoomlaScan gives better component coverage. For WordPress, use WPScan. Version detection is probabilistic — based on which core files are present — so results show a range of possible versions.

---

## Basic Usage

```bash
# Drupal
droopescan scan drupal -u http://drupal.target.com

# Joomla
droopescan scan joomla --url http://joomla.target.com/

# SilverStripe
droopescan scan silverstripe -u http://target.com

# Auto-detect CMS
droopescan scan -u http://target.com
```

---

## Scan Options

```bash
# Increase threads (default 4)
droopescan scan drupal -u http://target.com -t 20

# Verbose output
droopescan scan drupal -u http://target.com -v

# Multiple targets from file
droopescan scan drupal -U targets.txt

# JSON output
droopescan scan drupal -u http://target.com --output json
```

---

## What It Checks

| Category | Detail |
|---|---|
| Version | Core file presence + CHANGELOG.txt hash comparison |
| Plugins | Installed modules probed by path |
| Themes | Installed themes probed by path |
| Interesting URLs | CHANGELOG.txt, README.txt, /admin, install.php, xmlrpc.php |

---

## Post-Scan — Drupal

```bash
# Version disclosure — check directly
curl http://target.com/CHANGELOG.txt
curl http://target.com/core/CHANGELOG.txt    # Drupal 8+

# Search for exploits
searchsploit drupal 7.x
searchsploit drupal 8.x
searchsploit drupal 9.x

# Notable CVEs by version
# Drupalgeddon2 (CVE-2018-7600) — RCE, Drupal < 7.58 / 8.x < 8.3.9
# Drupalgeddon3 (CVE-2018-7602) — RCE via AJAX, Drupal 7.x / 8.x
# CVE-2019-6340  — REST RCE, Drupal 8.6.x / 8.5.x

# Default credentials to try
# admin:admin, admin:password, admin:drupal

# Admin login path
http://target.com/user/login
http://target.com/admin
```

---

## Post-Scan — Joomla

```bash
# Admin path
http://target.com/administrator/

# Version disclosure
curl http://target.com/administrator/manifests/files/joomla.xml

# Searchsploit
searchsploit joomla 3.x
searchsploit joomla 4.x
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
