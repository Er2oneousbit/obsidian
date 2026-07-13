# CeWL

**Tags:** `#cewl` `#wordlist` `#webenumeration` `#passwords` `#web`

Custom Word List generator. Spiders a target website and extracts words to build a domain-specific wordlist. Useful for password spraying, directory brute force, and credential attacks against targets where employees likely use company-related terms in their passwords.

**Source:** https://github.com/digininja/CeWL
**Install:** Pre-installed on Kali — `sudo apt install cewl`

```bash
cewl http://target.com -d 3 -m 6 -w wordlist.txt
```

> [!note]
> Most effective for password spraying against corporate targets — employees commonly use company names, product names, and internal terminology in passwords. Combine output with hashcat rules for variants. Use `-e` to also extract email addresses for username lists.

---

## Basic Usage

```bash
# Basic crawl — depth 3, minimum word length 6, lowercase
cewl http://target.com -d 3 -m 6 --lowercase -w wordlist.txt

# Deeper crawl
cewl https://www.inlanefreight.com -d 5 -m 6 --lowercase -w inlane.txt

# With custom user agent
cewl http://target.com -d 3 -m 5 -u "Mozilla/5.0" -w wordlist.txt

# Authenticated (basic auth)
cewl http://target.com --auth_type basic --auth_cred admin:password -w wordlist.txt

# With session cookie
cewl http://target.com --cookie "session=abc123" -d 3 -m 5 -w wordlist.txt
```

---

## Email Extraction

```bash
# Extract emails alongside wordlist
cewl http://target.com -d 3 -m 5 -e --email_file emails.txt -w wordlist.txt

# Emails useful for:
# - Username format discovery (first.last@company.com → first.last format)
# - Password spray target list
```

---

## Metadata Extraction

```bash
# Extract metadata from documents found during crawl (PDF, Word, etc.)
cewl http://target.com -d 3 -a --meta_file metadata.txt -w wordlist.txt

# Metadata often contains:
# - Author names (username leads)
# - Software versions
# - Internal paths / hostnames
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-d <depth>` | Spidering depth (default: 2) |
| `-m <length>` | Minimum word length (default: 3) |
| `-w <file>` | Output wordlist file |
| `--lowercase` | Lowercase all words |
| `-e` | Extract email addresses |
| `--email_file <file>` | Save emails to file |
| `-a` | Extract document metadata |
| `--meta_file <file>` | Save metadata to file |
| `-u <agent>` | Custom user agent |
| `--cookie <cookie>` | Session cookie |
| `--auth_type` | Auth: basic or digest |
| `--auth_cred` | Credentials: user:pass |
| `--proxy` | Proxy URL |
| `-v` | Verbose |

---

## Wordlist Enhancement

```bash
# Apply hashcat rules for variants
hashcat --stdout wordlist.txt -r /usr/share/hashcat/rules/best64.rule > wordlist_rules.txt

# john rules
john --wordlist=wordlist.txt --rules --stdout > wordlist_john.txt

# Combine with existing wordlists
cat wordlist.txt /usr/share/wordlists/rockyou.txt | sort -u > combined.txt
```

---

## Common Workflow

```bash
# 1. Generate domain-specific wordlist
cewl https://inlanefreight.com -d 4 -m 6 --lowercase \
  -e --email_file emails.txt -w cewl_words.txt

# 2. Enhance with rules
hashcat --stdout cewl_words.txt \
  -r /usr/share/hashcat/rules/best64.rule > cewl_enhanced.txt

# 3. Password spray
crackmapexec smb 10.10.10.10 -u usernames.txt -p cewl_enhanced.txt --continue-on-success
hydra -L usernames.txt -P cewl_enhanced.txt target.com http-post-form "/login:user=^USER^&pass=^PASS^:Invalid"
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
