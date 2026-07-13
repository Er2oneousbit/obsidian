# Username Anarchy

**Tags:** `#usernameanarchy` `#userenum` `#osint` `#recon` `#auth` `#wordlist`

Generates username permutations from real names — covers the formats most organizations actually use (`jsmith`, `john.smith`, `smithj`, `j.smith`, etc.). Essential for building targeted username lists before password spraying. Feed it a list of employee names (from LinkedIn, email headers, etc.) and get a ready-to-use wordlist.

**Source:** https://github.com/urbanadventurer/username-anarchy
**Install:** `git clone https://github.com/urbanadventurer/username-anarchy` — Ruby script, no install needed

```bash
# Single name
./username-anarchy John Smith

# List of names from file (First Last, one per line)
./username-anarchy -i names.txt

# Output to file for use with spray tools
./username-anarchy -i names.txt > usernames.txt
```

> [!note] **Workflow** — Collect full names from LinkedIn, email signatures, or OWA/GAL enumeration → feed into Username Anarchy → validate the generated list against the domain with Kerbrute → spray validated users with a safe password.

---

## Format Selection

By default Username Anarchy outputs all formats. Restrict to a specific format when you know the org's naming convention.

```bash
# List all available format plugins
./username-anarchy --list-formats

# Use a specific format only
./username-anarchy -f first.last John Smith       # john.smith
./username-anarchy -f firstlast John Smith        # johnsmith
./username-anarchy -f first_last John Smith       # john_last
./username-anarchy -f flast John Smith            # jsmith
./username-anarchy -f fmlast John Smith           # j.smith (middle initial variant)

# Multiple formats
./username-anarchy -f first.last,flast John Smith
```

**Common corporate formats:**

| Format | Example | Flag |
|---|---|---|
| `first.last` | john.smith | `-f first.last` |
| `flast` | jsmith | `-f flast` |
| `firstlast` | johnsmith | `-f firstlast` |
| `first` | john | `-f first` |
| `last` | smith | `-f last` |
| `lastfirst` | smithjohn | `-f lastfirst` |
| `f.last` | j.smith | `-f f.last` |

---

## Input File Format

```bash
# names.txt — one name per line, First Last
John Smith
Jane Doe
Bob Anderson
Michael Scott

# Generate from file
./username-anarchy -i names.txt > usernames.txt

# Specify format for the whole file
./username-anarchy -i names.txt -f first.last > usernames.txt
```

---

## Common Workflow

```bash
# 1. Collect names (LinkedIn scrape, OWA GAL, etc.)
cat names.txt
# John Smith
# Jane Doe
# ...

# 2. Generate all format variants
./username-anarchy -i names.txt > candidates.txt

# 3. Validate against the domain with Kerbrute (no auth needed)
kerbrute userenum candidates.txt --dc 10.10.10.10 -d inlanefreight.local -o valid_users.txt

# 4. Spray valid users
kerbrute passwordspray valid_users.txt 'Welcome1' --dc 10.10.10.10 -d inlanefreight.local
```

---

## Tips

- If you can observe one valid username (e.g. from an email), you know the format — use `-f` to generate only that pattern for the whole name list
- Combine with `--country` flag for locale-specific formats (some non-English naming conventions differ)
- Output is deduplicated automatically

```bash
# Identify format from a known username, then generate the rest
# Known: j.smith → format is f.last
./username-anarchy -i names.txt -f f.last > usernames.txt
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
