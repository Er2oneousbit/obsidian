# cupp

**Tags:** `#cupp` `#wordlists` `#generation` `#osint` `#passwords` `#targeted`

Common User Passwords Profiler. Generates targeted password wordlists based on personal information about a target — name, birthdate, partner, pet, company, keywords. Produces a compact list of high-probability guesses. Use after OSINT collection when you have personal details about a target and want to maximize hit rate before reaching for rockyou.

**Source:** https://github.com/Mebus/cupp
**Install:** `sudo apt install cupp` or `git clone https://github.com/Mebus/cupp`

```bash
cupp -i
```

> [!note]
> cupp is most effective combined with OSINT. Pull personal info from LinkedIn, social media, company sites, and breach data first. The interactive mode generates mutations automatically (leetspeak, appended digits/years, capitalization, special chars). Output lists are typically 10k–100k words — much smaller than rockyou but highly targeted.

---

## Interactive Mode (`-i`)

```bash
cupp -i
```

Prompts for:
```
First name:           → target's first name
Surname:              → target's last name
Nickname:             → known nicknames/usernames
Birthdate (DDMMYYYY): → DOB
Partner's name:       → spouse/partner name
Partner's nickname:   →
Partner's birthdate:  →
Child's name:         →
Child's nickname:     →
Child's birthdate:    →
Pet's name:           →
Company name:         →
Keywords:             → job title, hobbies, interests, city
Do you want special chars? [y/n]
Do you want random numbers? [y/n]
Leet mode? [y/n]      → a→4, e→3, i→1, o→0, s→5
```

Outputs: `[firstname].txt`

---

## Other Modes

```bash
# Download large alecto database (breach-based)
cupp -a

# Parse existing wordlist and add cupp mutations
cupp -w existing_wordlist.txt

# Update cupp itself
cupp -v
```

---

## What cupp Generates

Given `John Smith`, born `15/03/1985`, pet `Rex`, company `Acme`:

```
john
john1985
john85
john1503
john031985
johnsmith
smith1985
smithjohn
rex
rex1985
acme
acme2024
John
John1985
J0hn          ← leet
j0hn1985
j0hn!
John!
John1985!
smith@
...
```

Mutations applied:
- Capitalization (first char, all caps)
- Appended years (birth year, current year, 1990–2030 range)
- Appended digits (1–999)
- Appended symbols (`!`, `@`, `#`, `$`)
- Reversed strings
- Leetspeak substitutions
- Combinations of above

---

## Workflow

```bash
# 1. OSINT — collect target info from:
#    LinkedIn, Facebook, Instagram, company site, breach data, WHOIS

# 2. Run cupp interactive
cupp -i
# → outputs john.txt (or whatever first name)

# 3. Use generated list
hashcat -m 0 hash.txt john.txt
hashcat -m 1000 ntlm.txt john.txt           # NTLM
hashcat -m 13100 kerberoast.txt john.txt    # Kerberoast

# 4. Combine with rules for more coverage
hashcat -m 0 hash.txt john.txt -r /usr/share/hashcat/rules/best64.rule

# 5. Online spray (slow, lockout-aware)
crackmapexec smb target.com -u john.smith -P john.txt --no-bruteforce
```

---

## Combining with Other Tools

```bash
# Merge cupp output with rockyou top 1k for broader coverage
cat john.txt /usr/share/seclists/Passwords/Common-Credentials/10k-most-common.txt \
  | sort -u > combined.txt

# Add company-specific terms via CeWL, then merge
cewl https://company.com -d 2 -m 5 -w cewl_out.txt
cat john.txt cewl_out.txt | sort -u > targeted.txt

# Run with multiple hashcat rules
hashcat -m 0 hash.txt targeted.txt \
  -r /usr/share/hashcat/rules/best64.rule \
  -r /usr/share/hashcat/rules/toggles1.rule
```

---

## Tips

```bash
# If DOB unknown — try common years in Keywords field:
# Keywords: 1990, 1991, 1992, ... or just the company name + job role

# cupp -w can mutate an existing small list:
echo -e "summer\nwinter\nfootball\nmanchester" > hobbies.txt
cupp -w hobbies.txt
# → hobbies_cupp.txt with mutations applied to each word

# For AD environments — also try username as password:
# john.smith:john.smith, jsmith:jsmith, etc.
crackmapexec smb dc01.corp.local -u users.txt -p users.txt --no-bruteforce
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
