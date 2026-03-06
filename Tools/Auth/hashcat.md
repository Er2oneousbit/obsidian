# Hashcat

**Tags:** `#hashcat` `#passwordcracking` `#hashcracking` `#auth` `#gpu`

GPU-accelerated password cracker — the go-to tool for bulk hash cracking. Orders of magnitude faster than CPU-based tools (JTR) for most hash types. Supports 300+ hash modes covering everything from MD5 to bcrypt to Kerberos tickets.

**Source:** https://hashcat.net/hashcat/
**Example hashes:** https://hashcat.net/wiki/doku.php?id=example_hashes
**Install:** pre-installed on Kali (`hashcat`) — GPU drivers required for full performance

```bash
# Check GPU is detected
hashcat -I

# Fall back to CPU if no GPU (slower but functional)
hashcat --force    # add to any command to force CPU mode
```

> [!note] **Hashcat vs JTR** — Use hashcat for GPU-accelerated bulk cracking of large hash dumps. Use JTR for the 2john file extraction workflow (SSH keys, KeePass, Office docs) and quick single-mode runs. They complement each other.

---

## Hash Identification

Before cracking, identify the hash type.

```bash
# hashcat example hashes wiki — best reference
# https://hashcat.net/wiki/doku.php?id=example_hashes

# hashid — identify hash format
hashid '<hash>'
hashid -m '<hash>'    # -m shows the hashcat mode number

# hash-identifier (alternative)
hash-identifier

# Find mode by name
hashcat --help | grep -i ntlm
hashcat --help | grep -i kerberos
hashcat --help | grep -i bcrypt
```

---

## Attack Modes

| Mode | Flag | Description |
|---|---|---|
| Dictionary | `-a 0` | Wordlist, optionally with rules |
| Combinator | `-a 1` | Combines two wordlists (word1+word2) |
| Brute Force | `-a 3` | Mask-based character set attack |
| Hybrid Wordlist+Mask | `-a 6` | Wordlist entries with mask appended |
| Hybrid Mask+Wordlist | `-a 7` | Mask prepended to wordlist entries |
| Association | `-a 9` | Uses known plaintext hints |

---

## Common Hash Modes

| Mode | Hash Type |
|---|---|
| `0` | MD5 |
| `100` | SHA1 |
| `1000` | NTLM |
| `1800` | SHA-512 crypt (`$6$` — Linux shadow) |
| `3200` | bcrypt |
| `5600` | NTLMv2 (Responder captures) |
| `5500` | NTLMv1 |
| `13100` | Kerberoasting (TGS-REP / `$krb5tgs$`) |
| `18200` | ASREPRoasting (`$krb5asrep$`) |
| `2100` | DCC2 / MS Cache v2 |
| `7300` | IPMI2 RAKP HMAC-SHA1 |
| `500` | MD5 crypt (`$1$` — Linux shadow) |
| `7400` | SHA-256 crypt (`$5$` — Linux shadow) |
| `1500` | DES crypt (legacy Linux) |
| `400` | phpBB / WordPress / Joomla MD5 |
| `3000` | LM hash |
| `5200` | KeePass |
| `9600` | MS Office 2013 |
| `13400` | KeePass 1/2 |
| `16500` | JWT (HS256) |
| `22000` | WPA-PBKDF2 / WPA2 |

---

## Dictionary Attack (`-a 0`)

```bash
# Basic wordlist
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# Wordlist + rules (most effective combo)
hashcat -a 0 -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Multiple rule files
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r best64.rule -r /usr/share/hashcat/rules/d3ad0ne.rule

# Show results as they crack
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --status --status-timer=10
```

---

## Mask Attack / Brute Force (`-a 3`)

Use when you know the password pattern (e.g. corporate policy: 8 chars, upper+lower+digit+symbol).

```bash
# Mask character sets
# ?l = lowercase (a-z)
# ?u = uppercase (A-Z)
# ?d = digit (0-9)
# ?s = special (!@#$%^&*...)
# ?a = all printable ASCII
# ?b = all bytes (0x00-0xff)

# 8-char alphanumeric
hashcat -a 3 -m 1000 hashes.txt '?a?a?a?a?a?a?a?a'

# Pattern: Capital + 5 lowercase + 2 digits (e.g. Password12)
hashcat -a 3 -m 1000 hashes.txt '?u?l?l?l?l?l?d?d'

# Known prefix — "Winter" + 4 digits
hashcat -a 3 -m 1000 hashes.txt 'Winter?d?d?d?d'

# Custom charset — define your own
hashcat -a 3 -m 1000 hashes.txt -1 '?l?d' '?1?1?1?1?1?1?1?1'    # lowercase + digits only

# Increment (try all lengths from min to max)
hashcat -a 3 -m 1000 hashes.txt '?a?a?a?a?a?a?a?a' --increment --increment-min=6
```

---

## Hybrid Attacks (`-a 6` / `-a 7`)

Best for corporate passwords that follow a pattern — wordlist base with appended/prepended digits or symbols.

```bash
# Wordlist + mask (append) — e.g. "password123!", "summer2024"
hashcat -a 6 -m 1000 hashes.txt rockyou.txt '?d?d?d?d'

# Mask + wordlist (prepend) — e.g. "2024password"
hashcat -a 7 -m 1000 hashes.txt '?d?d?d?d' rockyou.txt
```

---

## Combinator Attack (`-a 1`)

Concatenates every word from list1 with every word from list2.

```bash
hashcat -a 1 -m 1000 hashes.txt wordlist1.txt wordlist2.txt

# With rules applied to each side
hashcat -a 1 -m 1000 hashes.txt wordlist1.txt wordlist2.txt -j '$-' -k '$!'
# -j = rule for left word, -k = rule for right word
```

---

## Rules

Rules mutate wordlist entries on the fly — far more effective than a plain wordlist.

```bash
# Built-in rules (Kali)
ls /usr/share/hashcat/rules/
# best64.rule        — 64 high-value rules, good starting point
# d3ad0ne.rule       — large, thorough ruleset
# dive.rule          — very large, slow but comprehensive
# rockyou-30000.rule — derived from rockyou patterns
# T0XlC.rule         — aggressive mutations
# KoreLogic/         — corporate-focused rules

# Use best64 first, escalate if needed
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/d3ad0ne.rule

# Generate a mutated wordlist (save output, don't crack)
hashcat -a 0 --stdout rockyou.txt -r /usr/share/hashcat/rules/best64.rule > mutated.txt

# Community rules
# https://github.com/NotSoSecure/password_cracking_rules
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -r OneRuleToRuleThemAll.rule
```

### Common Rule Functions

| Rule | Effect |
|---|---|
| `:` | Do nothing (passthrough) |
| `l` | Lowercase all |
| `u` | Uppercase all |
| `c` | Capitalise first letter |
| `r` | Reverse word |
| `d` | Duplicate word |
| `$X` | Append character X |
| `^X` | Prepend character X |
| `sXY` | Replace X with Y |
| `D0` | Delete first character |
| `p2` | Duplicate word twice |
| `T0` | Toggle case of first character |
| `z1` | Duplicate first character |

---

## Common Pentest Scenarios

### NTLM Hashes (Windows SAM / secretsdump)

```bash
hashcat -a 0 -m 1000 ntlm.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### NTLMv2 (Responder / Inveigh Captures)

```bash
hashcat -a 0 -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Kerberoasting (TGS-REP)

```bash
hashcat -a 0 -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### ASREPRoasting (AS-REP)

```bash
hashcat -a 0 -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### Linux Shadow (`/etc/shadow`)

```bash
# SHA-512 ($6$)
hashcat -a 0 -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# MD5 ($1$)
hashcat -a 0 -m 500 shadow.txt /usr/share/wordlists/rockyou.txt

# SHA-256 ($5$)
hashcat -a 0 -m 7400 shadow.txt /usr/share/wordlists/rockyou.txt
```

### DCC2 / Domain Cached Credentials

```bash
hashcat -a 0 -m 2100 dcc2.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule
```

### JWT (HS256 Secret Brute Force)

```bash
hashcat -a 0 -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt
```

### WPA2

```bash
hashcat -a 0 -m 22000 handshake.hccapx /usr/share/wordlists/rockyou.txt
```

---

## Session Management

```bash
# Named session — survives interruption
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --session=client1

# Restore session
hashcat --restore --session=client1

# Show cracked hashes from potfile
hashcat -m 1000 hashes.txt --show

# Custom potfile per engagement
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --potfile-path=./client.pot
hashcat -m 1000 hashes.txt --show --potfile-path=./client.pot
```

---

## Performance Tuning

```bash
# Check detected GPUs/CPUs
hashcat -I

# Workload profile (1=low, 2=default, 3=high, 4=nightmare)
hashcat -a 0 -m 1000 hashes.txt rockyou.txt -w 3

# Limit GPU temp (°C) to prevent throttling
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --gpu-temp-abort=90

# Benchmark a specific mode
hashcat -b -m 1000    # NTLM benchmark
hashcat -b -m 13100   # Kerberoast benchmark

# CPU-only (no GPU / VM environment)
hashcat -a 0 -m 1000 hashes.txt rockyou.txt --force
```

---

## Recommended Attack Order

```
1. hashcat -a 0 -m <mode> hashes.txt rockyou.txt                          # plain wordlist
2. hashcat -a 0 -m <mode> hashes.txt rockyou.txt -r best64.rule            # wordlist + rules
3. hashcat -a 0 -m <mode> hashes.txt rockyou.txt -r d3ad0ne.rule           # larger ruleset
4. hashcat -a 6 -m <mode> hashes.txt rockyou.txt '?d?d?d?d'               # hybrid append digits
5. hashcat -a 6 -m <mode> hashes.txt rockyou.txt '?d?d?d?d' -r best64.rule # hybrid + rules
6. hashcat -a 0 -m <mode> hashes.txt <bigger_list> -r OneRuleToRuleThemAll  # escalate wordlist
7. hashcat -a 3 -m <mode> hashes.txt '?a?a?a?a?a?a?a?a' --increment       # brute force last resort
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
