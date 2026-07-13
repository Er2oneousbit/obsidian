# crunch

**Tags:** `#crunch` `#wordlists` `#generation` `#bruteforce` `#passwords`

Pattern and charset-based wordlist generator. Generates every possible combination of characters for a given length and charset, or uses a pattern to define exact structure. Use when you know the password format (length, character set, prefix/suffix, structure) and need a targeted list instead of a generic one.

**Source:** https://github.com/crunchword/crunch
**Install:** `sudo apt install crunch` (pre-installed on Kali)

```bash
crunch <min-len> <max-len> [charset] [options]
```

> [!note]
> crunch generates exhaustive lists — they grow exponentially. A 6-character alphanumeric list is ~57 billion words. Use `-t` patterns, charsets, and piping directly into tools to avoid disk space issues. For targeted attacks based on known personal info, use cupp instead.

---

## Basic Syntax

```bash
# Generate all 4-char combos from lowercase letters
crunch 4 4 abcdefghijklmnopqrstuvwxyz

# Generate 6-8 char combos from lowercase + digits
crunch 6 8 abcdefghijklmnopqrstuvwxyz0123456789

# Save to file
crunch 4 6 abc123 -o wordlist.txt

# Pipe directly into tool (avoids disk usage)
crunch 4 4 0123456789 | hashcat -m 0 hash.txt --stdin
crunch 4 4 0123456789 | hydra -l admin -P - ssh://target.com
```

---

## Built-in Charsets

crunch ships with `/usr/share/crunch/charset.lst`:

```bash
# Use a named charset from charset.lst
crunch 6 8 -f /usr/share/crunch/charset.lst mixalpha-numeric

# Common charset names:
# lalpha          — lowercase a-z
# ualpha          — uppercase A-Z
# numeric         — 0-9
# lalpha-numeric  — lowercase + digits
# ualpha-numeric  — uppercase + digits
# mixalpha        — upper + lowercase
# mixalpha-numeric — upper + lower + digits
# mixalpha-numeric-all-space — above + symbols

crunch 8 8 -f /usr/share/crunch/charset.lst mixalpha-numeric
```

---

## Pattern Mode (`-t`)

Pattern tokens:
- `@` — lowercase letter
- `,` — uppercase letter
- `%` — digit
- `^` — symbol

```bash
# PIN: exactly 4 digits
crunch 4 4 -t %%%%

# Password pattern: Capital + 5 lower + 2 digits (e.g. Summer22)
crunch 8 8 -t ,@@@@@%%

# Known prefix: "Admin" + 3 digits
crunch 8 8 -t Admin%%%

# Known suffix: 4 letters + "2024"
crunch 8 8 -t @@@@2024

# Exact string with wildcard digits
crunch 10 10 -t Password%%

# Mixed: one symbol at end
crunch 9 9 -t ,@@@@@%%^
```

---

## Useful Options

| Flag | Description |
|------|-------------|
| `-o <file>` | Output to file |
| `-t <pattern>` | Use pattern (@ , % ^) |
| `-f <file> <name>` | Use charset from charset.lst |
| `-p <words>` | Permutations of given words/chars (no repeat) |
| `-d <n>` | Max consecutive same char (e.g., `-d 2@` = max 2 same lowercase) |
| `-i` | Invert output order |
| `-b <size>` | Split output into files of given size (e.g., `-b 100mb`) |
| `-c <n>` | Lines per output file (splits automatically) |
| `-s <word>` | Start at specific word |
| `-e <word>` | Stop at specific word |
| `-q <file>` | Read chars from file (one per line) |
| `-z <type>` | Compress output: gzip/bzip2/lzma/7z |

---

## Word Permutations (`-p`)

```bash
# All permutations of given characters (no repeat)
crunch 1 1 -p abc

# All permutations of given words (space-separated)
crunch 1 1 -p dog cat bird

# Combine words + crunch: prefix + all word permutations
# e.g., generate first.last username variants
crunch 5 5 -p john smith
```

---

## Splitting Large Wordlists

```bash
# Split into 100MB files
crunch 8 8 mixalpha-numeric -b 100mb -o START

# Split into 1M line files
crunch 8 8 0123456789 -c 1000000 -o START
# Creates: crunch1.txt, crunch2.txt, ...
```

---

## Practical Examples

```bash
# 4-digit PIN (ATM/phone)
crunch 4 4 0123456789 -o pins.txt

# 6-char numeric OTP
crunch 6 6 0123456789 -o otp.txt

# WPA passphrase: 8-char lowercase + digits
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789 -o wpa.txt

# Company password pattern: Corp + 4 digits
crunch 8 8 -t Corp%%%% -o corp_passwords.txt

# Pipe into aircrack-ng (WPA)
crunch 8 8 0123456789 | aircrack-ng capture.cap -e SSID -w -

# Pipe into john
crunch 6 6 0123456789 | john --stdin hash.txt

# Generate seasonal passwords (Summer + year + symbol)
crunch 10 10 -t Summer2024^
```

---

## Size Estimation

```bash
# crunch will show estimated size before generating
crunch 8 8 abcdefghijklmnopqrstuvwxyz0123456789
# Output: Crunch will now generate the following amount of data: X MB/GB

# Calculate manually:
# charset_size ^ length = number of combinations
# e.g., 36^8 = 2,821,109,907,456 ≈ 2.8 trillion (too large to save)
# Always pipe into tool or use tight patterns to keep lists manageable
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
