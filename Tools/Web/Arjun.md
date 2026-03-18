# Arjun

**Tags:** `#arjun` `#webenumeration` `#parameters` `#fuzzing` `#web`

HTTP parameter discovery tool. Finds hidden GET/POST/JSON/XML parameters by fuzzing a large parameter wordlist and detecting changes in response size, status, or behavior. Essential for finding undocumented API parameters, hidden admin flags, and debug parameters that may introduce vulnerabilities.

**Source:** https://github.com/s0md3v/Arjun
**Install:** `pip install arjun` or `sudo apt install arjun`

```bash
arjun -u http://target.com/endpoint
```

> [!note]
> Arjun works by sending chunks of parameters and using binary search to identify which ones cause a response difference. Default wordlist is built-in (~25k params). Run on every API endpoint — hidden parameters are a common source of IDOR, SQLi, and logic flaws.

---

## Basic Usage

```bash
# GET parameter discovery
arjun -u http://target.com/search

# POST parameter discovery
arjun -u http://target.com/login -m POST

# JSON body
arjun -u http://target.com/api/v1/user -m JSON

# XML body
arjun -u http://target.com/api -m XML
```

---

## Authentication & Headers

```bash
# With cookies
arjun -u http://target.com/api -c "session=abc123; admin=0"

# With custom headers
arjun -u http://target.com/api -H "Authorization: Bearer token"

# With existing POST data (adds discovered params to it)
arjun -u http://target.com/api -m POST -d "existing=value"
```

---

## Wordlists & Rate

```bash
# Custom wordlist
arjun -u http://target.com/ -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt

# Chunk size (params per request — lower = more accurate, slower)
arjun -u http://target.com/ --chunk-size 250

# Delay between requests (ms)
arjun -u http://target.com/ --delay 500

# Threads
arjun -u http://target.com/ -t 5
```

---

## Multiple Targets & Output

```bash
# From file (one URL per line)
arjun -i targets.txt

# Save results to JSON
arjun -u http://target.com/ -o results.json

# Quiet (only show found params)
arjun -u http://target.com/ -q
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `-u` | Target URL |
| `-m` | Method: GET (default), POST, JSON, XML |
| `-w` | Wordlist |
| `-d` | POST data to include |
| `-c` | Cookies |
| `-H` | Headers (repeatable) |
| `-t` | Threads (default 15) |
| `--delay` | Delay between requests (ms) |
| `--chunk-size` | Params per request (default 500) |
| `-i` | Input file (list of URLs) |
| `-o` | Output file (JSON) |
| `-q` | Quiet mode |
| `--stable` | More stable detection (slower) |

---

## Workflow

```bash
# 1. Discover hidden parameters on an API endpoint
arjun -u http://target.com/api/user -H "Authorization: Bearer token"
# Found: id, debug, format

# 2. Test debug param
curl "http://target.com/api/user?debug=true" -H "Authorization: Bearer token"

# 3. Test for IDOR via id param
for i in $(seq 1 20); do
    curl -s "http://target.com/api/user?id=$i" -H "Authorization: Bearer token"
done
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
