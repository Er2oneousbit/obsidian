# Web Fuzzing

#CWES #WebFuzzing #ffuf #gobuster #feroxbuster #wenum #DirectoryEnum #ParameterFuzzing #VHostFuzzing #APIFuzzing

## What is this?

Automated technique for discovering hidden directories, files, parameters, vhosts, and API endpoints by systematically sending wordlist entries as inputs and analyzing server responses. Use throughout recon and vuln discovery phases. Pairs with [[API Attacks]], [[Web Requests]], [[Information Gathering - Web Edition]].

---

## Key Concepts

| Term | Description |
|---|---|
| `Wordlist` | Dictionary of paths, params, or values fed to the fuzzer |
| `Payload` | The actual data sent per request (wordlist entry + any mutations) |
| `Response Analysis` | Comparing status codes, size, words, lines to filter noise from signal |
| `False Positive` | Result flagged as interesting that isn't (e.g., 404 for non-existent path) |
| `False Negative` | Real vulnerability the fuzzer missed (e.g., logic flaw requiring auth context) |
| `Fuzzing Scope` | Which endpoints/params you're targeting — define before starting |

---

## Tools

| Tool | Install | Primary Use |
|---|---|---|
| `ffuf` | `go install github.com/ffuf/ffuf/v2@latest` | Dir/file/param fuzzing, POST bodies |
| `gobuster` | `go install github.com/OJ/gobuster/v3@latest` | Dir, vhost, DNS subdomain enum |
| `feroxbuster` | `curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \| sudo bash -s $HOME/.local/bin` | Recursive forced browsing |
| `wenum` | `pipx install git+https://github.com/WebFuzzForge/wenum && pipx runpip wenum install setuptools` | Parameter/value fuzzing (wfuzz fork) |

> [!note]
> `wenum` is a drop-in replacement for `wfuzz` — same syntax, actively maintained. wfuzz has install issues on modern systems; prefer wenum.

---

## Wordlists

| Wordlist | Use Case |
|---|---|
| `Discovery/Web-Content/common.txt` | General-purpose starting point |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | Deep directory enum |
| `Discovery/Web-Content/raft-large-directories.txt` | Thorough directory campaigns |
| `Discovery/Web-Content/big.txt` | Wide net — both dirs and files |
| `Discovery/DNS/subdomains-top1million-5000.txt` | Subdomain enumeration |

> [!note]
> SecLists path on Kali/Pwnbox: `/usr/share/seclists/` (lowercase). Some systems use `/usr/share/SecLists/`. Check if a command errors on the wordlist path itself.

---

## Directory Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ
```

| Flag | Description |
|---|---|
| `-w` | Wordlist path |
| `-u` | Target URL — `FUZZ` is the insertion point |
| `-mc` | Match status codes (default: `200-299,301,302,307,401,403,405,500`) |
| `-fc` | Filter (exclude) status codes |
| `-fs` / `-ms` | Filter/match by response size (bytes) |
| `-fw` / `-mw` | Filter/match by word count |
| `-fl` / `-ml` | Filter/match by line count |
| `-mt` | Match by time-to-first-byte (e.g., `-mt >500`) |

```bash
# Filter common noise
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -fc 404,401,302

# Match only 200, filter responses with 427 words, size > 500 bytes
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://<TARGET_IP>:<PORT>/FUZZ -mc 200 -fw 427 -ms ">500"
```

---

## File Extension Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/DIRECTORY/FUZZ -e .php,.html,.txt,.bak,.js -v
```

| Flag | Description |
|---|---|
| `-e` | Extensions to append to each wordlist entry — multiplies requests by count |
| `-v` | Verbose — shows full URL in output |

---

## Recursive Fuzzing

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://<TARGET_IP>:<PORT>/FUZZ -e .html -recursion -recursion-depth 2 -rate 500
```

| Flag | Description |
|---|---|
| `-recursion` | Auto-fuzz newly discovered directories |
| `-recursion-depth` | Max depth — always set this, default is unlimited |
| `-rate` | Requests per second — throttle to avoid overwhelming target |
| `-ic` | Ignore comment lines in wordlist (lines starting with `#`) |

> [!warning]
> Uncapped recursive fuzzing on a deep app generates millions of requests. Always set `-recursion-depth`. Check RoE for rate limits before running.

---

## GET Parameter Fuzzing

```bash
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://<TARGET_IP>:<PORT>/page.php?x=FUZZ"
```

| Flag | Description |
|---|---|
| `--hc` / `--sc` | Hide/show by status code |
| `--hw` / `--sw` | Hide/show by word count |
| `--hl` / `--sl` | Hide/show by line count |
| `--hs` / `--ss` | Hide/show by size (bytes) |
| `--hr` / `--sr` | Hide/show by regex match on body |

```bash
# Probe manually first to understand baseline response
curl "http://<TARGET_IP>:<PORT>/page.php?x=test"

# Show only short responses (likely the valid hit)
wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --sc 200 --sw 1-5 -u "http://<TARGET_IP>:<PORT>/page.php?x=FUZZ"
```

---

## POST Parameter Fuzzing

```bash
ffuf -u http://<TARGET_IP>:<PORT>/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v
```

| Flag | Description |
|---|---|
| `-X POST` | HTTP method |
| `-H` | Set request header |
| `-d "y=FUZZ"` | POST body — `FUZZ` is the value under test |
| `-mc 200` | Match only 200 responses |
| `-fc` | Filter (exclude) status codes |
| `-fs` | Filter by response size |

```bash
# Probe manually first
curl -d "" http://<TARGET_IP>:<PORT>/post.php
```

---

## VHost Fuzzing

```bash
echo "<TARGET_IP> inlanefreight.htb" | sudo tee -a /etc/hosts
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain
```

| Flag | Description |
|---|---|
| `-u` | Base URL — the server receiving requests |
| `--append-domain` | Appends base domain to each word (e.g., `admin.inlanefreight.htb`) |
| `-s` | Include only these status codes |
| `-b` | Exclude these status codes |
| `--exclude-length` | Exclude by response size (supports ranges) |

Focus on `Status: 200` results. `400` responses are usually malformed wordlist entries, not valid vhosts.

```bash
# Exclude noise
gobuster vhost -u http://inlanefreight.htb:80 -w /usr/share/seclists/Discovery/Web-Content/common.txt --append-domain -b 400,404
```

---

## Subdomain DNS Fuzzing

```bash
gobuster dns --domain inlanefreight.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

| Flag | Description |
|---|---|
| `--domain` | Target domain for subdomain enum |
| `-t` | Threads (default 10) |

> [!note]
> Newer gobuster versions changed `-d` to set request delay. Use `--domain` to specify the target domain.

---

## Validating Findings

1. **Reproduce with curl or Burp** — not the fuzzer
2. **Check headers first** — confirms file type and size without pulling the body
3. **PoC only** — don't extract data; header evidence is enough for a report

```bash
# Confirm directory listing
curl http://<TARGET_IP>:<PORT>/backup/

# Header-only check — no data pulled
curl -I http://<TARGET_IP>:<PORT>/backup/password.txt
```

Key headers:
- `Content-Type` — confirms file type (`application/sql`, `text/plain`, etc.)
- `Content-Length` — non-zero means file has content; zero = likely empty

> [!tip]
> Directory listing + non-empty sensitive filename in headers = sufficient evidence. You don't need to read the file to prove the vuln.

---

## API Endpoint Discovery

| API Type | Endpoint Style | Params Location | How to Discover |
|---|---|---|---|
| REST | `/users`, `/items/{id}` | URL path, query string, body | Swagger/OpenAPI docs, Burp, ffuf |
| SOAP | Single endpoint (e.g., `/service`) | XML SOAP envelope body | WSDL file — append `?wsdl` to URL |
| GraphQL | Single endpoint (e.g., `/graphql`) | Query/mutation body | Introspection query, GraphiQL UI |

```bash
# Fuzz for undocumented REST endpoints
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/FUZZ -mc 200,201,204,301,302,307,401,403,405

# GraphQL introspection
curl -s -X POST http://<TARGET_IP>:<PORT>/graphql -H "Content-Type: application/json" -d '{"query":"{__schema{types{name}}}"}'
```

Check these paths first before fuzzing: `/docs`, `/swagger`, `/api-docs`, `/openapi.json`

---

## API Parameter Fuzzing

```bash
# Fuzz REST query parameter value
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "http://<TARGET_IP>:<PORT>/api/v1/items?id=FUZZ" -mc 200

# Fuzz POST JSON body value
ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://<TARGET_IP>:<PORT>/api/v1/items -X POST -H "Content-Type: application/json" -d '{"name":"FUZZ"}' -mc 200,201
```

| Flag | Description |
|---|---|
| `-mc` | Match status codes |
| `-fc` | Filter status codes |
| `-fs` | Filter by response size |

---

## API Vuln Classes

| Vuln | How to Fuzz |
|---|---|
| BOLA/IDOR | Fuzz object IDs in path — `/items/FUZZ` — look for other users' data |
| Broken Function-Level Auth | Fuzz HTTP methods (`-X DELETE`, `-X PUT`) on GET-only documented endpoints |
| SSRF | Inject internal IPs/URLs into parameters that accept URLs or hostnames |
| Hidden endpoints | Undocumented routes often have no auth — high value targets |

See [[API Attacks]] for full exploitation methodology.

---

*Created: 2026-05-12*
*Updated: 2026-05-13*
*Model: claude-sonnet-4-6*