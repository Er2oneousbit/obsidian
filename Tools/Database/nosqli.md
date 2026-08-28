# nosqli

**Tags:** #nosqli #NoSQL #NoSQLi #MongoDB #injection #WebAppAttacks #Scanner #Go

`nosqli` is a lightweight, web-focused NoSQL injection scanner written in Go. It targets the common MongoDB operator-injection classes against HTTP endpoints — auth bypass and blind data extraction via `$ne`/`$gt`/`$regex` — without the interactive-menu weight and Python-2 baggage of [[Tools/Database/NoSQLMap|NoSQLMap]]. Point it at a login or search endpoint and it fuzzes the parameters for injectable operators.

**Source:** https://github.com/Charlie-belmer/nosqli
**Install:** `go install github.com/Charlie-belmer/nosqli@latest` (single static binary)

```bash
# Scan a target URL — auto-detects GET/POST params
nosqli scan -t "http://<TARGET>/login"

# POST body with explicit request data
nosqli scan -t "http://<TARGET>/login" -r "username=admin&password=admin"

# JSON body
nosqli scan -t "http://<TARGET>/api/login" \
  -r '{"username":"admin","password":"admin"}' \
  --content-type application/json

# Authenticated / with a cookie
nosqli scan -t "http://<TARGET>/search?q=test" -a "session=<token>"
```

| Flag | Description |
|---|---|
| `scan` | Run the injection scan |
| `-t` | Target URL |
| `-r` | Request body / data |
| `-a` | Cookie/header for auth |
| `-p` | Proxy (route through Burp) |
| `--content-type` | Force the request content type |

> [!note] It focuses on **web-layer operator injection** — auth bypass and `$regex` extraction. It does not cover aggregation-pipeline injection (`$lookup`/`$unionWith`), direct-DB attacks, or the CouchDB/Redis/ES surfaces — test those by hand or with [[Tools/Database/NoSQLMap|NoSQLMap]].

> [!tip] Run it through Burp with `-p http://127.0.0.1:8080` so you capture the exact injectable request it finds and can iterate on the payload manually — the scanner confirms the injection point; hand-crafting gets you the data.

> [!note] **See also** — [[Techniques/NoSQL Injection|NoSQL Injection]] — automated web-layer NoSQLi discovery; pairs with [[Tools/Database/mongosh|mongosh]] for direct DB testing once an instance is reachable.

---

*Created: 2026-07-31*
*Updated: 2026-07-31*
*Model: claude-opus-5*
