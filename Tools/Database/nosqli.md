# nosqli

**Tags:** #nosqli #NoSQL #NoSQLi #MongoDB #injection #WebAppAttacks #Scanner #Go

`nosqli` is a lightweight, web-focused NoSQL injection scanner written in Go. It targets the common MongoDB operator-injection classes against HTTP endpoints — auth bypass and blind data extraction via `$ne`/`$gt`/`$regex` — without the interactive-menu weight and Python-2 baggage of [[Tools/Database/NoSQLMap|NoSQLMap]]. Point it at a login or search endpoint and it fuzzes the parameters for injectable operators.

**Source:** https://github.com/Charlie-belmer/nosqli
**Install:** `go install github.com/Charlie-belmer/nosqli@latest` (single static binary)

```bash
# Scan a target URL — auto-detects GET/POST params
nosqli scan -t "http://<TARGET>/login"

# POST with default body data (-d, NOT -r) — data should NOT contain injection strings
nosqli scan -t "http://<TARGET>/login" -d "username=admin&password=admin"

# JSON body / authenticated / custom headers → save the request from Burp/ZAP and load it with -r.
# -r takes a FILE (a raw HTTP request), which is also how you carry a session cookie or Content-Type:
nosqli scan -r ./login_request.txt

# Route through Burp to capture the injectable request it finds
nosqli scan -t "http://<TARGET>/login" -p http://127.0.0.1:8080

# Custom user agent
nosqli scan -t "http://<TARGET>/login" -u "Mozilla/5.0 ..."
```

| Flag | Description |
|---|---|
| `scan` | Run the injection scan |
| `-t, --target` | Target URL (e.g. `http://site/page?arg=1`) |
| `-r, --request` | Load a raw HTTP request from a **file** (Burp/ZAP export) — the way to send JSON, cookies, or custom headers |
| `-d, --data` | Default POST body data (should NOT include injection strings) |
| `-p, --proxy` | Proxy requests through this URL (Burp) |
| `-u, --user-agent` | Set the User-Agent |

> [!warning] There is **no `-a` cookie flag and no `--content-type` flag** — earlier drafts of this note invented both. For authenticated or JSON endpoints, capture the full request in Burp, save it, and pass it with `-r <file>`; the file carries the `Cookie`/`Content-Type` headers.

> [!note] It focuses on **web-layer operator injection** — auth bypass and `$regex` extraction. It does not cover aggregation-pipeline injection (`$lookup`/`$unionWith`), direct-DB attacks, or the CouchDB/Redis/ES surfaces — test those by hand or with [[Tools/Database/NoSQLMap|NoSQLMap]].

> [!tip] Run it through Burp with `-p http://127.0.0.1:8080` so you capture the exact injectable request it finds and can iterate on the payload manually — the scanner confirms the injection point; hand-crafting gets you the data.

> [!note] **See also** — [[Techniques/NoSQL Injection|NoSQL Injection]] — automated web-layer NoSQLi discovery; pairs with [[Tools/Database/mongosh|mongosh]] for direct DB testing once an instance is reachable.

---

*Created: 2026-07-31*
*Updated: 2026-09-29*
*Model: claude-opus-4-8*
