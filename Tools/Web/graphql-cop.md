# graphql-cop

**Tags:** #graphqlcop #GraphQL #APIAttacks #Audit #Recon #WebAppAttacks #Python

`graphql-cop` is a fast security audit for a single GraphQL endpoint. It runs a fixed battery of checks — introspection enabled, field suggestions on, alias and array batching permitted, GET/form-encoded methods accepted (CSRF), missing depth and complexity guards, verbose errors — and prints a pass/fail line per check. Run it immediately after confirming an endpoint: it takes seconds and tells you which of the deeper techniques are even available.

**Source:** https://github.com/dolevf/graphql-cop
**Install:** `pipx install graphql-cop` or `pip3 install graphql-cop`

```bash
# Standard audit
graphql-cop -t http://<TARGET>/graphql

# Authenticated
graphql-cop -t http://<TARGET>/graphql -H "Authorization: Bearer <token>"

# JSON output for reporting, through Burp for inspection
graphql-cop -t http://<TARGET>/graphql -o json --proxy http://127.0.0.1:8080
```

| Flag | Description |
|---|---|
| `-t` | Target endpoint |
| `-H` | Add a header (auth) |
| `-o` | Output format (`json`) |
| `--proxy` | Route requests through a proxy |
| `-f` | Force run even if the endpoint doesn't look like GraphQL |

**What each finding unlocks:**

| Finding | Why it matters next |
|---|---|
| Introspection enabled | Full schema dump — skip [[Tools/Web/clairvoyance\|clairvoyance]] entirely |
| Field suggestions enabled | Schema recoverable even with introspection off — clairvoyance will work |
| Alias / array batching | Rate-limit and brute-force protection bypass |
| GET or form-encoded accepted | CSRF against mutations |
| No depth / complexity limit | DoS primitive — report the missing guard rather than exploiting it |

> [!note] It reports *capabilities and missing hardening*, not exploited vulnerabilities. A finding here is the start of a test, not a finished one — you still have to show impact.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/GraphQL|GraphQL]] — first-pass endpoint audit; pairs with [[Tools/Web/graphw00f|graphw00f]] for engine fingerprinting.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
