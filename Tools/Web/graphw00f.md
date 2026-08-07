# graphw00f

**Tags:** #graphw00f #GraphQL #Fingerprinting #Recon #APIAttacks #WebAppAttacks

`graphw00f` fingerprints **which GraphQL engine** is behind an endpoint — Apollo, graphql-js, Hasura, Graphene, Ariadne, Sangria, and ~20 others — by sending malformed and edge-case queries and matching the error responses against known signatures. Knowing the engine tells you which introspection bypasses, batching behaviours, and engine-specific CVEs are worth trying, so it's the natural first step before deeper GraphQL testing.

**Source:** https://github.com/dolevf/graphw00f
**Install:** `git clone https://github.com/dolevf/graphw00f && cd graphw00f && pip3 install -r requirements.txt`

```bash
# Detect the endpoint, then fingerprint it
python3 main.py -f -d -t http://<TARGET>
# -f = fingerprint, -d = detect (find the GraphQL path first)

# Fingerprint a known endpoint directly
python3 main.py -f -t http://<TARGET>/graphql

# Authenticated
python3 main.py -f -t http://<TARGET>/graphql -H "Authorization: Bearer <token>"

# List every engine it can identify
python3 main.py -l
```

| Flag | Description |
|---|---|
| `-t` | Target URL |
| `-d` | Detect mode — probe common GraphQL paths |
| `-f` | Fingerprint the engine |
| `-H` | Add a header (auth) |
| `-l` | List detectable engines |
| `-o` | Write results to a file |

> [!tip] The engine determines what's worth trying next: Apollo historically leaks schema hints through "Did you mean" suggestions even with introspection off (useful for [[Tools/Web/clairvoyance|clairvoyance]]), while Hasura exposes admin endpoints and Graphene tends to permit query batching.

> [!note] Fingerprinting relies on error-message *shapes*. A target with generic/blanket error handling will come back unidentified — that's not an indication the endpoint is safe, just that it's quiet.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — GraphQL fuzzing workflow; [[Class notes/HTB Academy/CPTS v2 (claude)/GraphQL|GraphQL]] — the full attack surface; [[Class notes/HTB Academy/CWES Claude/Intro to GraphQL|Intro to GraphQL]] (CWES) — fingerprinting in the intro workflow.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
