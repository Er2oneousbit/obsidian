# clairvoyance

**Tags:** #clairvoyance #GraphQL #Introspection #Recon #APIAttacks #WebAppAttacks

`clairvoyance` reconstructs a GraphQL schema **when introspection is disabled**. Many engines still emit "Did you mean ...?" suggestions on a misspelled field, which leaks valid field names one error at a time; clairvoyance automates that oracle with a wordlist and rebuilds a usable schema JSON. Disabling introspection is the single most common GraphQL "hardening" step, and this is what makes it insufficient.

**Source:** https://github.com/nikitastupin/clairvoyance
**Install:** `pipx install clairvoyance` or `pip3 install clairvoyance`

```bash
# Reconstruct the schema with a wordlist
clairvoyance http://<TARGET>/graphql -o schema.json \
  -w /usr/share/seclists/Discovery/Web-Content/graphql.txt

# Authenticated
clairvoyance http://<TARGET>/graphql -o schema.json -w wordlist.txt \
  -H "Authorization: Bearer <token>"

# Slow it down — this sends one request per candidate field
clairvoyance http://<TARGET>/graphql -o schema.json -w wordlist.txt -c 2

# Then query the recovered schema like any other
python3 -c "import json;d=json.load(open('schema.json'));print(json.dumps(d,indent=2))" | head -50
```

| Flag | Description |
|---|---|
| `-o` | Output schema JSON |
| `-w` | Wordlist of candidate field names |
| `-H` | Add a header (auth) |
| `-c` | Concurrent requests |
| `-d` | Document/log level |

> [!warning] This is a brute-force oracle — it generates one request per candidate field name, so a large wordlist means thousands of requests. Rate-limit it (`-c 2`) on anything production, and expect it in the target's logs.

> [!tip] Feed the recovered `schema.json` into [[Tools/Web/Burpsuite|Burp Suite]]'s InQL extension to browse it and generate queries, rather than reading the raw JSON. Fingerprint the engine with [[Tools/Web/graphw00f|graphw00f]] first — engines that suppress suggestions won't yield to this at all.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — GraphQL schema recovery; [[Class notes/HTB Academy/CPTS v2 (claude)/GraphQL|GraphQL]] — exploiting what the schema reveals.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
