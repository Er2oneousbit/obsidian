# graphqlmap

**Tags:** #graphqlmap #GraphQL #APIAttacks #Injection #SQLi #NoSQLi #WebAppAttacks #Python

`graphqlmap` is an interactive exploitation shell for GraphQL endpoints — think sqlmap's workflow applied to GraphQL. It dumps the schema via introspection, lets you fire queries and mutations from a prompt without hand-writing JSON envelopes, and automates injection testing (SQLi, NoSQLi) through query arguments.

**Source:** https://github.com/swisskyrepo/GraphQLmap
**Install:** `git clone https://github.com/swisskyrepo/GraphQLmap && cd GraphQLmap && pip3 install -r requirements.txt`

```bash
# Drop into the interactive shell against an endpoint
python3 graphqlmap.py -u http://<TARGET>/graphql --method POST

# Authenticated
python3 graphqlmap.py -u http://<TARGET>/graphql --method POST \
  -v '{"Authorization":"Bearer <token>"}'
```

```text
# Inside the shell
GraphQLmap > help
GraphQLmap > dump_via_introspection          # full schema
GraphQLmap > dump_via_fragment               # schema via fragments when introspection is partial
GraphQLmap > {user(id:"1"){id username email}}    # run a raw query
GraphQLmap > nosqli                          # NoSQL injection helpers
GraphQLmap > postgresql_blind                # blind SQLi automation
```

| Option | Description |
|---|---|
| `-u` | Target endpoint URL |
| `--method` | `POST` (default) or `GET` |
| `-v` | Extra headers as JSON — use for auth |
| `--proxy` | Route through Burp for inspection |

> [!note] Development has been quiet for a while, and it assumes a fairly conventional endpoint. When it can't parse a response, fall back to raw `curl` — the GraphQL wire format is simple enough that manual testing loses very little.

> [!tip] Fingerprint with [[Tools/Web/graphw00f|graphw00f]] and run [[Tools/Web/graphql-cop|graphql-cop]] first — they take seconds and tell you whether introspection, batching, and suggestions are available, which decides whether graphqlmap's dump commands will work at all.

> [!note] **See also** — [[Class notes/HTB Academy/CWES Claude/GraphQL Attacks|GraphQL]] — automated schema dumping and injection; [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — GraphQL fuzzing workflow.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
