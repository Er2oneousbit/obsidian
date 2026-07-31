# Kafka client tools (kcat / kafka-*.sh)

**Tags:** `#kafka` `#kcat` `#kafkacat` `#messaging` `#streaming` `#dataengineering` `#client`

CLI clients for talking to an Apache Kafka cluster — list/describe topics, consume and produce messages, inspect broker and consumer-group metadata. Two families:

- **`kcat`** (formerly `kafkacat`) — a single lightweight binary, the go-to for quick enumeration and consuming/producing from an attack box. `apt install kafkacat`.
- **`kafka-*.sh`** — the scripts shipped in the Kafka distribution (`kafka-topics.sh`, `kafka-console-consumer.sh`, `kafka-console-producer.sh`, `kafka-configs.sh`, `zookeeper-shell.sh`). Heavier (JVM) but support SASL/SSL `--command-config` and admin operations.

**Source:** https://github.com/edenhill/kcat (kcat) / https://kafka.apache.org/downloads (distribution)
**Install:** `apt install kafkacat` (kcat); download the Kafka tgz for the `.sh` tools

```bash
# kcat — list metadata (brokers + topics), then consume a topic from the beginning
kcat -L -b <target>:9092
kcat -b <target>:9092 -t <topic> -C -o beginning -e

# kafka-*.sh equivalents
kafka-topics.sh --bootstrap-server <target>:9092 --list
kafka-console-consumer.sh --bootstrap-server <target>:9092 --topic <topic> --from-beginning

# Authenticated (SASL) — supply a client-config file
kafka-topics.sh --bootstrap-server <target>:9094 --command-config client.properties --list
```

> [!note] **See also** — [[Services/Cloud & Data/Kafka|Apache Kafka]] for the full attack methodology (topic data harvesting, Connect RCE, ZooKeeper/KRaft control plane, SASL brute force).

---

*Created: 2026-07-29*
*Updated: 2026-07-29*
*Model: claude-opus-4-8*
