# beanshooter

**Tags:** `#beanshooter` `#jmx` `#rmi` `#rce` `#java` `#deserialization`

JMX enumeration and attacking tool (qtc-de) — the modern one-stop for exploiting exposed Java Management Extensions services. Basic operations: `enum` (find common vulnerabilities), `brute` (JMX credential brute force), `list`/`info` (enumerate MBeans and their methods), `invoke` (call arbitrary MBean methods), `deploy`/`undeploy` (push your own MBean), `serial` (deserialization attacks), and `stager`. Ships the **tonka-bean** for a full command shell, MLet `load` operations for remote class loading, and dedicated support for the `DiagnosticCommandMBean`, Apache Tomcat's `MemoryUserDatabaseMBean`, and **Jolokia** (HTTP-exposed JMX).

**Source:** https://github.com/qtc-de/beanshooter
**Install:** Download the release jar (`beanshooter.jar`) or build with Maven; run `java -jar beanshooter.jar` (a `beanshooter` wrapper is common).

```bash
# Enumerate vulnerabilities / accessible MBeans
beanshooter enum <target> 1099

# Deploy tonka-bean → command exec / interactive shell
beanshooter tonka <target> 1099 exec "id"
beanshooter tonka <target> 1099 shell

# Brute-force credentials when auth is enabled
beanshooter brute <target> 1099 --username-file users.txt --password-file pass.txt
```

Companion RMI tool from the same author: [[Tools/Web/remote-method-guesser|remote-method-guesser]].

---

> [!note] **See also** — [[Services/Web Services/JMX|JMX]] — primary enumeration + RCE path against exposed JMX (MLet/tonka-bean, deserialization, Jolokia, app-specific MBeans).

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
