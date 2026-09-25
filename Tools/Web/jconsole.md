# jconsole

**Tags:** `#jconsole` `#jmx` `#mbean` `#java` `#jdk`

The JDK's graphical JMX client. Attaches to a local or remote JMX agent and lets you browse the MBean tree interactively — read/write attributes and invoke operations. In offensive use it's the quickest way to eyeball an unauthenticated JMX service for dangerous MBeans (class loading, diagnostic commands, app-specific exec) before scripting the attack with a CLI tool.

**Source:** Bundled with any JDK (`jconsole` on PATH).
**Install:** `apt install default-jdk` (Kali) if missing.

```bash
# Connect to a remote JMX agent
jconsole <target>:1099
jconsole service:jmx:rmi:///jndi/rmi://<target>:1099/jmxrmi
```

Scriptable/headless equivalents: [[Tools/Web/jmxterm|jmxterm]], [[Tools/Web/beanshooter|beanshooter]].

---

> [!note] **See also** — [[Services/Web Services/JMX|JMX]] — interactive MBean browsing to spot invokable dangerous operations on an exposed agent.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
