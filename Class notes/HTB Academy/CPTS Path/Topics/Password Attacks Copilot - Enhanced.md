## 🔍 Windows Credential Hunting

### 🔎 Searching for Plaintext Credentials

```cmd
findstr /SIM /C:"password" *.txt *.ini *.cfg *.config *.xml *.git *.ps1 *.yml
```

### 🗂️ Common Storage Locations

* Group Policy (SYSVOL)
* IT/dev shares
* `unattend.xml` files
* AD user/computer description fields
* KeePass databases
* Files like:

  * `pass.txt`
  * `passwords.docx`
  * `passwords.xlsx`
* SharePoint or public user shares

### 🔧 Helpful Tools

* `findstr` (Windows CLI search)
* **PowerShell** scripting
* **LaZagne** (post-exploitation)

---

## 🐧 Linux Credential Harvesting

### 📁 File-Based Secrets

| **Type**        | **Examples**                                |
| --------------- | ------------------------------------------- |
| Configs         | `.conf`, `.config`, `.cnf`                  |
| Databases       | `.sql`, `.db`, `*.sqlite`, `.db*`           |
| Notes & Scripts | `.txt`, `.sh`, `.py`, `.pl`, `.ps1`, `.yml` |
| SSH Keys        | `id_rsa`, `authorized_keys`, `known_hosts`  |

### 🔍 File & Key Discovery

```bash
# Find config files
find / -name *.conf 2>/dev/null | grep -v "lib\|fonts"

# Search for usernames/passwords in .cnf files
for i in $(find / -name *.cnf 2>/dev/null | grep -v "doc\|lib"); do
  grep "user\|password\|pass" $i 2>/dev/null | grep -v "#"
done

# Search for private keys
grep -rnw "PRIVATE KEY" /home/* 2>/dev/null | grep ":1"
```

---

### ⏱️ Scheduled Tasks & Command History

```bash
cat /etc/crontab
ls -la /etc/cron.*
tail -n 5 /home/*/.bash*
```

---

### 📜 Log File Analysis

```bash
for i in $(ls /var/log/* 2>/dev/null); do
  GREP=$(grep -Ei "accepted|session opened|session closed|failure|failed|ssh|password changed|new user|delete user|sudo|COMMAND=|logs" $i 2>/dev/null)
  if [[ $GREP ]]; then
    echo -e "\n#### Log file: $i"
    echo "$GREP"
  fi
done
```

| **Log File**        | **Purpose**                         |
| ------------------- | ----------------------------------- |
| `/var/log/auth.log` | Authentication logs (Debian/Ubuntu) |
| `/var/log/secure`   | Authentication logs (RedHat/CentOS) |
| `/var/log/syslog`   | System activity                     |
| `/var/log/messages` | General messages                    |
| `/var/log/faillog`  | Failed logins                       |
| `/var/log/cron`     | Cron job logs                       |

---

### 🔐 Linux Password Hash Extraction

```bash
sudo cp /etc/passwd /tmp/passwd.bak
sudo cp /etc/shadow /tmp/shadow.bak
unshadow /tmp/passwd.bak /tmp/shadow.bak > /tmp/unshadowed.hashes

# Crack with hashcat
hashcat -m 1800 -a 0 /tmp/unshadowed.hashes rockyou.txt -o cracked.txt
```

### 🧠 Hash Type Prefixes

| Prefix | Hash Type   |
| ------ | ----------- |
| `$1$`  | MD5         |
| `$2a$` | Blowfish    |
| `$2y$` | Eksblowfish |
| `$5$`  | SHA-256     |
| `$6$`  | SHA-512     |

---

