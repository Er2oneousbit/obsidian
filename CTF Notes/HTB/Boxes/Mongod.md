10.129.170.247
Versions
OS Ubuntu 9.3.0-17ubuntu1~20.04
SSH OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
MongoDB 3.6.8
OpenSSL 1.1.1f


nmap -sV --open -oA initial_scan 10.129.170.247
	22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
nmap -p- --open -oA full_tcp_scan 10.129.170.247
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
	22/tcp    open  ssh
	27017/tcp open  mongod
nmap -sC -p 22,27017 -oA script_scan  10.129.170.247

./mongo mongodb://10.129.170.247:27017
