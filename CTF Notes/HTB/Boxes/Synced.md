10.129.115.18

Versions
	rsync   (protocol version 31)




nmap -sV --open -oA initial_scan 10.129.115.18
	873/tcp open  rsync   (protocol version 31)
nmap -p- --open -oA full_tcp_scan 10.129.115.18
	873/tcp open  rsync
nmap -sC -p 873 -oA script_scan  10.129.115.18