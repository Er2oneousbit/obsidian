#wfuzz #webenumeration 

- `sudo wfuzz -c -f sub-fighter.txt -Z -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --sc 200,202,204,301,302,307,403 <targetURL>`
- `wfuzz -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-20000.txt -u http://permx.htb/ -H 'Host:FUZZ.permx.htb'`
- `wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --sc 200,301,302 -u http://172.16.1.10/FUZZ` 