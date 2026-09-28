# mimipenguin

**Tags:** `#mimipenguin` `#pillaging` `#memory` `#credentials` `#linux` `#postexploitation` `#auth`

The Linux answer to [[Tools/Auth/mimikatz|mimikatz]] `sekurlsa` — scrapes **cleartext
passwords out of process memory** on a compromised Linux host. It walks `/proc/<pid>/mem`
of a handful of known credential-holding processes and matches candidate strings against
the hash in `/etc/shadow` to confirm the password. Needs **root**.

**Source:** https://github.com/huntergregal/mimipenguin
**Install:** not on Kali by default — clone and run in place (no build needed):

```bash
git clone https://github.com/huntergregal/mimipenguin
sudo python3 mimipenguin.py      # Python version — more complete (full GDM/Keyring support)
sudo bash mimipenguin.sh         # shell version — fewer deps, but some targets are flaky
```

> [!warning] **Root required, and it's dated.** It reads other processes' memory, so root
> is mandatory. The supported matrix tops out around **Ubuntu 18.04 / older GNOME** — on
> current systemd/GNOME the cleartext often isn't held in memory the same way, so expect
> misses. It also leans on `gcore` (can hang) and the 32-bit build mishandles 64-bit
> address spaces. Treat a hit as a bonus, not a guarantee.

> [!note] **See also** — [[Tools/Auth/mimikatz|mimikatz]] (Windows counterpart);
> [[Tools/Auth/LaZagne|LaZagne]] (broader Linux/Windows app-credential harvester);
> [[Tools/Auth/Firefox Decrypt|Firefox Decrypt]] (browser creds). Fits the local-privesc /
> looting phase — see [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] (CPTS v2).

---

## What It Targets

| Source | Yields |
|---|---|
| **GNOME Keyring** | Logged-in desktop user's password (Ubuntu/Arch) — `CVE-2018-20781` |
| **GDM** | Display-manager login password (Kali/Debian) |
| **LightDM** | Display-manager login password (Ubuntu) |
| **VSFTPd** | Password of an **active** FTP connection |
| **Apache2** | Credentials from an active HTTP **Basic-Auth** session |
| **OpenSSH** | Password of an active SSH session that used `sudo` |

---

## Where It Fits

1. After landing a **root** shell on Linux, run it for a quick cleartext win — a desktop
   or service password you can reuse.
2. Recovered passwords feed credential reuse / spraying and lateral movement (users reuse
   the same password for SSH, sudo, and domain accounts).
3. If it comes up empty (likely on a modern box), fall back to reading `/etc/shadow`
   directly (you're already root) and cracking offline with
   [[Tools/Auth/hashcat|hashcat]] / [[Tools/Auth/john the ripper|john]], or loot
   config/history files and SSH keys manually.

---

*Created: 2026-07-13*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
