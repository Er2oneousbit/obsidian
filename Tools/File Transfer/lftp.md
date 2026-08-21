# lftp

**Tags:** `#lftp` `#ftp` `#ftps` `#sftp` `#filetransfer` `#mirror` `#exfil`

Sophisticated command-line file-transfer client speaking **FTP, FTPS, SFTP, HTTP(S), and FISH**. On an engagement it's the client you reach for when the basic `ftp` binary falls short: it does **TLS/FTPS** (with a one-liner to ignore self-signed certs), **recursive `mirror`** to pull or push an entire directory tree in a single command, segmented parallel downloads, and full non-interactive scripting. Think of it as `wget`/`rsync` ergonomics for FTP-family protocols.

**Source:** https://lftp.yar.ru/
**Install:** `sudo apt install lftp` (pre-installed on many pentest distros)

```bash
# Anonymous, then drop into the interactive prompt
lftp ftp://<target>

# Authenticated, one-shot command, then exit
lftp -u user,pass ftp://<target> -e "ls; bye"
```

> [!note] **`mirror` is the reason to use lftp.** One command exfiltrates an entire remote share (`mirror`) or uploads a whole local tree (`mirror -R`) — recursively, resumable, in parallel. See the mirror section below; mind the reversed argument order.

---

## Connecting

```bash
# Protocol is chosen by the URL scheme
lftp ftp://<target>              # plain FTP (port 21)
lftp ftps://<target>             # IMPLICIT FTPS (port 990)
lftp sftp://user@<target>        # SFTP over SSH (port 22)
lftp http://<target>             # HTTP(S) — download/browse

# Credentials: -u user,pass  (comma, no space) — or omit pass to be prompted
lftp -u user,pass ftp://<target>
lftp -u user ftp://<target>      # prompts for password (keeps it off the CLI/history)

# Non-standard port
lftp -u user,pass ftp://<target>:2121

# Anonymous
lftp ftp://<target>              # logs in as anonymous automatically
```

**Non-interactive execution** — three ways to script it:

```bash
lftp -e "ls; get flag.txt; bye" -u user,pass ftp://<target>   # -e: run then stay unless 'bye'
lftp -c "open -u user,pass ftp://<target>; mirror /srv ./loot" # -c: run this one command line and exit
lftp -f script.lftp                                            # -f: run a file of lftp commands
```

---

## TLS / FTPS — the feature the basic `ftp` client lacks

FTPS comes in two flavours and lftp handles them differently — getting this wrong is the usual reason "FTPS won't connect":

```bash
# EXPLICIT FTPS (AUTH TLS on the normal port 21) — most common. Use ftp:// and FORCE tls:
lftp -u user,pass ftp://<target> -e "set ftp:ssl-force true; set ftp:ssl-protect-data true; ls"

# IMPLICIT FTPS (TLS from byte one, dedicated port 990) — use the ftps:// scheme:
lftp -u user,pass ftps://<target>
```

```bash
# Self-signed / untrusted cert (the everyday CTF/pentest case) — don't verify:
lftp -e "set ssl:verify-certificate no" -u user,pass ftps://<target>
```

> [!warning] **`ssl-force` vs the scheme.** `ftps://` = *implicit* (990). Plain `ftp://` stays cleartext **unless** you `set ftp:ssl-force true`, which upgrades it to *explicit* AUTH TLS on 21. `ftp:ssl-protect-data true` also encrypts the **data** channel (some servers encrypt only the control channel by default, leaking your transfers). If a server advertises broken TLS and you just need the files, force cleartext with `set ftp:ssl-allow no`.

---

## Navigation & Transfer

```bash
# Inside the lftp prompt (or after -e "...")
ls / cls                 # list (cls = colorized/columnar)
cd /remote/dir           # remote dir;  lcd /local/dir = local dir
pwd                      # remote cwd
get file.txt             # download one file
get file.txt -o out.txt  # download, rename
mget *.conf              # download by glob
pget -n 5 big.iso        # segmented download — 5 parallel connections (much faster)
put shell.php            # upload one file
mput *.php               # upload by glob
cat /etc/passwd          # print a remote file to stdout (no local copy)
du -sh /share            # recursive size
find /                   # recursive remote listing (great for mapping a share)
!ls -la                  # run a command on YOUR local box (! = local shell)
```

> [!warning] **`get` only fetches files — a *directory* needs `mirror`.** Read the `ls` output: a leading **`d`** (`drwxr-xr-x`) marks a directory, a leading **`-`** marks a file. `get somedir` fails because `get` has no idea what to do with a directory — use `mirror somedir ./local` instead. And read names exactly: `apache2_conf` (a directory) is **not** `apache2.conf` (a file) — one wrong character is a failed `get`, not a missing file.

> [!warning] **`550 Failed to open file` is ambiguous — don't read it as a block.** FTP's `550` collapses **doesn't-exist**, **is-a-directory**, and **permission-denied** into one response code. A `get` that returns `550` almost always means a wrong filename or a directory, *not* that a security control stopped you. Before concluding access is denied, check which of the three it is: re-`ls` the path, confirm the leading `d`/`-`, and try `mirror`.

> [!tip] **Map before you pull: `find` first, then `mirror`.** `find /` prints the whole remote tree in one shot, so you know what's there before downloading. When you just want it all — or aren't sure what's a file vs a directory — `mirror /` recreates the entire tree locally and sidesteps every `get`-vs-directory mistake at once. That's the right move nine times out of ten:
> ```bash
> lftp -u user,pass ftp://<target> -e "mirror --verbose --parallel=4 / ./loot; bye"
> ```

---

## `mirror` — recursive download / upload

The standout. Default direction is **download** (remote → local); `-R` reverses it to **upload** (local → remote).

```bash
# DOWNLOAD an entire remote tree (exfil a whole share)
mirror /var/www ./www_loot
mirror --parallel=5 /srv ./loot        # 5 files at once
mirror -c /srv ./loot                  # -c = continue/resume an interrupted mirror
mirror --only-newer /srv ./loot        # skip files already current locally
mirror -X '*.iso' -X 'cache/*' /srv .  # -X exclude glob; -I to include-only

# UPLOAD an entire local tree (-R) — e.g. push a webshell directory to an FTP-root=webroot
mirror -R ./webshells /var/www/html
```

> [!warning] **Two mirror footguns.** (1) The argument order is `mirror <source> <target>`, and `-R` flips which side is which — it's easy to upload when you meant download. (2) `--delete` makes the target an exact copy by **deleting files at the destination that aren't in the source** — on an upload-mirror of the wrong directory that can wipe a live web root. Never add `--delete` until you've run the mirror once without it.

---

## Scripting & Automation

```bash
# A reusable script file (run with: lftp -f exfil.lftp)
cat > exfil.lftp <<'EOF'
set ssl:verify-certificate no
open -u user,pass ftps://target.htb
mirror --parallel=4 /home ./home_loot
bye
EOF

# Persist settings for every session
echo 'set ssl:verify-certificate no' >> ~/.lftprc
echo 'set ftp:passive-mode on'       >> ~/.lftprc

# Bookmark a target inside the prompt
bookmark add box            # saves the current open connection as "box"
open box                    # reconnect later by name
```

---

## Settings worth knowing

```bash
set ftp:passive-mode on         # passive (default) — firewall/NAT-friendly; 'off' for active
set net:timeout 10              # fail faster on a dead host
set net:max-retries 2           # stop retrying forever
set ssl:verify-certificate no   # ignore self-signed / hostname-mismatch certs
set ftp:ssl-force true          # explicit FTPS (AUTH TLS) on a plain ftp:// connection
set ftp:ssl-protect-data true   # encrypt the DATA channel too, not just control
set sftp:connect-program "ssh -a -x -oStrictHostKeyChecking=no"  # SFTP to an unknown host key
set xfer:clobber on             # allow overwriting local files on download
set cmd:parallel 3              # global parallelism for queued transfers
```

---

## Pentest use cases

- **Exfiltrate a whole share in one line** — `lftp -e "mirror /data ./loot; bye" -u user,pass ftp://target` beats clicking through `get` after `get`, and resumes with `-c` if the link drops.
- **Push a webshell tree** where FTP root = web root — `mirror -R ./php_shells /var/www/html`, then browse to it. (See [[Services/File Xfer/FTP|FTP]] → *Upload Web Shell*.)
- **FTPS the stock client can't touch** — a server enforcing AUTH TLS with a self-signed cert rejects the basic `ftp` binary; `lftp` with `set ftp:ssl-force true; set ssl:verify-certificate no` gets in.
- **Recursive over SFTP** — `mirror sftp://user@host:/etc ./etc_copy` grabs a config tree over SSH when you have creds but no shell.

---

> [!note] **See also** — [[Services/File Xfer/FTP|FTP]] and [[Services/File Xfer/SFTP|SFTP]]: lftp is the go-to client for FTPS and for mirroring an anonymous/authenticated tree in one shot. For simple one-file anonymous pulls, [[Tools/File Transfer/wget|wget]] (`wget -m ftp://…`) also works.

---

*Created: 2026-08-21*
*Updated: 2026-08-21*
*Model: claude-opus-5*
