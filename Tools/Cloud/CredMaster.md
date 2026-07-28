# CredMaster

**Tags:** `#credmaster` `#passwordspray` `#cloud` `#fireprox` `#ipsrotation` `#python`

Python password-spraying framework (knavesec fork of SpiderLabs' original) that routes attempts through AWS API Gateway (via Fireprox) to rotate the source IP on every request, defeating per-IP throttling/blocking. Plugin-based — includes an `o365` plugin for spraying Entra ID/M365 alongside plugins for other services.

**Source:** https://github.com/knavesec/CredMaster
**Install:** requires AWS credentials configured for Fireprox; see repo README for setup.

```bash
python3 credmaster.py --userfile users.txt --passwordfile passwords.txt \
  --plugin o365 --threads 1 --delay 30
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Password Spraying section.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
