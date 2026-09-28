# CredMaster

**Tags:** `#credmaster` `#passwordspray` `#cloud` `#fireprox` `#ipsrotation` `#python`

Python password-spraying framework (knavesec fork of SpiderLabs' original) that routes attempts through AWS API Gateway (via Fireprox) to rotate the source IP on every request, defeating per-IP throttling/blocking. Plugin-based — each plugin is a directory under `plugins/`.

**Source:** https://github.com/knavesec/CredMaster
**Install:** requires AWS API keys for Fireprox; see repo README for setup.

```bash
# Plugin is passed via --plugin and must be a real plugin name (dirs in plugins/):
#   M365/Entra spray -> msol (legacy sign-in) or msgraph (Graph token endpoint); azuresso;
#   enumeration -> o365enum. There is NO `o365` plugin (removed). Others: owa, ews, adfs, okta, ...
# Fireprox needs AWS keys; creds use -u / -p (not --userfile/--passwordfile).
python3 credmaster.py --plugin msol \
  --access_key <aws-key> --secret_access_key <aws-secret> \
  -u users.txt -p passwords.txt
# (add rate/thread/delay controls per `python3 credmaster.py --help`)
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Password Spraying section.

---

*Created: 2026-07-27*
*Updated: 2026-09-27*
*Model: claude-opus-4-8*
