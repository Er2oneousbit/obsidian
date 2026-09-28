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

> [!tip] **Why CredMaster over MSOLSpray/Go365** — those bolt FireProx on optionally;
> CredMaster is **IP-rotation-first**: it auto-provisions AWS API Gateway endpoints and passes
> every request through them, so each attempt appears from a different source IP — the cleanest
> defeat for per-IP Smart Lockout / geo-blocking. It's also multi-target (msol, msgraph,
> azuresso, owa, ews, adfs, okta, …), not M365-only.

> [!warning] **Clean up your AWS.** FireProx leaves **API Gateway** resources in your AWS
> account after a run. Tear them down (via the FireProx CLI / AWS console) so you're not
> billed and don't leave attack infra lying around.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] Password Spraying section; simpler single-target siblings [[Tools/Cloud/MSOLSpray|MSOLSpray]] and [[Tools/Cloud/Go365|Go365]]; Python enum+spray [[Tools/Auth/o365spray|o365spray]].

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
