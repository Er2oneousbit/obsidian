# ssh-audit

**Tags:** #ssh-audit #SSH #enumeration #cryptography

`ssh-audit` is the go-to unauthenticated SSH configuration auditor. Point it at a host and it reports the banner/version, supported key-exchange / host-key / cipher / MAC algorithms, and — crucially — flags weak or deprecated ones and known protocol vulnerabilities (e.g. **Terrapin, CVE-2023-48795**) with the OpenSSH version they were fixed in. On an engagement it turns "port 22 is open" into a concrete, reportable list of weak algorithms and CVEs without needing credentials.

**Source:** https://github.com/jtesta/ssh-audit
**Install:** `pipx install ssh-audit` (or `sudo apt install ssh-audit`)

```bash
ssh-audit <target>                 # full audit (algorithms + vulns + policy)
ssh-audit -p 2222 <target>         # custom port
ssh-audit --level=warn <target>    # only warnings and worse
```

> [!note] **See also** — [[Services/Remote Access/SSH|SSH]] (the service note: enumeration, auth methods, key attacks, tunneling). Cross-references the same weak-algorithm findings that [[Tools/Scanning/NMAP|NMAP]]'s `ssh2-enum-algos` surfaces.
> Also [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2) — SSH enumeration step.

---

*Created: 2026-09-23*
*Updated: 2026-10-08*
*Model: claude-opus-4-8*
