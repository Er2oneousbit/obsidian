# SIPVicious

**Tags:** #SIPVicious #SIP #VoIP #enumeration #bruteforce

SIPVicious is the primary open-source SIP/VoIP auditing toolkit — a suite of Python tools for finding and testing SIP devices (PBXs, phones, gateways). It is the go-to for the recon→enumeration→brute-force chain against UDP/TCP 5060: `svmap` scans a host or range for SIP endpoints and fingerprints the PBX, `svwar` enumerates valid extensions (valid vs invalid extensions return different SIP status codes), and `svcrack` brute-forces the SIP digest password for a known extension. `svreport`/`svlearndb` manage the results database. (EnableSecurity also ships a closed-source **SIPVicious PRO** rewrite; the classic OSS `sv*` tools are what's referenced here.)

**Source:** https://github.com/EnableSecurity/sipvicious
**Install:** `pipx install sipvicious` or `sudo apt install sipvicious`

```bash
svmap <target>                      # scan for SIP devices
svmap <subnet>/24 --fp              # sweep + fingerprint PBX vendor/version
svwar -e100-999 -m OPTIONS <target> # enumerate extensions 100-999 (OPTIONS = stealthier)
svcrack -u 200 -d rockyou.txt <target>   # brute-force ext 200's SIP password
```

> [!note] **See also** — [[Services/Network management/SIP-VoIP|SIP-VoIP]] (the service note: enumeration, credential brute force, eavesdropping, toll fraud).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
