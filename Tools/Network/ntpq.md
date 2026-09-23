# ntpq

**Tags:** #ntpq #NTP #enumeration #network

`ntpq` is the standard NTP query client (mode 6 control messages) shipped with the reference `ntp`/`ntpsec` implementation. On an engagement it is the primary NTP recon tool: `ntpq -p` lists a server's upstream peers (leaking internal time-source topology) and `ntpq -c readvar` dumps system variables that frequently leak the OS, kernel and `ntpd` version for fingerprinting. Its older sibling `ntpdc` speaks the mode-7 protocol and carries the `monlist` command abused for DDoS amplification (CVE-2013-5211) — mode 7 is disabled by default since `ntpd` 4.2.7p26, so `monlist` succeeding is itself a "legacy/unpatched" finding.

**Source:** https://www.ntp.org / https://www.ntpsec.org
**Install:** `sudo apt install ntpsec-ntpq` (Debian/Kali; the classic package is `ntp`)

```bash
ntpq -p <target>            # list peers (upstream time sources)
ntpq -c readvar <target>    # system vars — OS/kernel/version leak
ntpq -c sysinfo <target>    # system info summary
ntpdc -c monlist <target>   # last-seen clients (amplification / recon); mode 7, often disabled
```

> [!note] **See also** — [[Services/Network management/NTP|NTP]] (the service note: enumeration, monlist amplification, Kerberos clock-skew, NTP-MITM time-shifting).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
