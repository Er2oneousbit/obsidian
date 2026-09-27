# NTP

#NTP #NetworkTimeProtocol #networkmanagement

## What is NTP?
Network Time Protocol — synchronizes clocks across networked systems over **UDP 123**. It matters on an engagement for three reasons: it is a soft **recon** source (`readvar` leaks OS/version, `monlist` leaks recent clients), it is a classic **DDoS amplification** reflector, and — most usefully — **Kerberos rejects authentication when clock skew exceeds 5 minutes**, so you routinely have to sync *your* clock to the target DC before any AD attack works, and a rogue NTP server can **time-shift** a victim to bypass certificate/HSTS/DNSSEC validity windows.

- Port **UDP 123**
- Config: `/etc/ntp.conf` / `/etc/ntpsec/ntp.conf` (Linux), Windows Time Service (`w32tm`); modern Linux often runs `chrony`/`systemd-timesyncd` instead of `ntpd`
- Stratum hierarchy: stratum 0 = reference clock, 1 = direct from ref, etc.
- Protocol modes: `ntpq` = **mode 6** (control), `ntpdc` = **mode 7** (legacy, disabled by default since ntpd 4.2.7p26)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Scanning/NMAP\|NMAP]] | `ntp-info`, `ntp-monlist` NSE on UDP 123 |
| [[Tools/Network/ntpq\|ntpq]] | Primary query client — peers, `readvar` OS/version leak (`ntpdc` = mode-7 monlist) |
| [[Tools/Payloads & Shells/metasploit\|metasploit]] | `auxiliary/scanner/ntp/ntp_monlist` amplification check |

Also used inline: `ntpdate`/`sntp` (one-shot clock sync — `ntpdate` is deprecated on modern systems), `w32tm` (Windows time service), `faketime` (run a single process with a spoofed clock when you can't change system time), `Delorean` (rogue NTP server for time-shifting MITM).

---

## Enumeration

```bash
# Nmap — NTP info + monlist amplification check
nmap -sU -p 123 --script ntp-info,ntp-monlist -sV <target>

# Peers + system variables (OS / kernel / ntpd version leak)
ntpq -p <target>
ntpq -c readvar <target>
ntpq -c sysinfo <target>

# ntpdc — mode 7 (often disabled on patched systems)
ntpdc -c monlist <target>     # last ~600 clients — amplification source + recon
ntpdc -c listpeers <target>
ntpdc -c version <target>

# Metasploit
use auxiliary/scanner/ntp/ntp_monlist
set RHOSTS <target>
run
```

---

## Attack Vectors

### monlist — DDoS Amplification (CVE-2013-5211)

```bash
# monlist returns up to ~600 recent clients in one small request → ~556x amplification.
# In a reflection DDoS the attacker spoofs the victim's IP as source; a responding
# server here is a finding even if you never weaponise it.
ntpdc -c monlist <target>
```

### Version / OS Fingerprinting

```bash
# ntpq readvar leaks processor/system/kernel/version
ntpq -c readvar <target>
# e.g. processor="x86_64", system="Linux", version="ntpd 4.2.8p15"
```

### Sync Your Clock for Kerberos (the practical one)

Kerberos returns `KRB_AP_ERR_SKEW` when your clock differs from the DC by > 5 minutes — the single most common reason AD tooling "mysteriously" fails from a fresh foothold. Fix it before roasting/relaying:

```bash
# Disable the local time daemon, then hard-set from the DC
sudo timedatectl set-ntp false
sudo ntpdate <dc_ip>            # or: sudo rdate -n <dc_ip> ; sudo sntp -sS <dc_ip>

# If you can't change system time (shared box, no root), fake it per-process instead:
faketime "$(ntpdate -q <dc_ip> | awk 'END{print $4, $5}')" impacket-GetUserSPNs ...
```

### NTP-MITM Time-Shifting (Delorean)

```bash
# A rogue NTP server that answers with an attacker-chosen time can push a victim's clock
# forward/back to bypass time-based checks:
#   - expire/pre-date TLS certs, defeat HSTS max-age, roll past DNSSEC signature windows
#   - invalidate Kerberos tickets or force re-auth
# Requires you to be the client's NTP source (rogue DHCP/NTP, on-path, or LAN spoofing).
python3 delorean.py -i <interface>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `monlist` / mode-7 enabled (old ntpd) | DDoS amplification + client recon |
| NTPv3 / unpatched ntpd | Mode 7 queries, information disclosure |
| No authentication (symmetric/`autokey` keys) | NTP spoofing → time-shift MITM |
| Open to internet with no rate limiting | Amplification reflector |
| Clients trust an untrusted/DHCP-provided NTP source | Time-shift → cert/HSTS/Kerberos bypass |
| Kerberos reliance without NTP monitoring | Skew-induced auth failures / manipulation |

---

## Quick Reference

| Goal | Command |
|---|---|
| Enumerate | `nmap -sU -p 123 --script ntp-info,ntp-monlist host` |
| Query peers | `ntpq -p host` |
| Version / OS info | `ntpq -c readvar host` |
| monlist (amplification check) | `ntpdc -c monlist host` |
| Sync clock to DC (Kerberos) | `sudo ntpdate <dc_ip>` |
| Fake clock per-process | `faketime "<time>" <command>` |
| Win time check | `w32tm /query /status` |

---

> [!note] **See also** — the clock-skew fix here unblocks [[Services/Active Directory/Kerberos|Kerberos]] attacks; time-shift MITM overlaps the rogue-name-resolution surface of [[Services/Network Management/NetBIOS|NetBIOS]]/[[Services/Network Management/DNS|DNS]] (both need an on-path/spoofing position).

---

*Created: 2026-07-13*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
