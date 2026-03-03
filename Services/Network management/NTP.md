#NTP #NetworkTimeProtocol #networkmanagement

## What is NTP?
Network Time Protocol — synchronizes clocks across networked systems. Critical for Kerberos (AD auth fails if clock skew > 5 minutes). NTPv4 is current. Runs as UDP.

- Port: **UDP 123**
- Config: `/etc/ntp.conf` (Linux), Windows Time Service (w32tm)
- Stratum: hierarchical system (stratum 0 = reference clock, stratum 1 = direct from ref, etc.)

---

## Enumeration

```bash
# Nmap — NTP info scripts
nmap -sU -p 123 --script ntp-info,ntp-monlist -sV <target>

# Manual query — server status
ntpq -c readvar <target>
ntpq -c sysinfo <target>
ntpq -p <target>

# ntpdc (older, sends mode 7 queries)
ntpdc -c monlist <target>
ntpdc -c listpeers <target>

# Metasploit
use auxiliary/scanner/ntp/ntp_monlist
```

---

## Key Commands

```bash
# Query NTP server info
ntpq -p <target>              # list peers
ntpq -c readvar <target>      # system variables (version, OS, etc.)
ntpq -c sysinfo <target>      # system info

# ntpdc (mode 7 — often disabled on patched systems)
ntpdc -c monlist <target>     # list recently seen clients (amplification source)
ntpdc -c version <target>     # version
ntpdc -c info <target>

# Sync local time from NTP server (Linux)
sudo ntpdate <target>
sudo ntpdate -u <target>

# w32tm (Windows — check time offset)
w32tm /query /status
w32tm /stripchart /computer:<target> /dataonly /samples:3

# Force time sync (Windows)
w32tm /resync /force
```

---

## Attack Vectors

### monlist — DDoS Amplification

```bash
# NTP monlist returns list of last 600 clients — amplification factor ~556x
# Used in reflection DDoS attacks (attacker spoofs victim IP as source)
ntpdc -c monlist <target>

# Metasploit
use auxiliary/scanner/ntp/ntp_monlist
set RHOSTS <target>
run
```

### Version / OS Fingerprinting

```bash
# ntpq readvar leaks OS, kernel, NTP version
ntpq -c readvar <target>

# Example output reveals:
# processor=x86_64, system=Linux, kernel=Linux 5.x, version=ntpd 4.x
```

### Kerberos Clock Skew Attack

```bash
# Kerberos rejects auth if clock skew > 5 minutes
# If you control NTP or can manipulate time:
# - Advance clocks to extend ticket validity
# - Skew clocks to invalidate other authentications

# On Kali — sync to AD DC (useful when testing from new network segment)
sudo ntpdate -u <dc_ip>
sudo timedatectl set-ntp false
sudo date -s "$(ntpdate -q <dc_ip> | tail -1 | awk '{print $4,$5}')"
```

### Bypass Kerberos via Time Sync

```bash
# When attacking AD — sync attacker clock to DC first
sudo ntpdate <dc_ip>
# or
sudo ntpdate -b <dc_ip>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `monlist` enabled | DDoS amplification |
| NTPv3 / old version | Mode 7 queries, information disclosure |
| No authentication (MD5 keys) | NTP spoofing / time manipulation |
| Open to internet with no rate limiting | Amplification source |
| Kerberos reliance without NTP monitoring | Clock skew auth failures |

---

## Quick Reference

| Goal | Command |
|---|---|
| Enumerate | `nmap -sU -p 123 --script ntp-info host` |
| Query peers | `ntpq -p host` |
| Version / OS info | `ntpq -c readvar host` |
| monlist (amplification check) | `ntpdc -c monlist host` |
| Sync clock to target | `sudo ntpdate host` |
| Win time check | `w32tm /query /status` |
