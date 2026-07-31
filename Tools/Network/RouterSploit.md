# RouterSploit

**Tags:** #RouterSploit #NetworkDevices #EmbeddedDevices #Exploitation #IoT #Framework #Python

`RouterSploit` is an exploitation framework for embedded devices — routers, switches, IP cameras, and other network gear — modelled closely on Metasploit's `use`/`set`/`run` workflow. Where Metasploit is broad, RouterSploit is focused: its module set targets the default credentials, config-disclosure bugs, and command-injection CVEs common to consumer and enterprise network hardware, and its `autopwn` scanner throws every applicable exploit at a target to find what sticks.

**Source:** https://github.com/threat9/routersploit
**Install:** `git clone https://github.com/threat9/routersploit && cd routersploit && python3 -m pip install -r requirements.txt` (the git version is more current than any PyPI package)

```bash
python3 rsf.py
```

```text
# Autopwn — fire all known exploits at a target
rsf > use scanners/autopwn
rsf (AutoPwn) > set target 10.0.0.1
rsf (AutoPwn) > run

# Vendor-specific scanners
rsf > use scanners/routers/cisco_scanner
rsf > use scanners/routers/juniper_scanner
rsf > use scanners/routers/fortinet_scanner

# Default-credential checks
rsf > use creds/routers/cisco_enable_telnet_default
rsf > use creds/ssh/ssh_default
rsf (SSH Default) > set target 10.0.0.1
rsf (SSH Default) > run

# A specific CVE
rsf > use exploits/routers/cisco/<module>
rsf > show options
```

| Module class | Purpose |
|---|---|
| `scanners/` | Identify which exploits/creds a target is susceptible to |
| `exploits/` | Vendor/CVE-specific exploitation |
| `creds/` | Default and brute-force credential checks |
| `payloads/` | Generate reverse/bind shells for the device architecture |
| `generic/` | Protocol-level bugs (e.g. Shellshock, misfortune cookie) |

> [!warning] `autopwn` is loud — it sends every applicable exploit, some of which crash or reboot fragile embedded devices. On a live network that can knock a router or camera offline. Prefer a targeted `scanners/<vendor>_scanner` first, and only autopwn devices you can afford to reset.

> [!note] The bundled module set lags current CVEs — it's strong on older consumer-router bugs, thin on the latest enterprise-firewall RCEs. For those (FortiOS, PAN-OS, IOS XE) reach for the dedicated PoCs or [[Tools/Payloads & Shells/metasploit|Metasploit]] modules instead.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Network Device Pentesting|Network Device Pentesting]] — embedded/router exploitation and default-credential testing.

---

*Created: 2026-07-31*
*Updated: 2026-07-31*
*Model: claude-opus-5*
