# ike-scan

**Tags:** #ike-scan #IPsec #IKE #VPN #enumeration

`ike-scan` discovers and fingerprints IKE (IPsec VPN) endpoints on UDP 500/4500. On an engagement its highest-value use is against IKEv1 **Aggressive Mode**: supplying a group/identity (`--id`, the tunnel-group / PSK identifier) makes the gateway return a hash that can be captured with `--pskcrack` and cracked offline (`psk-crack`), so a guessable group name + weak PSK = full VPN keys. It also enumerates valid group names by brute-forcing `--id`, negotiates custom transform sets (`--trans`), and probes IKEv2 (`--ikev2`).

**Source:** https://github.com/royhills/ike-scan
**Install:** `sudo apt install ike-scan`

```bash
ike-scan <target>                               # main-mode probe (is IKE up?)
ike-scan --aggressive --id=<group> <target>     # aggressive mode against a group name
ike-scan -A --id=<group> --pskcrack=hash.txt <target>   # capture the crackable PSK hash
psk-crack -d /usr/share/wordlists/rockyou.txt hash.txt   # crack it offline
ike-scan --ikev2 <target>                        # IKEv2 support check
```

> [!note] **See also** — [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect / ASA]] (IKEv1/v2 enumeration + aggressive-mode group/PSK attack against ASA IPsec VPN).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
