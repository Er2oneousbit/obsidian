# Seth

**Tags:** #Seth #RDP #MITM #credentialtheft #remoteaccess

Seth is an RDP man-in-the-middle tool that downgrades and intercepts Remote Desktop connections to capture credentials in cleartext. It ARP-spoofs between a client and the RDP server, then forces the connection down from NLA/CredSSP to standard RDP security (a warning the victim usually clicks through), so the password typed at the RDP login is recovered in plaintext. Effective wherever RDP uses a self-signed cert and NLA can be downgraded — i.e. most internal deployments without enforced NLA + cert pinning.

**Source:** https://github.com/SySS-Research/Seth
**Install:** `git clone https://github.com/SySS-Research/Seth` (Python; needs `tcpdump`, `arpspoof`)

```bash
# seth.sh <interface> <attacker-ip> <victim-client-ip> <rdp-server-ip> [<gateway>]
./seth.sh eth0 <attacker_ip> <client_ip> <target_ip>
# victim connects → Seth downgrades NLA → password captured in cleartext
```

> [!note] **See also** — [[Services/Remote Access/RDP|RDP]] (MITM on self-signed certs / NLA downgrade → credential capture). Defence is enforced NLA + cert pinning; see RDP's Dangerous Settings.

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
