# openconnect

**Tags:** #openconnect #VPN #SSLVPN #remoteaccess #client

`openconnect` is the open-source client that speaks Cisco AnyConnect's SSL VPN protocol (and GlobalProtect, Pulse, Fortinet, Juniper). On an engagement it is how you **actually connect** once you hold harvested credentials or a client certificate — it runs headless on Linux, takes the tunnel-group as `--authgroup`, and drops you onto the internal network the ASA pushes routes for. Far more scriptable than the official client and available where the GUI client isn't.

**Source:** https://www.infradead.org/openconnect/
**Install:** `sudo apt install openconnect`

```bash
# Password auth with a tunnel group (protocol=anyconnect is the default)
sudo openconnect --protocol=anyconnect --user=<user> --authgroup=<tunnel-group> https://<vpn-gateway>

# Client-certificate auth (e.g. a PFX exported from a compromised host's cert store)
sudo openconnect --certificate=vpncert.pfx --key=vpncert.pfx https://<vpn-gateway>

# Non-interactive password (lab only)
echo '<pass>' | sudo openconnect --protocol=anyconnect --user=<user> --passwd-on-stdin https://<vpn-gateway>
```

> [!note] **See also** — [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect / ASA]] (Connect / Access — establishing the tunnel with harvested creds or an extracted client cert).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
