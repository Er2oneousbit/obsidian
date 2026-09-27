# sngrep

**Tags:** #sngrep #SIP #VoIP #sniffing #RTP

`sngrep` is an ncurses (TUI) SIP traffic monitor — it captures and displays SIP call flows live or from a pcap, making it the fastest way to watch registrations, INVITEs and digest-auth challenges on the wire during a VoIP engagement. It groups packets into calls, renders the ladder/flow diagram per call, and can export selected dialogs (and their RTP) back out to pcap for offline audio reconstruction or DTMF extraction. Because it shows the digest `REGISTER` challenge/response in real time, it pairs naturally with an on-path (ARP-spoof/VLAN-hop) position to harvest SIP credentials.

**Source:** https://github.com/irontec/sngrep
**Install:** `sudo apt install sngrep`

```bash
sudo sngrep                       # live capture, all interfaces
sudo sngrep -d eth0 port 5060     # bind an interface + BPF filter
sngrep -I voip_capture.pcap       # replay a saved pcap
# In the TUI: select a call → Enter for the flow ladder; F2/save to export the dialog + RTP
```

> [!note] **See also** — [[Services/Network Management/SIP-VoIP|SIP-VoIP]] (eavesdropping / RTP capture, SIP registration hijacking, DTMF extraction).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
