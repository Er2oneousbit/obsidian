# PCredz

**Tags:** #PCredz #NetworkCapture #CredentialDumping #Sniffing #pcap #Recon #MITM

`PCredz` extracts credentials from network traffic — live off an interface or from a saved pcap. It parses out cleartext logins (FTP, POP/IMAP/SMTP, HTTP Basic, SNMP community strings), HTTP NTLM and form auth, and crucially **NTLMv1/NTLMv2 challenge-response hashes** in hashcat-ready format. Pair it with a poisoning/MITM position (Responder, mitm6, ARP spoofing) or just run it against a pcap someone handed you during an engagement.

**Source:** https://github.com/lgandx/PCredz
**Install:** `git clone https://github.com/lgandx/PCredz` — needs `libpcap` and `python3-pip` (`pip3 install Cython python-libpcap`)

```bash
# Parse a saved capture
python3 Pcredz -f capture.pcap

# Live capture on an interface
sudo python3 Pcredz -i eth0

# Whole directory of pcaps
python3 Pcredz -d /path/to/pcaps/

# -v verbose, -t also parse from a tcpdump-style file
```

| Flag | Description |
|---|---|
| `-f` | Single pcap file |
| `-d` | Directory of pcaps |
| `-i` | Live interface |
| `-v` | Verbose |

**What it recovers:**

| Category | Examples |
|---|---|
| Cleartext protocols | FTP, Telnet, POP3, IMAP, SMTP, HTTP Basic |
| Challenge-response | NTLMv1 / NTLMv2 hashes (→ hashcat / crack or relay) |
| Other | SNMP community strings, Kerberos, HTTP form logins, credit-card patterns |

> [!tip] The high-value output is NTLMv1/v2 hashes captured passively — feed NTLMv2 into `hashcat -m 5600`, or if NTLMv1 is present, that's a downgrade path worth flagging (crackable to NTLM via crack.sh). Combine with a [[Tools/Lateral Movement/responder|Responder]] poisoning position to *generate* the auth you then capture.

> [!warning] Passive capture is quiet, but the MITM/poisoning you use to *get* the traffic (Responder, ARP spoof) is noisy and disruptive on a production LAN — scope the poisoning, not just the sniffing.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]] — extracting credentials from network captures. Sibling tool focused on **Net-NTLMv2 from raw pcap/`.etl`**: [[Tools/Network/NTLMRawUnHide|NTLMRawUnHide]] (Python + PowerShell-7 fork).

---

*Created: 2026-07-31*
*Updated: 2026-08-14*
*Model: claude-opus-5*
