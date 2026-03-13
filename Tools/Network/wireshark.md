# Wireshark / tshark

**Tags:** `#wireshark` `#tshark` `#packetsniffing` `#networkenumeration` `#mitm`

GUI and CLI packet analyzer. Used during pentests for credential capture on unencrypted protocols, analyzing NTLM/Kerberos traffic, inspecting web requests, and validating that tools like Responder and mitm6 are capturing properly.

**Source:** https://www.wireshark.org
**Install:** `sudo apt install wireshark tshark`

```bash
# GUI
sudo -E wireshark

# CLI (tshark)
sudo tshark -i eth0
```

> [!note]
> `tshark` is the CLI equivalent — useful for remote capture over SSH or scripted extraction. Run as root or add your user to the `wireshark` group: `sudo usermod -aG wireshark $USER`

---

## Capture

```bash
# Start GUI capture
sudo -E wireshark

# tshark — capture on interface
sudo tshark -i eth0

# Capture to file
sudo tshark -i eth0 -w capture.pcap

# Read a saved capture
tshark -r capture.pcap

# Capture on specific port
sudo tshark -i eth0 -f "port 445"
```

---

## Display Filters (GUI / tshark `-Y`)

| Filter | Description |
|--------|-------------|
| `ip.addr == 10.129.14.128` | Traffic to/from specific IP |
| `ip.src == 10.0.0.1 && ip.dst == 10.0.0.2` | Between two hosts |
| `tcp.port == 80` | Filter by TCP port |
| `udp.port == 161` | SNMP traffic |
| `http` | All HTTP traffic |
| `http.request.method == "POST"` | HTTP POST requests (credential hunting) |
| `dns` | DNS queries and responses |
| `smb || smb2` | SMB traffic |
| `kerberos` | Kerberos auth traffic |
| `ntlmssp` | NTLM authentication |
| `icmp` | ICMP (ping/scan) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN packets (port scans) |
| `tcp.stream eq 5` | Follow specific TCP stream |
| `eth.addr == 00:11:22:33:44:55` | Filter by MAC address |
| `!(arp || dns || icmp)` | Exclude noise |

---

## tshark CLI Extraction

```bash
# Apply display filter
sudo tshark -i eth0 -Y "http.request.method == POST"

# Extract HTTP credentials from pcap
tshark -r capture.pcap -Y "http.request.method == POST" -T fields \
  -e http.host -e http.request.uri -e http.file_data

# Extract DNS queries
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name

# Extract NTLM hashes
tshark -r capture.pcap -Y "ntlmssp.auth.username" -T fields \
  -e ntlmssp.auth.domain -e ntlmssp.auth.username

# Follow TCP stream (stream 0)
tshark -r capture.pcap -q -z follow,tcp,ascii,0

# Extract HTTP objects from pcap
tshark -r capture.pcap --export-objects http,./extracted-files/
```

---

## Credential Hunting Workflow

```bash
# 1. Capture while Responder/mitm6 runs
sudo tshark -i eth0 -w session.pcap

# 2. Review NTLM auth attempts
tshark -r session.pcap -Y "ntlmssp" -T fields \
  -e ip.src -e ntlmssp.auth.username -e ntlmssp.auth.domain

# 3. Pull HTTP POST bodies (cleartext creds)
tshark -r session.pcap -Y "http.request.method==POST" -T fields \
  -e ip.src -e http.host -e http.file_data 2>/dev/null

# 4. Check for FTP/Telnet/SMTP cleartext
tshark -r session.pcap -Y "ftp || telnet" -T fields -e text
```

---

## Capture Filters (BPF — set before capture)

```bash
# BPF filters (faster — set at capture level, not display level)
sudo tshark -i eth0 -f "host 10.129.14.128"
sudo tshark -i eth0 -f "port 445"
sudo tshark -i eth0 -f "not port 22"
sudo tshark -i eth0 -f "net 10.129.14.0/24"
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
