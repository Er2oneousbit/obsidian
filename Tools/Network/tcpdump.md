# tcpdump

**Tags:** `#tcpdump` `#packetsniffing` `#networkenumeration` `#mitm` `#credentialcapture` `#bpf`

CLI packet capture built on libpcap, using BPF (Berkeley Packet Filter) expressions. Present on virtually every Unix host — including targets you've compromised — which is why it matters more than [[Tools/Network/wireshark|Wireshark]] on an engagement: it's the sniffer you'll actually have on a shell. Primary pentest uses are capturing cleartext credentials off legacy protocols (r-services, FTP, Telnet, HTTP, SMTP, SNMP), confirming a pivot/relay is passing traffic, and writing `.pcap` files to pull back for offline analysis.

**Source:** https://www.tcpdump.org
**Install:** `sudo apt install tcpdump` (usually preinstalled on Kali and most Linux targets)

```bash
# Capture cleartext credentials on legacy r-services and print packet contents as ASCII
sudo tcpdump -i eth0 -nn -A 'port 512 or port 513 or port 514'
```

---

## Core Flags

| Flag | Purpose |
|---|---|
| `-i <iface>` | Interface to capture on (`-i any` for all) |
| `-nn` | Don't resolve hostnames **or** port names — faster, avoids noisy DNS lookups that leak your presence |
| `-A` | Print packet payload as ASCII — the one you want for cleartext creds |
| `-X` | Print payload as hex **and** ASCII |
| `-w <file.pcap>` | Write raw packets to a file (analyze later in Wireshark) |
| `-r <file.pcap>` | Read back a saved capture |
| `-s 0` | Full packet capture, no snaplen truncation (default is already full on modern versions) |
| `-c <count>` | Stop after N packets |
| `-l` | Line-buffered — required when piping to `grep` |
| `-v` / `-vv` | Increase verbosity (TTL, IP ID, checksums) |

---

## Filter Expressions (BPF)

```bash
# By port / port range
sudo tcpdump -i eth0 -nn 'port 21'
sudo tcpdump -i eth0 -nn 'portrange 512-514'

# By host and direction
sudo tcpdump -i eth0 -nn 'host 10.10.14.5'
sudo tcpdump -i eth0 -nn 'src 10.10.14.5 and dst port 25'

# Boolean logic
sudo tcpdump -i eth0 -nn 'tcp and (port 80 or port 8080) and not host 10.10.14.1'

# Whole subnet
sudo tcpdump -i eth0 -nn 'net 10.10.10.0/24'
```

> [!tip] Quote the filter expression. `and`, `or`, `not`, and parentheses are shell metacharacters or reserved words — an unquoted filter silently captures the wrong thing or errors out.

---

## Credential Capture

Legacy protocols transmit credentials in the clear — pipe the ASCII payload straight to `grep`:

```bash
# Watch for logins across common cleartext protocols
sudo tcpdump -i eth0 -nn -A -l 'port 21 or port 23 or port 25 or port 110 or port 143' \
  | grep -iE 'USER|PASS|LOGIN|AUTH'

# r-services — rlogin/rsh send the username pair and rexec sends the password outright
sudo tcpdump -i eth0 -nn -A 'portrange 512-514'

# HTTP Basic auth (base64 — decode after)
sudo tcpdump -i eth0 -nn -A -l 'port 80' | grep -i 'Authorization: Basic'
```

> [!warning] Sniffing only sees traffic that reaches your interface. On a switched network you'll see just your own traffic and broadcast/multicast unless you're on a SPAN/mirror port, are the gateway, or have poisoned ARP first. Capturing on a compromised host's own interface is the common engagement case.

---

## Capture to File

```bash
# Write for offline analysis, rotate at 100MB
sudo tcpdump -i eth0 -nn -w capture.pcap -C 100

# Read back and filter offline (no root needed)
tcpdump -nn -r capture.pcap 'port 445'

# Transfer off the target, then open in Wireshark
```

> [!note] On a compromised host, prefer `-w` to a file in `/tmp` and exfiltrate it, rather than streaming a live capture over your C2 — it's far less traffic and survives a dropped shell.

---

## Quick Reference

| Goal | Command |
|---|---|
| Cleartext creds, all legacy ports | `sudo tcpdump -i eth0 -nn -A 'port 21 or 23 or 25 or 110'` |
| r-services sniff | `sudo tcpdump -i eth0 -nn -A 'portrange 512-514'` |
| Single host, both directions | `sudo tcpdump -i eth0 -nn 'host <ip>'` |
| Save to pcap | `sudo tcpdump -i eth0 -nn -w out.pcap` |
| Read a pcap | `tcpdump -nn -r out.pcap` |
| Pipe to grep (needs `-l`) | `sudo tcpdump -i eth0 -nn -A -l 'port 80' \| grep -i pass` |
| List interfaces | `tcpdump -D` |

---

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Remote Access/R-Services|R-Services]] (cleartext credential capture on 512–514).
> Related tooling: [[Tools/Network/wireshark|Wireshark / tshark]] for GUI analysis of the resulting `.pcap`.

---

*Created: 2026-08-13*
*Updated: 2026-08-13*
*Model: claude-opus-5*
