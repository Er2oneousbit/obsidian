# netsh

**Tags:** `#netsh` `#windows` `#portforwarding` `#pivoting` `#enumeration`

Windows built-in CLI for network configuration. Used during post-exploitation for port forwarding, firewall rule inspection/modification, proxy setup, and packet capture. No install required — native on all Windows versions.

**Source:** Built-in Windows (`netsh.exe`)
**Install:** Native — no install needed

```cmd
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.25
```

> [!note]
> Primary use case in pentests is port forwarding for pivoting — forward a port on the compromised host to reach an internal service. Requires admin for most operations.

---

## Port Forwarding (Pivoting)

```cmd
# Add portproxy rule — forward external port to internal target
netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=3389 connectaddress=172.16.5.25

# View all portproxy rules
netsh.exe interface portproxy show v4tov4

# Delete a specific rule
netsh.exe interface portproxy delete v4tov4 listenport=8080 listenaddress=0.0.0.0

# Delete all rules
netsh.exe interface portproxy reset
```

> [!tip]
> Combine with a firewall allow rule so traffic actually reaches the listener:
> ```cmd
> netsh advfirewall firewall add rule name="PivotFwd" dir=in action=allow protocol=TCP localport=8080
> ```

---

## Firewall Enumeration

```cmd
# Show all firewall rules
netsh advfirewall firewall show rule name=all

# Show rules for a specific port
netsh advfirewall firewall show rule name=all | findstr "8080"

# Show firewall state/profile
netsh advfirewall show allprofiles
```

---

## Firewall Modification

```cmd
# Disable firewall (all profiles) — noisy
netsh advfirewall set allprofiles state off

# Add allow rule for a port
netsh advfirewall firewall add rule name="AllowPort" dir=in action=allow protocol=TCP localport=4444

# Delete a rule
netsh advfirewall firewall delete rule name="AllowPort"
```

---

## Network Interface / Route Enum

```cmd
# Show interfaces
netsh interface show interface

# Show IP configuration
netsh interface ipv4 show addresses

# Show routing table
netsh interface ipv4 show route

# Show ARP cache
netsh interface ipv4 show neighbors
```

---

## Proxy Configuration

```cmd
# Set proxy (useful for pivoting traffic)
netsh winhttp set proxy 127.0.0.1:1080

# Show current proxy
netsh winhttp show proxy

# Reset proxy
netsh winhttp reset proxy
```

---

## Packet Capture

```cmd
# Start capture to file
netsh trace start persistent=yes capture=yes tracefile=C:\Temp\capture.etl

# Stop capture
netsh trace stop
```

Convert `.etl` to `.pcap` with `etl2pcapng` or open in Windows Performance Analyzer.

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
