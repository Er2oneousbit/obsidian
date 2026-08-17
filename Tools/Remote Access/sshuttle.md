# sshuttle

**Tags:** `#sshuttle` `#pivoting` `#tunneling` `#vpn` `#ssh` `#proxy`

"Poor man's VPN" over SSH — transparently routes whole subnets through an SSH connection to a pivot, using local iptables/pf rules, so **no proxychains** and no per-tool proxy config. Only requires a normal SSH login and Python on the pivot (no root there). Ideal when you want ordinary tools (`nmap`, browsers, `crackmapexec`) to reach an internal subnet as if directly connected. TCP + DNS only — it will not carry UDP/ICMP.

**Source:** https://github.com/sshuttle/sshuttle
**Install:** `sudo apt install sshuttle` (or `pipx install sshuttle`)

```bash
# Route an internal subnet through the pivot; --dns also tunnels name resolution
sudo sshuttle -r ubuntu@10.129.202.64 172.16.5.0/23 --dns -v
```

> [!note] **See also**
> Used as a pivoting technique in [[Class notes/HTB Academy/CPTS v2 (claude)/Pivoting, Tunneling & Port Forwarding|Pivoting, Tunneling & Port Forwarding]] — the transparent-routing option when you want to avoid proxychains. Contrast with [[Tools/Remote Access/ligolo-ng|ligolo-ng]] (TUN, carries more) and [[Tools/Remote Access/Proxychains|proxychains]] (per-tool SOCKS).

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
