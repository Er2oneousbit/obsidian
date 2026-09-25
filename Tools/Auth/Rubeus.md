#rubeus #auth #authentication #crendentals #secretsdump #passwords #passwordcracking #passtheticket
- [GitHub - GhostPack/Rubeus: Trying to tame the three-headed dog.](https://github.com/GhostPack/Rubeus)
	- [GitHub - GhostPack/Rubeus: Trying to tame the three-headed dog.](https://github.com/GhostPack/Rubeus#example-over-pass-the-hash)
- For kerberos attacks
- `Rubeus.exe dump /nowrap` dumps all tickets if ran as admin, prints in b64
- 
---

> [!note] **See also** — the full methodology behind these commands: [[Services/Active Directory/Kerberos|Kerberos]] (Kerberoast/AS-REP/overpass-the-hash/S4U/ticket forging). Also [[Services/Active Directory/ACL Abuse|ACL Abuse]] — consume a shadow-credential cert with `Rubeus.exe asktgt /certificate:...` and run targeted Kerberoasting after a `GenericWrite` SPN write. Linux counterpart: [[Tools/AD/impacket-kerberos-scripts|impacket Kerberos scripts]].

---

*Created: 2026-07-13*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
