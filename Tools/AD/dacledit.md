# dacledit

**Tags:** `#dacledit` `#impacket` `#dacl` `#acl` `#activedirectory` `#privesc`

Impacket script (`impacket-dacledit`) for reading and writing Active Directory object DACLs from Linux — the precise counterpart to PowerView's `Add-DomainObjectAcl`/`Get-DomainObjectAcl`. Given a right over a target object (or after a `WriteDacl` edge), it adds an ACE granting a chosen principal a chosen right (e.g. `FullControl`, or specific rights like DS-Replication for DCSync), enabling ACL-edge escalation without touching Windows.

**Source:** Ships with Impacket (https://github.com/fortra/impacket). **Install:** `pipx install impacket` (Kali: pre-installed as `impacket-dacledit`).

```bash
# Read who has rights over a target
impacket-dacledit -action read -principal <user> -target <victim> '<domain>/<user>:<pass>'

# Grant FullControl (needs WriteDacl/GenericAll on the target)
impacket-dacledit -action write -rights FullControl -principal <user> -target <victim> '<domain>/<user>:<pass>'
```

---

> [!note] **See also** — [[Services/Active Directory/ACL Abuse|ACL Abuse]] — precise DACL read/write for `WriteDacl`→FullControl/DCSync escalation from Linux.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
