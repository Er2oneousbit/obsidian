# ACL Abuse

#ACLAbuse #DACL #ActiveDirectory #BloodHound #Privesc

## What is ACL Abuse?

Every Active Directory object (users, groups, computers, GPOs, OUs) has a DACL governing who can read or modify it. Misconfigured or over-permissive ACEs — `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, `ForceChangePassword`, `AddMember`, `ReadGMSAPassword`, `ReadLAPSPassword`, and others — let a low-privileged principal escalate by directly modifying a more-privileged object instead of cracking or stealing a credential. BloodHound is the primary tool for discovering these paths at scale; PowerView/bloodyAD for exploiting individual edges.

*Content pending — see TODO.md for planned scope.*

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
