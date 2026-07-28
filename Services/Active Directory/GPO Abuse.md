# GPO Abuse

#GPOAbuse #GroupPolicy #ActiveDirectory #LateralMovement #Privesc

## What is GPO Abuse?

Group Policy Objects push configuration, scheduled tasks, scripts, and security settings to every computer/user in the OUs they're linked to. A principal with edit rights (or link rights) on a GPO applied to high-value systems — a Domain Controllers OU, a server OU — can push an immediate scheduled task or startup script to get code execution as SYSTEM on every machine the GPO applies to. Fast, wide blast radius, and easy to miss if GPO ACLs aren't audited alongside AD object ACLs.

*Content pending — see TODO.md for planned scope.*

---

*Created: 2026-07-27*
*Updated: 2026-07-27*
*Model: claude-sonnet-5*
