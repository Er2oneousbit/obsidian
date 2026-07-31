## Obsidian Offensive Security Knowledge Base

A personal, continuously‑evolving offensive security knowledge base built in Obsidian.
This vault contains 100+ cross‑linked notes covering pentesting techniques, service exploitation, methodologies, tooling, and training material. It serves as my structured learning system and reference library for real-world testing.

> ⚠️ **Authorized and educational use only.** Everything here is for authorized penetration testing, CTF competitions, security research, and defensive learning. Using these techniques against systems you don't own or have explicit written permission to test is illegal. You are responsible for how you use this material. Verify commands and CVE details against primary sources before relying on them on an engagement.

## Purpose

This repo documents how I learn, test, break, and analyze systems.
It reflects my offensive methodology, my curiosity, and my commitment to building repeatable processes rather than one-off exploits. Some content was AI-assisted (Claude/Copilot) during research or drafting.  Report an issue if something is missing or incorrect.

## Structure

```
CTF Notes/            # Per-platform CTF writeups (HTB, THM)
Class notes/          # HTB Academy, Portswigger, training course notes
Exploits/             # Standalone exploit/technique notes
Methdocs/             # Testing methodologies and checklists
Misc/                 # Catch-all notes
Services/             # Service-specific attack/enum references (SMB, MSSQL, etc.)
Sr Tester Role/       # Web/API/AI testing topics and checklists
Tools/                # Tool-specific usage notes
VM notes/             # VM setup/config notes
_Pentest Artifacts/   # Report templates and engagement checklists
```

## Highlights

A few representative notes that show the type of work in this vault:
Service enumeration & exploitation chains (SMB, MSSQL, LDAP, Kerberos)
Web/API testing methodologies and repeatable checklists
HTB Academy & PortSwigger labs with step-by-step reasoning
Tool usage breakdowns (Burp, FFUF, Impacket, SQLmap, etc.)
Exploit PoCs and technique notes (auth bypass, deserialization, SSRF, RCE)
AI/LLM security testing notes (prompt injection, jailbreaks, model behavior)

## Usage

Clone the repo and open the vault root in Obsidian.
The graph view provides a high-level map of how concepts connect across services, tools, and methodologies.
As I am refactoring old notes and adding new notes, they should have cross and back links to and from service to tool usage.
Hack the box notes are per module/topic and the tooling or service should be linked to the corresponding link (this is in progress).

## Not affiliated with Hack The Box

The `Class notes/HTB Academy/CPTS v2 (claude)` and `CWES Claude` folders are **independently‑written reference notes** covering the same general topic areas as common certification curricula. They are **not** affiliated with, endorsed by, or reproductions of any Hack The Box Academy course or other paid material. My raw personal course notes are intentionally excluded from this repository.

## AI assistance

Large portions of the reference notes were drafted and standardized with AI assistance (Anthropic's Claude), then organized, fact‑checked against current sources, and curated by me. Footers on individual notes record the model used. Treat everything as a starting point, not gospel.

## License

Licensed under [Creative Commons Attribution 4.0 International (CC BY 4.0)](LICENSE) — you're free to share and adapt with attribution. See [`LICENSE`](LICENSE) for the full terms.