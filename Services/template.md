# Template — How to Write Services Notes

Standard skeleton for every `Services/*.md` note. This vault currently has two competing styles across the 60 existing notes (majority: tag-line + `Enumeration`/`Connect`/`Attack Vectors`/`Dangerous Settings`/`Quick Reference`; minority "alternate": plain heading + generic `What is it?` + `Dangerous Configurations`). This template picks **one** standard — refactor both styles into this when you touch a note. Read a converted note alongside this file before writing/refactoring another.

---

## When to use this template

- One note per network service/protocol (e.g. `FTP.md`, `Kerberos.md`, `MSSQL.md`), filed under the matching category subfolder (`File Xfer/`, `Active Directory/`, `Database Services/`, etc. — see `_Frameworks and Compliance.md`-style folder grouping already in place).
- Goal is **"I have this service open on an engagement — what do I do?"** — a scannable enumeration → exploitation → hardening reference, not a protocol history lesson.
- This note documents the *service*. It links out to `Tools/*.md` for *how to use* each tool — don't duplicate a tool's full flag reference here, just enough of the command to show intent, then link.

---

## Skeleton

```markdown
# <Service Name>

#<ServiceTag> #<ProtocolTag> #<CategoryTag>

## What is <Service Name>?

1–3 sentences: what the service is, its default port(s)/protocol, and the one or two things that make it interesting on an engagement (cleartext auth, common misconfig, frequently-exposed admin interface, etc.).

- Port **<PROTO> <PORT>** — <purpose>
- <Other protocol basics: passive/active mode, auth mechanisms, common variants/forks>

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/<Category>/<ToolName>\|<ToolName>]] | One line — what it's for against this service |
| [[Tools/<Category>/<ToolName>\|<ToolName>]] | One line — what it's for against this service |

---

## Enumeration

```bash
# Nmap service/version detection + relevant NSE scripts
nmap -p <PORT> --script <script-name> -sV <target>
```

| Flag / Script | Description |
|---|---|
| `<script-name>` | What it checks for |

---

## Connect / Access

```bash
# Standard connection
<client> <target>

# Anonymous / default-creds connection, if the service commonly allows it
```

### <Variant — e.g. SSL/TLS, alternate client, Windows vs Linux>

```bash
<variant-specific commands>
```

---

## Attack Vectors

### <Technique 1 — e.g. Brute Force>

```bash
hydra -l <user> -P <wordlist> <service>://<target>
```

### <Technique 2 — e.g. known CVE, protocol-specific abuse, relay/pivot>

```bash
<commands>
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| <misconfiguration> | <impact if present> |

---

## Quick Reference

| Goal | Command |
|---|---|
| <goal> | `<command>` |

---

*Created: YYYY-MM-DD*
*Updated: YYYY-MM-DD*
*Model: claude-sonnet-5*
```

---

## Section-by-section rules

**Title (`# H1`)** — exactly one, matches the file name. Currently missing from most existing notes (they start directly at the tag line) — add it when refactoring. Cheap, and matches every other folder in this vault (`Tools/`, `Frameworks and Compliance/`, `Class notes/`).

**Tag line** — directly under the title, no blank-line heading, a line of `#CamelCase` hashtags: the service name, the protocol family, and the category it's filed under (mirrors the existing convention — don't invent new casing, check a sibling note in the same subfolder).

**`## What is <Service>?`** — always the first section, always this exact heading pattern (not the generic "What is it?" used by the 8 alternate-style notes — name the actual service). Prose is fine here; everything after this section should be commands/tables, not paragraphs.

**`## Tools`** — new section, not present in any existing Services note. This is what makes the Service → Tool cross-linking design work: every tool named anywhere in this note should appear here once, wikilinked to its actual `Tools/` note. Use the **full path** in the link (`[[Tools/Auth/Hydra|Hydra]]`, not `[[Hydra]]`) — several tools currently exist in two places (a full note and a not-yet-expanded stub in a shadow folder, see `TODO.md`), and a bare filename link is ambiguous. Always link to the fuller note, not the stub, until the stub gets expanded.

**No "no vault note yet" plain text.** If a tool named in the note doesn't have a `Tools/` note at all, don't leave it as bare text in the Tools table — create a stub note for it and link to that instead. A stub is: `# ToolName` → `**Tags:**` line → a 2–4 sentence description (what it does, why it's relevant here) → `**Source:**` (repo/docs link) and `**Install:**` if known → one small usage example pulled from the context you already have in the Services note → `> [!note] **See also**` callout linking back to the Services note(s) that reference it → footer. File it in the `Tools/` subfolder that matches its category (mirror where sibling tools already live — e.g. a coercion script goes next to `Coercer.md`, a cloud/M365 tool goes in `Tools/Cloud/`). This is a real note meant to be expanded later, not a placeholder — don't write `#update` markers or leave it at one line.

**Every linked tool needs a backlink, not just new stubs.** Whenever a `Tools/` note gets linked from a Services note's Tools table — whether it's a brand-new stub or an existing full note that just didn't have this yet — open that tool note and make sure it has a `> [!note] **See also**` callout pointing back to the Services note(s) that use it (`[[Services/<Category>/<Service>|<Service>]]`), same as the AADInternals/GraphRunner/Certify examples. If the tool is already linked from multiple Services notes, list all of them in the one callout rather than adding several. This is what makes the cross-linking bidirectional — check it every time you add a link to the Tools table, not only when creating a new stub.

**The same reciprocal rule applies to any `Services/` note you link as a secondary target** — a Service note that cross-references another Service note (e.g. an ADCS note linking `[[Services/Active Directory/Kerberos]]`) must leave a `> [!note] **See also**` backlink in that other note pointing here, listing every note that references it, footer bumped. Tools *and* Services: every vault note touched as a backlink target lists the note currently being audited. Do it inline, before the note is considered done — never defer to a later sweep.

**`## Enumeration`** — how to identify/fingerprint the service and pull version info. Nmap NSE scripts first if they exist for the service.

**`## Connect / Access`** — the basic "get in" commands: standard auth, anonymous/default access if commonly open, then `### ` subsections for variants (TLS wrapper, Windows-native client, alternate ports).

**`## Attack Vectors`** — one `### ` subsection per technique (brute force, known CVE class, protocol-specific abuse, relay potential). This is the section most existing notes already do well — keep that density, just make sure headings are consistent (`### Brute Force`, not `### Cracking passwords` one place and `### Password Attacks` another).

**`## Dangerous Settings`** — always this exact heading (not "Dangerous Configurations", which 8 notes currently use — standardize down to this one). A `Setting | Risk` table of misconfigurations worth flagging in a report if found.

**`## Quick Reference`** — always a `Goal | Command` table (not the bash-comment-block style some alternate notes use) — scroll-free copy-paste cheat sheet condensing the whole note.

**Footer** — new for this folder (no existing Services note has one). Matches every other folder's convention: `*Created:*` set once and never changed, `*Updated:*` bumped on material edits, `*Model:*` set to whichever model actually wrote/edited it.

---

## Content completeness check (do this for every note, not just formatting)

Refactoring a note into this skeleton is a structural pass — it does not by itself verify the note's *content* is current or complete. Do both, every time:

1. **Inventory what the note currently covers** — list the named techniques/CVEs/attack classes it documents (e.g. for ADCS: which ESC numbers are present).
2. **Web-search the current state of the art for that service** — e.g. "`<service>` attack techniques {current year}", "`<primary tool>` privilege escalation techniques list" — and diff against the inventory. Look specifically for:
   - Newer named/numbered technique variants added since the note was last touched (CVE-numbered or scheme-numbered, like ADCS's ESC*).
   - Tool command syntax drift — flags renamed or added across the primary tool's versions (verify against the tool's own docs/wiki, not just older blog posts).
   - Structural gaps the template expects but this specific service doesn't need forced content for (e.g. a service with no natural "Connect / Access" step — it's fine to omit or repurpose a section rather than pad it).
3. **Report gaps before writing hundreds of lines unprompted.** If the gap is small (a couple of missing rows), just fix it. If it's substantial (multiple missing techniques, like ADCS's missing ESC5/11-16), summarize what's missing and ask whether to add it all, stub it, or skip — don't assume silently.
4. **Match the existing depth when filling gaps** — same structure as sibling techniques already in the note (a `### ` subsection with a **Conditions** line and a runnable command block), not a lighter-weight summary.

This is what "no issues found" should mean going forward for any note in this folder: structurally compliant *and* content-checked against current sources — not just "the file parses and has the right headings."

---

## Migration checklist (per existing note)

When refactoring an existing `Services/*.md` note into this template:

- [ ] Run the **content completeness check** above first — this determines how much of the rest of the checklist actually matters
- [ ] Add `# <Service Name>` H1 if missing
- [ ] Rename `## What is it?` → `## What is <Service>?` if it's one of the 8 alternate-style notes
- [ ] Add a `## Tools` section — pull every tool name mentioned in commands throughout the note, wikilink each to its `Tools/` note (full path, pointing at the fuller version per the cross-linking TODO)
- [ ] Rename `## Dangerous Configurations` → `## Dangerous Settings` if present; add the section if missing entirely (a few notes lack it)
- [ ] Convert a bash-block `Quick Reference` into a `Goal | Command` table if needed
- [ ] Add the `Created`/`Updated`/`Model` footer
- [ ] Fix the two folder-name typos this affects if editing a note in them: `Local System Managment/` → should be `Local System Management/`, `Network management/` → should be `Network Management/` (rename the folder once, not per-file)
