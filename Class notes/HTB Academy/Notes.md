# Notes — How to Write Notes Like CWES Claude / CPTS v2 (claude)

Reference for creating new notes that match the style of [[Class notes/HTB Academy/CWES Claude|CWES Claude]] and [[Class notes/HTB Academy/CPTS v2 (claude)|CPTS v2 (claude)]]. Both folders use the same template — read a couple of existing notes in those folders alongside this before writing a new one.

---

## When to use this template

- One note per HTB Academy module/topic (e.g. `Command Injection.md`, `JWT Attacks.md`).
- File name = the topic in Title Case, no module number or "HTB Academy" prefix. Matches how the note gets wikilinked elsewhere (`[[Command Injection]]`).
- Goal is a **standalone reference you'd pull up during an engagement**, not a transcript of the course. Condense the module content into commands, tables, and gotchas — cut narrative explanation.

---

## Skeleton

```markdown
# <Topic Title>

#Tag1 #Tag2 #Tag3 #ToolName #MoreTags

## What is this?

2-4 sentences: what the vuln/technique/tool is, when in an engagement you'd reach for it. End with a "Pairs with" sentence linking related notes: Pairs with [[Other Note]], [[Another Note]].

---

## Tools

| Tool | Use |
|---|---|
| `toolname` | What it's for, one line |
| [ToolWithRepo](https://github.com/owner/repo) | What it's for |

---

## <First Technique/Concept Section>

Short lead-in paragraph if needed, then a table and/or code block.

```bash
command --with FLAGS
```

| Flag | Description |
|---|---|
| `-x` | What it does |

> [!note]
> Gotcha, version difference, or environment quirk worth flagging.

---

## <Next Section>
... repeat pattern ...

---

## Quick Reference

| Goal | Payload / Command |
|---|---|
| Do X | `command x` |
| Do Y | `command y` |

---

*Created: YYYY-MM-DD*
*Updated: YYYY-MM-DD*
*Model: claude-sonnet-4-6*
```

---

## Section-by-section rules

**Title (`# H1`)** — exactly one, matches the file name.

**Tag line** — directly under the title, no blank-line heading, just a line of `#CamelCase` or `#lowercase` hashtags. Mix of: the topic itself, parent category, every tool named in the note, and any HTB-specific keyword you'd search for later (`#Enumeration`, `#RCE`, `#WebAppAttacks`). 4–12 tags is typical. Match the casing style already used for that concept elsewhere in the vault (check a sibling note) rather than inventing a new casing.

**`## What is this?`** — always the first section, always this exact heading. Definition + when-to-use, 2–4 sentences, ends by linking related notes with `[[wikilinks]]` ("Pairs with...", "See also..."). This is the only prose-heavy section — everything after it should be scannable (tables/code), not paragraphs.

**`## Tools`** — present in almost every note. Table of `Tool | Use` (or `Tool | Install | Primary Use` if install commands aren't one-liners). Two linking rules, in priority order:

1. **If the tool has a vault note under `Tools/`, wikilink to it with the full path** — `[[Tools/Web/wpscan|wpscan]]`, `[[Tools/Payloads & Shells/ysoserial|ysoserial]]` — exactly like the `Services/*.md` notes do. Use the full path (not a bare `[[wpscan]]`) because several tools exist in two folders (a full note plus an un-expanded shadow-folder stub — see `TODO.md`); always point at the fuller note. This is what makes the note↔tool cross-linking bidirectional.
2. **If the tool has no vault note at all, create a stub** under the matching `Tools/` subfolder rather than leaving bare text — `# ToolName` → `**Tags:**` line → 2–4 sentence description → `**Source:**`/`**Install:**` → one usage example pulled from this note → a `> [!note] **See also**` callout linking back to the note(s) that use it → footer. Then link the stub. (A real note to expand later, not a one-line placeholder.) For a genuinely standard pre-installed binary that has no vault note and doesn't warrant one (`curl`, `nc`), leave it as plain `` `code` `` and, if useful, link the upstream docs/repo with `[name](url)`.

**Every linked tool needs a backlink.** Whenever you link a `Tools/` note from a Tools table here — new stub or existing full note — open that tool note and ensure it has a `> [!note] **See also**` callout pointing back to this note (`[[Class notes/HTB Academy/CPTS v2 (claude)/<Note>|<Note>]]` or the CWES-folder equivalent). If it's already referenced from several notes, list them all in the one callout. **Bump that tool note's footer** when you add/extend the backlink (`*Updated:*` to today, `*Model:*` to the editing model); if it's a legacy note with no footer, add the standard three-line footer (Created = first-commit date via `git log --diff-filter=A --format=%ad --date=short -- <path>`, Updated = today, Model = editing model). Same discipline as `Services/template.md`.

**This is not deferrable, and it applies to Service notes too.** The reciprocal backlink is part of *completing* the note being audited — add it inline, before you mark the note done; never batch it into a later "backlink sweep." The same rule covers **any `Services/` note you link as a secondary target** from the note being audited (e.g. a technique note that references `[[Services/Active Directory/Kerberos]]`): open that Service note and ensure it carries a `> [!note] **See also**` callout pointing back here, listing every note that references it, and bump its footer. Tools *and* Services — every vault note you touch as a backlink target must list the note currently being audited. (Soft `Pairs with [[Other Technique Note]]` links between class notes are exempt — those don't need to be made bidirectional.)

**Body sections (`## `)** — one per sub-technique or phase. Separate every top-level `## ` section with a `---` horizontal rule before and after (i.e. the whole doc is `## Section` → content → `---` → `## Section` → content → `---`...). Use `### ` subsections for OS variants (Linux/Windows), tool variants, or ordered steps within a section. Prefer:
- A **flag/parameter reference table** right after the first example command in a section.
- **Multiple small fenced code blocks** over one giant block — each block is a runnable, copy-pasteable variant with a `# comment` above non-obvious lines.
- Real command syntax with placeholders in angle brackets: `<TARGET_IP>`, `<PORT>`, `<collaborator-url>`, `<token>`. Attacker IP in examples is `10.10.14.5` (matches HTB VPN convention used throughout these notes).

**Callouts** — Obsidian callout syntax, used sparingly and only for information that would otherwise cause wasted time on an engagement:
- `> [!note]` — clarification, version difference, path difference between distros.
- `> [!tip]` — a shortcut or better default (e.g. "start with `-ac`, it's faster than manual filtering").
- `> [!warning]` — anything destructive, noisy, or scope-sensitive (uncapped recursion, DoS-risk flags, rate limits).

**Diagrams & images** — when a flow or relationship is clearer as a picture than as ASCII/prose/a table, use one. Prefer a fenced ` ```mermaid ` block (flowcharts, sequence/attack flows, graphs — it's text, diffs cleanly, and renders in both Obsidian and GitHub). For anything mermaid can't express, author a **self-contained** `.svg` (no external fonts/scripts/refs), drop it in a `_media/` subfolder beside the note, and embed with `![[diagram.svg]]` — don't paste raw inline `<svg>` into the body (Obsidian reading-mode is inconsistent and GitHub strips it). Make diagrams legible in both light *and* dark themes and give SVGs a `<title>`/`<desc>`. Reserve them for real structure (attack chains, auth flows, trust relationships, network topology); a small table or short ASCII is still fine — don't add decorative pictures.

**Cross-links** — `[[Note Name]]` to other notes, `[[Note Name#Section]]` or same-doc `[[#Section Name]]` to jump to a specific technique instead of repeating it (e.g. Command Injection's API section says "same flags as [[#Directory Fuzzing]]" instead of restating the flag table).

**`## Quick Reference`** — last content section before the footer, in the longer/more technique-dense notes (skip it on short single-concept notes). A `Goal | Payload/Command` copy-paste table condensing the whole doc into one scroll-free cheat sheet.

**Footer** — always the last three lines, after a final `---`:
```
*Created: YYYY-MM-DD*
*Updated: YYYY-MM-DD*
*Model: claude-sonnet-4-6*
```
Set `Created` to the date you first write the note and never change it again. Bump `Updated` any time you materially edit the note (new section, corrected command, etc.) — cosmetic edits don't need a bump. Use the actual model you're running as (update the `Model:` line if it isn't `claude-sonnet-4-6`).

---

## Content judgment calls

- Condense, don't transcribe. If HTB Academy spends three paragraphs motivating a concept, that becomes one sentence in `What is this?`.
- Every command should be runnable as shown once placeholders are filled in — don't leave pseudocode.
- When a technique has a "noisy/manual" and an "automated/tool" version, show both (e.g. manual curl fuzz loop vs. `ffuf`), automated first if it's what you'd actually reach for.
- Don't duplicate content that already lives in another note — link to it instead ([[#Directory Fuzzing]]-style backreferences, or `[[Other Note]]` for a different file).
- It's fine for a note to be long (several hundred lines) if the topic is broad (e.g. `Attacking Common Applications.md`, `Command Injection.md`) — length isn't a problem as long as it stays table/code-dense rather than prose-dense.

---

## Content completeness check (do this for every note, not just formatting)

Refactoring a note into this skeleton is a structural pass — it does not by itself verify the *content* is current. Do both, every time (same discipline as `Services/template.md`):

1. **Inventory what the note currently covers** — list the named techniques/CVEs/tool flags it documents.
2. **Web-search the current state of the art** — e.g. "`<topic>` attack techniques {current year}", "`<primary tool>` new flags/modules" — and diff against the inventory. Look for newer named/numbered technique variants, CVE-numbered additions, and tool syntax drift (verify flags against the tool's own docs, not just old blog posts).
3. **Report gaps before writing hundreds of lines unprompted.** Small gap (a couple of rows/commands) → just fix it. Substantial gap (multiple missing techniques) → summarize and ask whether to add all / stub / skip; don't assume silently.
4. **Match the existing depth when filling gaps** — a full `### ` subsection with a runnable command block, not a lighter-weight summary.

"No issues found" for a note in these folders means **structurally compliant *and* content-checked against current sources** — not just "parses and has the right headings."
