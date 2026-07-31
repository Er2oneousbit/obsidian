# Bashfuscator

**Tags:** #Bashfuscator #Obfuscation #Evasion #CommandInjection #Bash #Linux #Payloads

`Bashfuscator` is a modular obfuscation framework for Bash/`sh` command lines. It takes a plaintext command and emits a functionally identical but heavily mangled one — token obfuscation, string encoding, variable indirection, and randomised mangling — to get past keyword blacklists, WAF signatures, and command-line logging. Reach for it when a [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|command injection]] point works but the obvious payload keeps getting filtered.

**Source:** https://github.com/Bashfuscator/Bashfuscator
**Install:** `git clone https://github.com/Bashfuscator/Bashfuscator && cd Bashfuscator && pip3 install -e .`

```bash
# Obfuscate a command with a randomly chosen technique
bashfuscator -c 'cat /etc/passwd'

# Minimal-size output — one layer, one technique, no extra mangling
# (default output can run to tens of KB, too long for a URL parameter)
bashfuscator -c 'cat /etc/passwd' -s 1 -t 1 --no-mangling -m random

# List available obfuscation modules to pick one deliberately
bashfuscator --list
```

> [!tip] Default output is enormous. Always start with `-s 1 -t 1 --no-mangling` for injection points with a length limit, then dial up only if the short form gets caught.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Command Injection|Command Injection]] — Linux payload obfuscation when keyword filters block the direct command. Windows counterpart is [[Tools/Payloads & Shells/Invoke-DOSfuscation|Invoke-DOSfuscation]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
