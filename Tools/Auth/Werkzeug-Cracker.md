# Werkzeug-Cracker

**Tags:** `#WerkzeugCracker` `#PasswordCracking` `#Werkzeug` `#Flask` `#PBKDF2` `#Python` `#hashcracking`

Wordlist cracker for **Werkzeug password hashes** — the `pbkdf2:sha256:…` (and scrypt) strings produced by Flask's `werkzeug.security.generate_password_hash()` and stored in most Flask app databases. It calls Werkzeug's own `check_password_hash()` per candidate, so it consumes the hash **verbatim — no reformatting** — and works for whatever method the hash declares. Multithreaded but **CPU-only**; for GPU speed on plain `pbkdf2:sha256`, reformat and use [[Tools/Auth/hashcat|hashcat]] `-m 10900` instead.

**Source:** https://github.com/AnataarXVI/Werkzeug-Cracker
**Install:**
```bash
git clone https://github.com/AnataarXVI/Werkzeug_Cracker.git
cd Werkzeug_Cracker
pip3 install -r requirements.txt      # needs Python 3.10+ and the werkzeug library
```

---

## Usage

```bash
# hash.txt = one Werkzeug hash per line; -t threads (default 15)
python3 werkzeug_cracker.py -p hash.txt -w /usr/share/wordlists/rockyou.txt
python3 werkzeug_cracker.py -p hash.txt -w rockyou.txt -t 32
```

| Flag | Meaning |
|---|---|
| `-p, --password <file>` | File of target hashes (required) |
| `-w, --wordlist <file>` | Wordlist (required) |
| `-t, --threads <n>` | Thread count (default 15) |

**The hash it expects** — straight out of a Flask users table:

```
pbkdf2:sha256:600000$YnRgjnim$c9541a8c...        # method:algo:iterations$salt$hexdigest
```

---

## When to use this vs hashcat

| | Werkzeug-Cracker | [[Tools/Auth/hashcat\|hashcat]] `-m 10900` |
|---|---|---|
| Input | **Werkzeug string as-is** — no conversion | needs reformat → `sha256:iter:base64(salt):base64(digest)` |
| Methods | any `check_password_hash` supports (pbkdf2 variants, scrypt) | `pbkdf2-hmac-sha256` only |
| Speed | CPU, multithreaded — modest | **GPU — far faster** |
| Best for | quick job, odd method, no GPU, no conversion hassle | big wordlist + a GPU box |

> [!tip] **PBKDF2 iterations only parallelise *across* candidates, not within one** (each hash is a serial chain), so even on a GPU the H/s is low (a 600k-iter hash ran ~4.3 kH/s on an RTX 5060 Ti). But **rockyou is frequency-ordered** — a common password lands in the first fraction of a percent regardless of tool. **Run the wordlist before deciding it's infeasible;** the "is this even worth it" analysis often costs more than the crack. (HTB *Instant*: a 600k-iter hash that "looked" like 2.7 days fell in ~1 minute.)

---

## Quick Reference

| Need | Command |
|---|---|
| Crack a Flask hash, no conversion | `python3 werkzeug_cracker.py -p hash.txt -w rockyou.txt` |
| More threads | `... -t 32` |
| GPU alternative | reformat → `hashcat -a 0 -m 10900 h.txt rockyou.txt` (see [[Tools/Auth/hashcat\|hashcat]]) |

> [!note] **See also** — [[Services/Web Services/Werkzeug|Werkzeug]] (where these hashes come from + the debug-console RCE path), [[Tools/Auth/hashcat|hashcat]] (`-m 10900` GPU path), [[Class notes/HTB Academy/CPTS v2 (claude)/Password Attacks|Password Attacks]].

---

*Created: 2026-08-26*
*Updated: 2026-08-26*
*Model: claude-opus-5*
