# swaks

**Tags:** #swaks #SMTP #Email #Phishing #Enumeration

Swaks (Swiss Army Knife for SMTP) is a scriptable CLI SMTP client — send fully-controlled test emails, exercise STARTTLS/AUTH, and abuse open relays for phishing during an engagement. Reach for it after `smtp-user-enum` confirms valid recipients or when an `smtp-open-relay` finding needs a proof-of-concept delivery.

**Source:** https://github.com/jetmore/swaks
**Install:** `sudo apt install swaks`

```bash
# Send a test/phishing email (open-relay abuse)
swaks --to victim@target.com --from admin@target.com --server 10.10.10.10 \
  --header "Subject: Test" --body "Click here"

# With an attachment
swaks --to victim@target.com --from admin@target.com --server 10.10.10.10 \
  --attach malicious.docx

# Authenticated submission over STARTTLS
swaks --to victim@target.com --server mail.target.com:587 -tls \
  --auth LOGIN --auth-user user@target.com --auth-password 'Password123'
```

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] — SMTP relay abuse / test email delivery; pairs with [[Tools/Email/smtp-user-enum|smtp-user-enum]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-4-8*
