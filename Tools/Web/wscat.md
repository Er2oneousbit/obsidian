# wscat

**Tags:** #wscat #WebSockets #Fuzzing #WebAppAttacks #APIAttacks #NodeJS

`wscat` is a command-line WebSocket client. Once a connection is upgraded, WebSocket frames bypass most of the request-level controls a site applies to HTTP — authorization checks, rate limits, and input validation are frequently enforced only on the REST side. wscat gives you a raw interactive session to send arbitrary frames and watch what the server accepts, which is hard to do from a browser and clumsy from a proxy.

**Source:** https://github.com/websockets/wscat
**Install:** `npm install -g wscat`

```bash
# Connect
wscat -c ws://<TARGET>/ws

# Authenticated (the handshake is a normal HTTP request — headers apply)
wscat -c wss://<TARGET>/ws -H "Authorization: Bearer <token>"
wscat -c ws://<TARGET>/ws -H "Cookie: session=<token>"

# Origin header is the usual access control on the handshake — test it
wscat -c ws://<TARGET>/ws -H "Origin: https://evil.com"

# Self-signed cert on the target
wscat -c wss://<TARGET>/ws --no-check

# Listen mode — stand up your own endpoint for CSWSH testing
wscat -l 8080
```

```bash
# Once connected, send frames at the > prompt
> {"action":"getUser","id":1}
> {"action":"getUser","id":2}        # IDOR — does it return another user?
> {"action":"admin","cmd":"whoami"}  # is authorization re-checked per message?
```

| Flag | Description |
|---|---|
| `-c` | Connect to a URL |
| `-l` | Listen on a port (server mode) |
| `-H` | Add a header to the handshake |
| `--no-check` | Skip TLS certificate validation |
| `-s` | Subprotocol to request |
| `-x` | Send one message, print the response, exit |

> [!tip] The highest-yield test is whether authorization is re-checked **per message** or only at the handshake. Connect as a low-privilege user, then send a privileged action — a lot of implementations authenticate once on upgrade and trust every frame afterwards.

> [!note] If the handshake succeeds with an arbitrary `Origin`, the endpoint is likely vulnerable to Cross-Site WebSocket Hijacking — see [[Techniques/WebSockets|WebSockets]].

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Fuzzing|Fuzzing]] — WebSocket fuzzing; [[Techniques/WebSockets|WebSockets]] — full attack surface. [[Tools/Web/Burpsuite|Burp Suite]] handles interception and replay when you need the proxy view.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
