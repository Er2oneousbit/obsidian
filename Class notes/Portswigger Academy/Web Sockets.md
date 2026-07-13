- full duplex communications protocol initiated over HTTP. They are commonly used in modern web applications for streaming data and other asynchronous traffic.
- Messages can be sent in either direction at any time and are not transactional in nature. The connection will normally stay open and idle until either the client or the server is ready to send a message.
- created using client-side JavaScript 
	- **unencrypted** `var ws = new WebSocket("ws://normal-website.com/chat");`
	- **encrypted** `var ws = new WebSocket("wss://normal-website.com/chat");`
- Request
```
GET /chat HTTP/1.1 
Host: normal-website.com 
Sec-WebSocket-Version: 13 
Sec-WebSocket-Key: wDqumtseNBJdhkihL6PW7w== Connection: 
keep-alive, Upgrade 
Cookie: session=KOsEJNuflw4Rd9BDNrVmvwBF9rEijeE2 
Upgrade: websocket
```
- Response
```
HTTP/1.1 101 
Switching Protocols Connection: Upgrade 
Upgrade: websocket 
Sec-WebSocket-Accept: 0FFP+2nmNIf/h+4BP36k9uzrYGk=
```
- Data xfer examples
	- `ws.send("Hello World!");`
	- `{"user":"Hal Pline","content":"I wanted to be a Playstation growing up, not a device to answer your inane questions"}`

##### Attacking
- Intercept with [[05 - Personal/Jonathan/Tools/Burpsuite|Burpsuite]] browser or proxy
- Use burp repeater to:
	- manually alter messages
	- Alter the handshake request
	- Create new sockets
	- Connect to an existing socket
	- Use the pencil icon in repeater next to the websocket ID to change channels
- Payloads:
	- WS message `{"message":"<img src=1 onerror='alert(1)'>"}`
	- 










WebSockets are a **communication protocol** that enables **full-duplex, real-time communication** between a client (typically a web browser) and a server over a single, long-lived connection. Unlike HTTP, which is **request-response based**, WebSockets allow **continuous two-way interaction** without the overhead of repeatedly opening and closing connections.

### 🔧 How WebSockets Work

1. **Handshake**: The client initiates a WebSocket connection by sending an HTTP request with an `Upgrade` header.
2. **Upgrade**: If the server supports WebSockets, it responds with a `101 Switching Protocols` status, upgrading the connection.
3. **Persistent Connection**: After the handshake, the connection stays open, allowing both client and server to send messages at any time.

### 📦 Key Features

- **Bi-directional**: Both client and server can send data independently.
- **Low latency**: Ideal for real-time applications like chat, gaming, live feeds.
- **Efficient**: Less overhead compared to HTTP polling or long-polling.

### 🧠 Use Cases

- **Chat applications**
- **Live sports scores**
- **Stock ticker updates**
- **Collaborative tools (e.g., Google Docs)**
- **Online gaming**

### 🧪 Example (JavaScript Client)

```javascript
const socket = new WebSocket("wss://example.com/socket");

socket.onopen = () => {
  console.log("Connected");
  socket.send("Hello Server!");
};

socket.onmessage = (event) => {
  console.log("Received:", event.data);
};

socket.onclose = () => {
  console.log("Disconnected");
};
```


Pentesting WebSockets involves assessing the security of applications that use the WebSocket protocol for real-time communication. Since WebSockets differ from traditional HTTP, they introduce unique attack surfaces and require specialized testing techniques.

---

### 🧪 Key Areas to Test in WebSocket Pentesting

#### 1. **Handshake & Protocol Upgrade**

- **Check for insecure upgrades**: Ensure the WebSocket handshake (`Upgrade: websocket`) is only allowed over HTTPS (`wss://`).
- **Header manipulation**: Try injecting or modifying headers during the handshake to bypass authentication or trigger unexpected behavior.

#### 2. **Authentication & Authorization**

- **Session handling**: Confirm that authentication tokens (e.g., cookies, JWTs) are properly validated during WebSocket communication.
- **Privilege escalation**: Test if users can access data or perform actions beyond their role by manipulating messages.

#### 3. **Message Tampering**

- **Replay attacks**: Resend previous messages to see if the server processes them again.
- **Message fuzzing**: Send malformed or unexpected payloads to test server robustness.
- **Injection attacks**: Try injecting SQL, XSS, or command payloads if the server parses WebSocket data into other systems.

#### 4. **Input Validation**

- **Client-side trust**: Ensure the server does not rely on client-side validation.
- **Boundary testing**: Send oversized payloads or unexpected data types.

#### 5. **Rate Limiting & DoS**

- **Flooding**: Send a high volume of messages to test for denial-of-service vulnerabilities.
- **Resource exhaustion**: Check if the server allocates excessive resources per connection.

#### 6. **Cross-Site WebSocket Hijacking (CSWSH)**

- **Origin header validation**: Ensure the server checks the `Origin` header to prevent unauthorized cross-origin connections.

#### 7. **Data Leakage**

- **Verbose error messages**: Look for stack traces or internal info in WebSocket responses.
- **Sensitive data exposure**: Monitor traffic for credentials, tokens, or PII.

---

### 🔧 Tools for WebSocket Pentesting

- **Burp Suite** (with WebSockets tab)
- **ZAP Proxy**
- **wscat** (CLI tool for manual interaction)
- **Postman** (WebSocket support in newer versions)
- **Custom scripts** using Python (`websocket-client`) or Node.js (`ws`)

---

### 🧠 Sample Attack Scenario

```
// Example of sending a crafted message via WebSocket
{
  "action": "deleteUser",
  "userId": "admin"
}
``
```