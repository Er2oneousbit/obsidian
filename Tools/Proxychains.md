#proxy #proxychains 
- Tool used to proxy network traffic from A to B then B to C as to act like A is talking to C directly when normally A cannot talk to C
- [GitHub - haad/proxychains: proxychains - a tool that forces any TCP connection made by any given application to follow through proxy like TOR or any other SOCKS4, SOCKS5 or HTTP(S) proxy. Supported auth-types: "user/pass" for SOCKS4/5, "basic" for HTTP.](https://github.com/haad/proxychains)
- Must turn on or configure proxychains prior to its use
- `cat /etc/proxychains.conf`
- ```[ProxyList]
	socks5 127.0.0.1 1080``` IP and Port of proxy entrance 
