#netsh #CMD 

- Windows command line for network configuration
	- `Finding routes`
	- `Viewing the firewall configuration`
	- `Adding proxies`
	- `Creating port forwarding rules`
- [Netsh Command Syntax, Contexts, and Formatting | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/networking/technologies/netsh/netsh-contexts)
- `netsh trace start persistent=yes capture=yes tracefile=c:\temp\phonecall.etl` netsh packet capture to file
- `netsh.exe interface portproxy add v4tov4 listenport=8080 listenaddress=10.129.15.150 connectport=3389 connectaddress=172.16.5.25` Port Forwarding with Windows Netsh
- `netsh.exe interface portproxy show v4tov4`