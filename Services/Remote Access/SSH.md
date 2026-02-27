#SSH #SecureShell #remoteaccess 

- Secure Shell (SSH) enables two computers to establish an encrypted and direct connection
- Port TCP 22
- Target requires SSH server running, typically OpenBSD SSH
- SSH-1 and SSH-2 whereas SSH-2 is more advanced and more secure than SSH-1 (SSH-1 has a MITM vuln)
- OpenSSH Auth Methods
	- Password authentication
		- Server sends cert to client to verify correct server is being connected to
		- Client sends a known password, which is sent as a hash to the server
	- Public-key authentication
		- Server sends cert to client to verify correct server is being connected to
		- Client sends a private key to server, server matches it to the corresponding public key that it has stored
		- 
	- Host-based authentication
	- Keyboard authentication
	- Challenge-response authentication
	- GSSAPI authentication
- Check sshd_config file
Dangerous settings

|**Setting**|**Description**|
|---|---|
|`PasswordAuthentication yes`|Allows password-based authentication.|
|`PermitEmptyPasswords yes`|Allows the use of empty passwords.|
|`PermitRootLogin yes`|Allows to log in as the root user.|
|`Protocol 1`|Uses an outdated version of encryption.|
|`X11Forwarding yes`|Allows X11 forwarding for GUI applications.|
|`AllowTcpForwarding yes`|Allows forwarding of TCP ports.|
|`PermitTunnel`|Allows tunneling.|
|`DebianBanner yes`|Displays a specific banner when logging in.|



Attack with
- [[ssh audit]] 
- nmap scripts
- look for vulns for identified version
- attempt different auth methods
	- `ssh -v cry0l1t3@10.129.14.132 -o PreferredAuthentications=password`
- brute force logins like [[Hydra]]
- 