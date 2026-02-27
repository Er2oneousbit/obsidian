#rservices #remotemanagement #remotecommands #remoteaccess
- R-Services are a suite of services hosted to enable remote access or issue commands between Unix hosts over TCP/IP.
- Ports 512,513,514
- Usually seen with Unix systems
- /etc/hosts.equiv list of trusted hosts # host username
- Uses PAM for authentication # https://debathena.mit.edu/trac/wiki/PAM
- Commands

|**Command**|**Service Daemon**|**Port**|**Transport Protocol**|**Description**|
|---|---|---|---|---|
|`rcp`|`rshd`|514|TCP|Copy a file or directory bidirectionally from the local system to the remote system (or vice versa) or from one remote system to another. It works like the `cp` command on Linux but provides `no warning to the user for overwriting existing files on a system`.|
|`rsh`|`rshd`|514|TCP|Opens a shell on a remote machine without a login procedure. Relies upon the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files for validation.|
|`rexec`|`rexecd`|512|TCP|Enables a user to run shell commands on a remote machine. Requires authentication through the use of a `username` and `password` through an unencrypted network socket. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
|`rlogin`|`rlogind`|513|TCP|Enables a user to log in to a remote host over the network. It works similarly to `telnet` but can only connect to Unix-like hosts. Authentication is overridden by the trusted entries in the `/etc/hosts.equiv` and `.rhosts` files.|
- Abuse with
	- nmap scripts
	- bypass auth by editing hosts.equiv and .rhosts
		- spoof or steal trusted hostname or IP
	- look for common passwords or reuse