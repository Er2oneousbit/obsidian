#SMB #CFIS #ServerMessageBlock #Samba #CommonInternetFileSystem

- SMB is commonly used in Windows networks, and we will often find share folders in a Windows network. We can interact with SMB using the GUI, CLI, or tools. Let us cover some common ways of interacting with SMB using Windows & Linux.
	- **Windows**
		- [WINKEY] + [R] to open the Run dialog box 
		- Example path `\\192.168.220.129\Finance\`
		- Check for **guest** or **anonymous** access
		- `net use n: \\192.168.220.129\Finance` **map** a SMB share to a local drive `n:`
		- `net use n: \\192.168.220.129\Finance /user:plaintext Password123` **map** a SMB share with credentials
		- `dir n: /a-d /s /b | find /c ":\"` **count** files in `n:\` 
		- `dir n:\*cred* /s /b` **search** for `cred` files 
		- `findstr /s /i cred n:\*.*` **search** for `cred` files 
		- `Get-ChildItem \\192.168.220.129\Finance\`  **search** for files in **UNC** path
		- `New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem"` **powershell** to **map** the `finance` share
		- Script to **map** a drive with credentials
		```
		PS C:\htb> $username = 'plaintext'
		PS C:\htb> $password = 'Password123'
		PS C:\htb> $secpassword = ConvertTo-SecureString $password -AsPlainText -Force
		PS C:\htb> $cred = New-Object System.Management.Automation.PSCredential $username, $secpassword
		PS C:\htb> New-PSDrive -Name "N" -Root "\\192.168.220.129\Finance" -PSProvider "FileSystem" -Credential $cred
		```
		- `(Get-ChildItem -File -Recurse | Measure-Object).Count`  **count** how many files are in `n:\`
		- `Get-ChildItem -Recurse -Path N:\ -Include *cred* -File` **search** for `cred` files
	- **Linux**


#### **Versions**

|**SMB Version**|**Supported**|**Features**|
|---|---|---|
|CIFS|Windows NT 4.0|Communication via NetBIOS interface|
|SMB 1.0|Windows 2000|Direct connection via TCP|
|SMB 2.0|Windows Vista, Windows Server 2008|Performance upgrades, improved message signing, caching feature|
|SMB 2.1|Windows 7, Windows Server 2008 R2|Locking mechanisms|
|SMB 3.0|Windows 8, Windows Server 2012|Multichannel connections, end-to-end encryption, remote storage access|
|SMB 3.0.2|Windows 8.1, Windows Server 2012 R2||
|SMB 3.1.1|Windows 10, Windows Server 2016|Integrity checking, AES-128 encryption|

#### **Tools**
- [[05 - Personal/Jonathan/Tools/File Xfer/smbclient]] smbclient # main tool for connecting and interacting
- nmap scripts
- [[RPCclient]]
- [[05 - Personal/Jonathan/Tools/File Xfer/smbmap]]
- [[samrdump]]
- [[crackmapexec]]
- [[enum4linux]]
- [[05 - Personal/Jonathan/Tools/File Xfer/smbclient|smbclient]]


