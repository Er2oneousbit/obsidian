#smbclient #smb #smbattack #smbenum

Connecting
- `smbclient –L \\\\$TIP` (List shares)
- `smbclient -N -L //10.129.14.128`  list shares with null session (no userid or pass)
- `smbclient -N //10.129.14.128/share`  connect to share with null session (no userid or pass)
- `smbclient //10.10.10.10/share`  connect to a share
- `smbclient //server/share --user {username}` connect as user
- `smbclient //server/share --user {username} {password}` connect as user and password
- `get {file}` get a file
- `!ls`  run ls on host system
- `smbstatus` get info on the smb session
- `smbclient //dc01/C$ -k -c ls -no-pass` this is using a kerberos ticket to do an `ls` on the `C$` share instead of a password