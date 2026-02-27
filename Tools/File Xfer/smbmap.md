#smbmap #smb #smbenum #smbattack

[GitHub - ShawnDEvans/smbmap: SMBMap is a handy SMB enumeration tool](https://github.com/ShawnDEvans/smbmap)

- `smbmap -H 10.129.14.128` list of smb shares
- `smbmap -H 10.129.14.128 -r notes` recursive search of a share
- `smbmap -H 10.129.14.128 --download "notes\note.txt"` copy file
- `smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"` send file
- `smbmap -R replication -h 10.129.14.128` list replication folder