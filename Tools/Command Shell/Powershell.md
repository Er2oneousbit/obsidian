#powershell #windows #scripting #commandline

- `cat {file} | base64 -w 0;echo` b64 encode a file
- `PS [IO.File]::WriteAllBytes("{Filelocation\filename}",{B64 string}"))` convert b64 to a file
`