#aquatone #webenumeration #web

#update
- https://github.com/michenriksen/aquatone
- New version - [aquatone](https://github.com/shelld3v/aquatone)
- automatic and visual inspection of websites across many hosts
```
Er2oneousbit@htb[/htb]$ sudo apt install golang chromium-driver
Er2oneousbit@htb[/htb]$ go install github.com/michenriksen/aquatone@latest
Er2oneousbit@htb[/htb]$ export PATH="$PATH":"$HOME/go/bin"
```
- `cat facebook_aquatone.txt | aquatone -out ./aquatone -screenshot-timeout 1000` cat a subdomain list and pipe to aquatone for enumeration and screenshots