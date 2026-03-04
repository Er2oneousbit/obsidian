#gobuster #directoryenumeration #webenumeration #dnsenumeration #fuzzing

- [GitHub - OJ/gobuster: Directory/File, DNS and VHost busting tool written in Go](https://github.com/OJ/gobuster)
- bruteforce enumeration tool
- Pairs nicely with wordlists from [[seclist]]
- Gobuster can be used to enumerate over patterns:
```shell-session
	lert-api-shv-{GOBUSTER}-sin6
	atlas-pp-shv-{GOBUSTER}-sin6
	
	Er2oneousbit@htb[/htb]$ export TARGET="facebook.com"
	Er2oneousbit@htb[/htb]$ export NS="d.ns.facebook.com"
	Er2oneousbit@htb[/htb]$ export WORDLIST="numbers.txt"
	Er2oneousbit@htb[/htb]$ gobuster dns -q -r "${NS}" -d "${TARGET}" -w "${WORDLIST}" -p ./patterns.txt -o "gobuster_${TARGET}.txt"
```



- `dns`: Launch the DNS module
	- `-q`: Don't print the banner and other noise.
	- `-r`: Use custom DNS server
	- `-d`: A target domain name
	- `-p`: Path to the patterns file
	- `-w`: Path to the wordlist
	- `-o`: Output file

- `dir` the directory module
	- `gobuster dir -u http://83.136.251.68:35479/ -w /opt/useful/seclists/Discovery/Web-Content/directory-list-2.3-small.txt` 