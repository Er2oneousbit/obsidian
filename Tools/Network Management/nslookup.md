#nslookup #dns #dnsenum #dnsattack 

- Command line utility to query [[DNS]] server
	- `nslookup {FQDN}`
	- `nslookup -query=A {FQDN}`  look at A records only
	- `nslookup -query=ANY {FQDN}`  look at all records (may not work if banned)
	- `nslookup -query=TXT {FQDN}`  look at text records only
	- `nslookup -query=MX {FQDN}`  look at mail records only
	- `nslookup -query=PTR {IP}` reverse lookup
	- add name server after target FQDN