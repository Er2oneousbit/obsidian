#dig #dns #dnsattack

DNS tool
- `dig {FQDN} @{Name Server IP or FQDN}` generic lookup
- `dig a {FQDN} @{Name Server IP or FQDN}` look at A records
- `dig txt {FQDN} @{Name Server IP or FQDN}` look at text records
- `dig mx {FQDN} @{Name Server IP or FQDN}` look at mail records
- `dig -x {IP} @{Name Server IP or FQDN}` reverse lookup
- `dig soa {FQDN}`  start of authority lookup
- `dig ns {FQDN} @{Name Server IP or FQDN}`  specific nameserver lookup @ symbol for specific host
- `dig CH TXT version.bind {FQDN}`  chaos and text query
- `dig any {FQDN} @{Name Server IP or FQDN}`  show all records that a specific nameserver has (may not work if banned)
- `dig axfr {FQDN} @{Name Server IP or FQDN}`  zone transfer from specific nameserver
- `dig +noall +answer +multiline`  this will return just the records and 1 per line
- `dig +nocmd`  cuts out some of the verbose output
- +short only the IPs
- 