#harvester #TheHarvester 

- https://github.com/laramies/theHarvester
- Automation on data gathering
```
Er2oneousbit@htb[/htb]$ export TARGET="facebook.com"
Er2oneousbit@htb[/htb]$ cat sources.txt | while read source; do theHarvester -d "${TARGET}" -b $source -f "${source}_${TARGET}";done
Er2oneousbit@htb[/htb]$ cat *.json | jq -r '.hosts[]' 2>/dev/null | cut -d':' -f 1 | sort -u > "${TARGET}_theHarvester.txt"
Er2oneousbit@htb[/htb]$ cat facebook.com_*.txt | sort -u > facebook.com_subdomains_passive.txt
Er2oneousbit@htb[/htb]$ cat facebook.com_subdomains_passive.txt | wc -l
```
