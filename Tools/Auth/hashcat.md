#hashcat #passwordcracking #auth #hash

- A password cracking tool
- [hashcat - advanced password recovery](https://hashcat.net/hashcat/)
- [example_hashes [hashcat wiki]](https://hashcat.net/wiki/doku.php?id=example_hashes)



- Rules can be used to mutate passwords in a list on the fly
	- [GitHub - NotSoSecure/password_cracking_rules: One rule to crack all passwords. or atleast we hope so.](https://github.com/NotSoSecure/password_cracking_rules)
	- `/usr/share/hashcat/rules/` location of hashcat rules
	- `best64.rule` most common built in rule
- `hashcat --force password.list -r custom.rule --stdout | sort -u > mut_password.list` Create a list with mutation rules
	- `sed -ri '/^.{,9}$/d' mut_password.list` strip 9 char and lower from file
	- `head -7000 mut_password.list | shortend.list` first 7000 lines into a file
- `hashcat -a 0 -m 0 1b0556a75770563578569ae21392630c /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule` dictionary attack with rules against a MD5 hash
- `hashcat -a 3 -m 0 1e293d6912d074c0fd15844d803400dd '?u?l?l?l?l?d?s'` masked attack against a MD5 hash

|**Function**|**Description**|
|---|---|
|`:`|Do nothing.|
|`l`|Lowercase all letters.|
|`u`|Uppercase all letters.|
|`c`|Capitalize the first letter and lowercase others.|
|`sXY`|Replace all instances of X with Y.|
|`$!`|Add the exclamation character at the end.|
