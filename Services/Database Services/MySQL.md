#MySQL #MariaDB

- Open source SQL database
- client server model
- MySQL server is the database management system
- Typically stored as .sql
- clients query and retrieve data from the SQL management system
- Works well for dynamic websites
- Typical usage is with LAMP stack (linux, apache, mysql, php) or LEMP (linux, nginx, mysql php)
- Sensitive data should be stored hashed or encrypted
- Clients could be vulnerable to SQL injection, which can run unexpected queries from MySQL
- SQL commands read, modify, or delete data in the database.  They also create or delete databases as well as change the structure of the database
- MariaDB is a fork of MySQL due to the main developer leaving Oracle
	- [MariaDB vs MySQL ‒ Key Differences, Pros and Cons, and More (hostinger.com)](https://www.hostinger.com/tutorials/mariadb-vs-mysql)
- Large and complex MySQL implementations can have misconfigurations or vulnerabilities
- Debug and sql_warning modes may lead to sensitive data leakage
- Usually runs on TCP 3306
- Look for accounts that do not have a password
- Commands

| **Command**                                          | **Description**                                                                                       |
| ---------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `mysql -u <user> -p<password> -h <IP address>`       | Connect to the MySQL server. There should **not** be a space between the '-p' flag, and the password. |
| `show databases;`                                    | Show all databases.                                                                                   |
| `use <database>;`                                    | Select one of the existing databases.                                                                 |
| `show tables;`                                       | Show all available tables in the selected database.                                                   |
| `show columns from <table>;`                         | Show all columns in the selected database.                                                            |
| `select * from <table>;`                             | Show everything in the desired table.                                                                 |
| `select * from <table> where <column> = "<string>";` |                                                                                                       |

- `sqsh -S 10.129.20.13 -U username -P Password123` **connect** to a mysql database with **linux** tool `sqsh` 
- `mysql -u username -pPassword123 -h 10.129.20.13` **connect** to a mysql database with **linux** tool `mysql` 
- `sqlcmd -S 10.129.20.13 -U username -P Password123` **connect** to a mysql database with **windows** tool `sqlcmd` 
- `mysql -u username -pPassword123 -h 10.129.20.13` **connect** to a mysql database with **windows** tool `mysql`