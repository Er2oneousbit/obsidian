#MSSQL #MicrosoftSQL 
- Microsofts SQL flavor
- Closed source software for windows operating systems only (originally) but now will run on OSX and Linux with .net
- Manage SQL services with SQL Server Management Studio or SSMS
	- This is a GUI way of managing the database and the data vs command line
	- Can be used on the SQL server or from a client

Databases:

| Default System Database | Description                                                                                                                                                                                            |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `master`                | Tracks all system information for an SQL server instance                                                                                                                                               |
| `model`                 | Template database that acts as a structure for every new database created. Any setting changed in the model database will be reflected in any new database created after changes to the model database |
| `msdb`                  | The SQL Server Agent uses this database to schedule jobs & alerts                                                                                                                                      |
| `tempdb`                | Stores temporary objects                                                                                                                                                                               |
| `resource`              | Read-only database containing system objects included with SQL server                                                                                                                                  |
- Default service account is NT Service\MSSQLESRVER
- Encryption is not enabled by default
- Authentication can be local to the server or via Windows authentication (which can be local windows or active directory)
- 

Things to look for
- Vulnerable SA
- System Execution
- SQL service OS admin
- Named pipes
- No encryption on connection

Attack With:
- mssql-cli
- SQL server powershell
- HeidiSQL
- SQLPro
- Impacket mssqleclient
- nmap --script ms-sql* (look up scripts and their args, some need auth/creds)
- metasploit mssql_ping
- 

Commands
- `select name from sys.databases` # list databases
- `SELECT TABLE_NAME FROM [<DATABASE_NAME>].INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'` # list tables in specific database
- 
