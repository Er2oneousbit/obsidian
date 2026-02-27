#Oracle #OracleTNS #OracleTransparentNetworkSubstrate

- Oracle Transparent Network Substrate - Oracle database client communication protocol
- Part of the Oracle Net Services suite
- Supports IPX,SPX,TCP/IP, IPv6, Appletalk, TLS
- Native support for Oracle 8/9 
- Default configuration has basic authentication set
	- authorized hosts, IPs, username/password
- Listener is configured by tnsnames.ora and listener.ora found in {App Root}/network/admin
	- files contain configuration 
	- the client-side Oracle Net Services software uses the `tnsnames.ora` file to resolve service names to network addresses, while the listener process uses the `listener.ora` file to determine the services it should listen to and the behavior of the listener.
- Ports TCP 1521
- Oracle databases can be protected by using so-called PL/SQL Exclusion List (`PlsqlExclusionList`). It is a user-created text file that needs to be placed in the `$ORACLE_HOME/sqldeveloper` directory, and it contains the names of PL/SQL packages or types that should be excluded from execution. Once the PL/SQL Exclusion List file is created, it can be loaded into the database instance. It serves as a blacklist that cannot be accessed through the Oracle Application Server.
- Oracle System Identifier (SID) is a unique name that identifies a particular database instance
	- part of the auth process, cannot connect without it
	- SID brute force with NMAP script oracle-sid-brute or odat.py _all_ param
- Look for users that may have admin or can elevate to the admin account (like a runas or sudo)
- Attempt to read password from sys.user attempt to crack
	- [[05 - Personal/Jonathan/Tools/Auth/hashcat]] - https://hashcat.net/wiki/doku.php?id=example_hashes
	- [[john the ripper]]  - [John The Ripper Hash Formats | pentestmonkey](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)
- Attempt uploading a webshell if server has a webserver with odat.py


|**Setting**|**Description**|
|---|---|
|`DESCRIPTION`|A descriptor that provides a name for the database and its connection type.|
|`ADDRESS`|The network address of the database, which includes the hostname and port number.|
|`PROTOCOL`|The network protocol used for communication with the server|
|`PORT`|The port number used for communication with the server|
|`CONNECT_DATA`|Specifies the attributes of the connection, such as the service name or SID, protocol, and database instance identifier.|
|`INSTANCE_NAME`|The name of the database instance the client wants to connect.|
|`SERVICE_NAME`|The name of the service that the client wants to connect to.|
|`SERVER`|The type of server used for the database connection, such as dedicated or shared.|
|`USER`|The username used to authenticate with the database server.|
|`PASSWORD`|The password used to authenticate with the database server.|
|`SECURITY`|The type of security for the connection.|
|`VALIDATE_CERT`|Whether to validate the certificate using SSL/TLS.|
|`SSL_VERSION`|The version of SSL/TLS to use for the connection.|
|`CONNECT_TIMEOUT`|The time limit in seconds for the client to establish a connection to the database.|
|`RECEIVE_TIMEOUT`|The time limit in seconds for the client to receive a response from the database.|
|`SEND_TIMEOUT`|The time limit in seconds for the client to send a request to the database.|
|`SQLNET.EXPIRE_TIME`|The time limit in seconds for the client to detect a connection has failed.|
|`TRACE_LEVEL`|The level of tracing for the database connection.|
|`TRACE_DIRECTORY`|The directory where the trace files are stored.|
|`TRACE_FILE_NAME`|The name of the trace file.|
|`LOG_FILE`|The file where the log information is stored.|
Attack with
- [[odat.py]]
	- `./odat.py all -s 10.129.204.235`
- [[05 - Personal/Jonathan/Tools/NMAP|NMAP]] oracle scripts
- [[SQLplus]]
	- sqlplus scott/tiger@10.129.205.19/XE as sysdba
	- sqlplus scott/tiger@10.129.205.19/XEXDB
	- SELECT owner, table_name  FROM dba_tables;
	- SELECT owner, table_name  FROM all_tables;
- 


```bash
#!/bin/bash

sudo apt-get install libaio1 python3-dev alien -y
git clone https://github.com/quentinhardy/odat.git
cd odat/
git submodule init
git submodule update
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-basic-linux.x64-21.12.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/2112000/instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
unzip instantclient-sqlplus-linux.x64-21.12.0.0.0dbru.zip
export LD_LIBRARY_PATH=instantclient_21_12:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
pip3 install cx_Oracle
sudo apt-get install python3-scapy -y
sudo pip3 install colorlog termcolor passlib python-libnmap
sudo apt-get install build-essential libgmp-dev -y
pip3 install pycryptodome
```
