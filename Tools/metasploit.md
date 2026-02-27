#msfconsole #metasploit #MSFVenom #shells #webshells #webenumeration #payloads 

Open source framework that is a collection of various scripts, applications, or modules to enumerate or exploit targets

Meterpreter 
- built in persistence
- can use plugins to expand functionality


Payloads
- Stageless/singles - sends everything at once
- Staged - broken into parts
	- exploit - only the code needed to exploit a vuln
	- stage 0 - starts the initial connection
	- stage 1 - the larger payload to create the session
		- meterpreter payload relies on DLL injection and runs in memory


Location
- `ls /usr/share/metasploit-framework/`

Commands
- `msfconsole`  basic start up command
- `sudo msfdb init` create a metasploit database
- `sudo msfdb status` check database status
- `sudo msfdb run` connect to database
- ``` msfdb reinit
	cp /usr/share/metasploit-framework/config/database.yml ~/.msf4/
	sudo service postgresql restart
	msfconsole -q``` recreate the database 
- `workspace` display what workspace in use
	- `workspace test1` switch to test1 workspace
	- `workspace -a test1` add test1 workspace
	- `workspace -d test1` delete test1 workspace
- `db_import nmapscan.xml` import nmap scan XML format
- `db_nmap` run nmap inside msf and store results
	- `db_nmap -sV -p- -T5 -A 10.10.10.15` example scan, results stored in DB.  Can use `hosts` or `services` to see results
- `db_export -f xml backup.xml` copy database to xml file
- `hosts` list of stored hosts
- `services` list of stored services
- `creds` list of stored creds
- `loot` list of collected loot
- `load {plugin}` load a plugin
- `sessions` list all the sessions
	- `sessions -i 1` interact with session 1
- `jobs -l` list all running jobs
	- `jobs -k 1` kill job 1
- `hashdump` or `lsa_dump_samlsa_dump_sam` grap SAM hashes in windows session
- `lsa_dump_secrets`

Searching
- `search cve:2009 type:exploit
- `search cve:2009 type:exploit platform:-linux
- `search cve:2009 -s name
-  `search type:exploit -s type -r
- `search type:exploit platform:windows cve:2021 rank:excellent microsoft`
- `grep meterpreter show payloads` list all the payloads and find ones that are meterpreter based
	- `grep -c meterpreter show payloads` line count of records found
- `grep meterpreter grep reverse_tcp show payloads` find meterpreter payloads that use reverse TCP connection
	- `grep -c meterpreter grep reverse_tcp show payloads` line count of records found
- `search local_exploit_suggester` post exploit, use the local exploit suggester module

-  Modules
	- `<No.> <type>/<os>/<service>/<name>`
	- `679  exploit/windows/ftp/scriptftp_list`
- Module information
	- `show options` the options to set for the module/payload
	- `show info` a full description of the module
	- `show targets` list of different kinds of targets, like different versions
	- `show payloads` list of payloads a module can use
	- `show encoder` list the available encoders for the payload
- Configure modules
	- `set RHOSTS 10.10.10.40` set the target IP/FQDN
	- `set LHOSTS 123.456.78.90` set the local IP 
	- `setg RHOSTS 12.123.123.32` set the target globally
	- `set target 3` use the 3rd target in the target list
	- `help` list the commands that can be used
- Execution
	- `run -j` run as a job in the background
	- `exploit` alias for run, single time use without -j


Post exploit
- `steal_token 1836` try to steal the user account running for process 1836
- `search local exploit suggester` have meterpreter session guess what might privesc
	- `set session 2` some modules require the specification of an open session
	- configure/run post exploit module just like exploit modules


Custom Modules
- Copy rb file to the /usr/share/metasploit-framework directory while matching the folder structure of the type of module 
	- `/usr/share/metasploit-framework/modules/exploits/unix/webapp/nagios3_command_injection.rb` example of a linux webapp exploit
	- alternatively there may be a ~/.msf4 folder that is symlinked to the actual metasploit module folder.  Same rule applies for folder structure
	- must be in snake case, `some_module.rb`
- `msfconsole -m /usr/share/metasploit-framework/modules/` reload the modules 
	- `reload_all` alternative command inside msfconsole
- generic rb payloads potentially can be ported as a metasploit module
	- `cp ~/Downloads/48746.rb /usr/share/metasploit-framework/modules/exploits/linux/http/bludit_auth_bruteforce_mitigation_bypass.rb` copy ruby script to the appropriate metasploit folder
	- copy the necessary code from a similar module and paste it into rb file to port
		- all the necessary includes
		- customize the info section
		- customize the options section

- #handlers 
	- `use multi/handler` sort of a swiss army knife jack of all trades generic handler