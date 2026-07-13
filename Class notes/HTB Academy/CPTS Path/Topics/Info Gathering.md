#enumeration #informationgathering
- The [information gathering](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/01-Information_Gathering/README) phase is the first step in every penetration test where we need to simulate external attackers without internal information from the target organization. This phase is crucial as poor and rushed information gathering could result in missing flaws that otherwise thorough enumeration would have uncovered.
- Information gathering is typically an iterative process. As assets are discovered they will need to be enumerated.
 ![[image-20240607143008051-_Info Gathering.png]]
- Information should be well organized.
- Create your own methodology and its OK to borrow from others
- Create your own information gathering/enumeration scripts and its OK to borrow others (with permission from author)

|**Category**   | **Description**                                                                                                                                                                                                                                                                                                                                                                                                                             |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Passive information gathering` | We do not interact directly with the target at this stage. Instead, we collect publicly available information using search engines, whois, certificate information, etc. The goal is to obtain as much information as possible to use as inputs to the active information gathering phase.                                                                                                                                              |
| `Active information gathering`  | We directly interact with the target at this stage. Before performing active information gathering, we need to ensure we have the required authorization to test. Otherwise, we will likely be engaging in illegal activities. Some of the techniques used in the active information gathering stage include port scanning, DNS enumeration, directory brute-forcing, virtual host enumeration, and web application crawling/spidering. |

|**Area**|**Description**|
|---|---|
|`Domains and Subdomains`|Often, we are given a single domain or perhaps a list of domains and subdomains that belong to an organization. Many organizations do not have an accurate asset inventory and may have forgotten both domains and subdomains exposed externally. This is an essential part of the reconnaissance phase. We may come across various subdomains that map back to in-scope IP addresses, increasing the overall attack surface of our engagement (or bug bounty program). Hidden and forgotten subdomains may have old/vulnerable versions of applications or dev versions with additional functionality (a Python debugging console, for example). Bug bounty programs will often set the scope as something such as `*.inlanefreight.com`, meaning that all subdomains of `inlanefreight.com`, in this example, are in-scope (i.e., `acme.inlanefreight.com`, `admin.inlanefreight.com`, and so forth and so on). We may also discover subdomains of subdomains. For example, let's assume we discover something along the lines of `admin.inlanefreight.com`. We could then run further subdomain enumeration against this subdomain and perhaps find `dev.admin.inlanefreight.com` as a very enticing target. There are many ways to find subdomains (both passively and actively) which we will cover later in this module.|
|`IP ranges`|Unless we are constrained to a very specific scope, we want to find out as much about our target as possible. Finding additional IP ranges owned by our target may lead to discovering other domains and subdomains and open up our possible attack surface even wider.|
|`Infrastructure`|We want to learn as much about our target as possible. We need to know what technology stacks our target is using. Are their applications all ASP.NET? Do they use Django, PHP, Flask, etc.? What type(s) of APIs/web services are in use? Are they using Content Management Systems (CMS) such as WordPress, Joomla, Drupal, or DotNetNuke, which have their own types of vulnerabilities and misconfigurations that we may encounter? We also care about the web servers in use, such as IIS, Nginx, Apache, and the version numbers. If our target is running outdated frameworks or web servers, we want to dig deeper into the associated web applications. We are also interested in the types of back-end databases in use (MSSQL, MySQL, PostgreSQL, SQLite, Oracle, etc.) as this will give us an indication of the types of attacks we may be able to perform.|
|`Virtual Hosts`|Lastly, we want to enumerate virtual hosts (vhosts), which are similar to subdomains but indicate that an organization is hosting multiple applications on the same web server. We will cover vhost enumeration later in the module as well.|

### DNS Enumeration
- zone transfers
	- [[dig]]
- Tools
	- `for sub in $(cat /opt/useful/SecLists/Discovery/DNS/subdomains-top1million-110000.txt);do dig $sub.inlanefreight.htb @10.129.14.128 | grep -v ';\|SOA' | sed -r '/^\s*$/d' | grep $sub | tee -a subdomains.txt;done`
	- [[gobuster]]
	- [[The Harvester]] 
- Sites 
	- https://www.virustotal.com/ may have subdomains collected by IP
	- [DNSDumpster.com - dns recon and research, find and lookup dns records](https://dnsdumpster.com/)
	- [crt.sh | Certificate Search](https://crt.sh/)
	- [Censys Search](https://search.censys.io/)


### Infrastructure - Web
- https://sitereport.netcraft.com meta data about a site/URL
- http://web.archive.org/ find historical copies of a site
- https://facebook.com find public information
- https://linkedin.com find public information
- IIS to Windows Version
	- IIS 6.0: Windows Server 2003
	- IIS 7.0-8.5: Windows Server 2008 / Windows Server 2008R2
	- IIS 10.0 (v1607-v1709): Windows Server 2016
	- IIS 10.0 (v1809-): Windows Server 2019
- Linux and other web servers can be a hodgepodge 
- IDS/IDP may interfere with fingerprinting
- Review HTTP headers and cookies
- [[whatweb]] to fingerprint tech stack
- [[wappalyzer]] to fingerprint tech stack
- [[WafWoof]] to fingerprint WAFs
- [[aquatone]] to screenshot and enumeration websites

### Active Subdomain Enumeration
- see [[DNS]]
- [Zone Transfer Test Online | HackerTarget.com](https://hackertarget.com/zone-transfer/) Zonetransfers
- [[dig]]
- [[dnsenum]]
- [[nslookup]]
- [[gobuster]]

### Virtual Hosts
- A virtual host (`vHost`) is a feature that allows several websites to be hosted on a single server.
- Types of hosting
	- `IP`-based virtual hosting
		- server has multiple IPs assigned to it and the IPs correspond to different web sites
	- `Name`-based virtual hosting
		- can have the same IP but are seen as different web servers
		- can be actual different servers behind a proxy or LB
- Can be filtered by HTTP Host header
- Abuse
	- cURL with different host headers
		- `cat ./vhosts | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********";curl -s -I http://192.168.10.10 -H "HOST: ${vhost}.randomtarget.com" | grep "Content-Length: ";done` cat a list of hosts and fuzz in the host header
		- `cat /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | while read vhost;do echo "\n********\nFUZZING: ${vhost}\n********" | tee -a fuzz.results;curl  -s http://10.129.252.205 -H "HOST: ${vhost}.inlanefreight.htb" | grep "HTB" | tee -a fuzz.results;done;` cat a seclist of subdomains then search the body for HTB.  Output results to file.
	- [[ffuf]]

### Web Crawling
- [[ZAP]] can spider web directories
- [[gobuster]] brute force web directories
- [[ffuf]] brute force files and directories
- Use wordlists from [[seclist]]
	- `/usr/share/seclists/Discovery/Web-Content/raft*`
- Create custom wordlists with [[CeWL]]
- Look for sensitive information during crawling/bruteforcing
- robots.txt 
- look for \.well-known\ [Well-Known URIs (iana.org)](https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml)

### Google Dorks
- [Google Hacking Database (GHDB) - Google Dorks, OSINT, Recon (exploit-db.com)](https://www.exploit-db.com/google-hacking-database)

|**Operator**|**Operator Description**|**Example**|**Example Description**|
|:--|:--|:--|:--|
|`site:`|Limits results to a specific website or domain.|`site:example.com`|Find all publicly accessible pages on example.com.|
|`inurl:`|Finds pages with a specific term in the URL.|`inurl:login`|Search for login pages on any website.|
|`filetype:`|Searches for files of a particular type.|`filetype:pdf`|Find downloadable PDF documents.|
|`intitle:`|Finds pages with a specific term in the title.|`intitle:"confidential report"`|Look for documents titled "confidential report" or similar variations.|
|`intext:` or `inbody:`|Searches for a term within the body text of pages.|`intext:"password reset"`|Identify webpages containing the term “password reset”.|
|`cache:`|Displays the cached version of a webpage (if available).|`cache:example.com`|View the cached version of example.com to see its previous content.|
|`link:`|Finds pages that link to a specific webpage.|`link:example.com`|Identify websites linking to example.com.|
|`related:`|Finds websites related to a specific webpage.|`related:example.com`|Discover websites similar to example.com.|
|`info:`|Provides a summary of information about a webpage.|`info:example.com`|Get basic details about example.com, such as its title and description.|
|`define:`|Provides definitions of a word or phrase.|`define:phishing`|Get a definition of "phishing" from various sources.|
|`numrange:`|Searches for numbers within a specific range.|`site:example.com numrange:1000-2000`|Find pages on example.com containing numbers between 1000 and 2000.|
|`allintext:`|Finds pages containing all specified words in the body text.|`allintext:admin password reset`|Search for pages containing both "admin" and "password reset" in the body text.|
|`allinurl:`|Finds pages containing all specified words in the URL.|`allinurl:admin panel`|Look for pages with "admin" and "panel" in the URL.|
|`allintitle:`|Finds pages containing all specified words in the title.|`allintitle:confidential report 2023`|Search for pages with "confidential," "report," and "2023" in the title.|
|`AND`|Narrows results by requiring all terms to be present.|`site:example.com AND (inurl:admin OR inurl:login)`|Find admin or login pages specifically on example.com.|
|`OR`|Broadens results by including pages with any of the terms.|`"linux" OR "ubuntu" OR "debian"`|Search for webpages mentioning Linux, Ubuntu, or Debian.|
|`NOT`|Excludes results containing the specified term.|`site:bank.com NOT inurl:login`|Find pages on bank.com excluding login pages.|
|`*` (wildcard)|Represents any character or word.|`site:socialnetwork.com filetype:pdf user* manual`|Search for user manuals (user guide, user handbook) in PDF format on socialnetwork.com.|
|`..` (range search)|Finds results within a specified numerical range.|`site:ecommerce.com "price" 100..500`|Look for products priced between 100 and 500 on an e-commerce website.|
|`" "` (quotation marks)|Searches for exact phrases.|`"information security policy"`|Find documents mentioning the exact phrase "information security policy".|
|`-` (minus sign)|Excludes terms from the search results.|`site:news.com -inurl:sports`|Search for news articles on news.com excluding sports-related content.|
- Finding Login Pages:
    - `site:example.com inurl:login`
    - `site:example.com (inurl:login OR inurl:admin)`
- Identifying Exposed Files:
    - `site:example.com filetype:pdf`
    - `site:example.com (filetype:xls OR filetype:docx)`
- Uncovering Configuration Files:
    - `site:example.com inurl:config.php`
    - `site:example.com (ext:conf OR ext:cnf)` (searches for extensions commonly used for configuration files)
- Locating Database Backups:
    - `site:example.com inurl:backup`
    - `site:example.com filetype:sql`


### FTP 
- [[FTP]]

### SQL
- User enumeration
	- `EXEC sp_change_users_login @Action='Report';`

### Recon Automation
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon): A Python-based reconnaissance tool offering a range of modules for different tasks like SSL certificate checking, Whois information gathering, header analysis, and crawling. Its modular structure enables easy customisation for specific needs.
- [Recon-ng](https://github.com/lanmaster53/recon-ng): A powerful framework written in Python that offers a modular structure with various modules for different reconnaissance tasks. It can perform DNS enumeration, subdomain discovery, port scanning, web crawling, and even exploit known vulnerabilities.
- [theHarvester](https://github.com/laramies/theHarvester): Specifically designed for gathering email addresses, subdomains, hosts, employee names, open ports, and banners from different public sources like search engines, PGP key servers, and the SHODAN database. It is a command-line tool written in Python.
- [SpiderFoot](https://github.com/smicallef/spiderfoot): An open-source intelligence automation tool that integrates with various data sources to collect information about a target, including IP addresses, domain names, email addresses, and social media profiles. It can perform DNS lookups, web crawling, port scanning, and more.
- [OSINT Framework](https://osintframework.com/): A collection of various tools and resources for open-source intelligence gathering. It covers a wide range of information sources, including social media, search engines, public records, and more.

### Tools and Tricks
- [[05 - Personal/Jonathan/Tools/NMAP|NMAP]]
    - Finding an usual port, think of any other ports that looks the same. Such as port 6521 is like port 21, try FTP then.
    - nmap --min-rtt-timeout changes the probe run trip time
    - Try different scripts, look for ones that relate to identified service/port/OS
- [[WHOIS]] # find information about domain registration
- https://www.virustotal.com/ May contain data such as URLs and IPs
- [[eyewitness]]
- [[whatweb]]
- [[Netcat]]
- [[telnet]]
- check out certs
- View robots.txt
- view source code
- Vuln research
	- searchsploit
	- exploitdb
	- vulnerability lab
	- rapid7 DB
	- metasploit search and scanners
- Common services
    - [[SSH]]
        - banner grab - find vulns
    - [[FTP]]
        - banner grab - find vulns
        - open FTP
        - dir traversal
    - [[SMB]]
        - guest access
        - Old vuln versions
        - look for non standard shares
            - try no creds or discovered creds
    - [[SNMP]]
        - [[snmpwalk]]
        - [[onesixtyone]]
- Our goal is not to get at the systems but to find all the ways to get there.
	- What can we see?
	- What reasons can we have for seeing it?
	- What image does what we see create for us?
	- What do we gain from it?
	- How can we use it?
	- What can we not see?
	- What reasons can there be that we do not see?
	- What image results for us from what we do not see?
	- [enum-method3.png (2622×1474) (hackthebox.com)](https://academy.hackthebox.com/storage/modules/112/enum-method3.png)
- Check out domain certs https://crt.sh/
- Cloud enumeration
	- https://domain.glass/
	- https://buckets.grayhatwarfare.com/
- Research for CVEs or PoCs

| **Tool**     | **Description**                                                                                                       | **Features**                                                                                        |
| ------------ | --------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `Wappalyzer` | Browser extension and online service for website technology profiling.                                                | Identifies a wide range of web technologies, including CMSs, frameworks, analytics tools, and more. |
| `BuiltWith`  | Web technology profiler that provides detailed reports on a website's technology stack.                               | Offers both free and paid plans with varying levels of detail.                                      |
| `WhatWeb`    | Command-line tool for website fingerprinting.                                                                         | Uses a vast database of signatures to identify various web technologies.                            |
| `Nmap`       | Versatile network scanner that can be used for various reconnaissance tasks, including service and OS fingerprinting. | Can be used with scripts (NSE) to perform more specialised fingerprinting.                          |
| `Netcraft`   | Offers a range of web security services, including website fingerprinting and security reporting.                     | Provides detailed reports on a website's technology, hosting provider, and security posture.        |
| `wafw00f`    | Command-line tool specifically designed for identifying Web Application Firewalls (WAFs).                             | Helps determine if a WAF is present and, if so, its type and configuration.                         |

