#IPMI #IntelligentPlatformManagementInterface
- [Intelligent Platform Management Interface](https://www.thomas-krenn.com/en/wiki/IPMI_Basics) (`IPMI`) is a set of standardized specifications for hardware-based host management systems used for system management and monitoring. It acts as an autonomous subsystem and works independently of the host's BIOS, CPU, firmware, and underlying operating system. IPMI provides sysadmins with the ability to manage and monitor systems even if they are powered off or in an unresponsive state. It operates using a direct network connection to the system's hardware and does not require access to the operating system via a login shell. IPMI can also be used for remote upgrades to systems without requiring physical access to the target host. IPMI is typically used in three ways:
	- Before the OS has booted to modify BIOS settings
	- When the host is fully powered down
	- Access to a host after a system failure
- Port 623 UDP
- Clients are called Baseboard Management Controllers or BMC
	- typically embedded ARM running linux
	- typically on motherboards but can be an add on
- More or less the same as physical access
- Sometimes may include a web GUI or remote command line via telnet or ssh
- HP iLO, Dell DRAC, Supermicro IPMI are common systems
- look for common or default credentials

Default user names

| Product         | Username      | Password                                                                  |
| --------------- | ------------- | ------------------------------------------------------------------------- |
| Dell iDRAC      | root          | calvin                                                                    |
| HP iLO          | Administrator | randomized 8-character string consisting of numbers and uppercase letters |
| Supermicro IPMI | ADMIN         | ADMIN                                                                     |
- IPMI sends a hash of user's password to the client before authentication, capture and crack
	- Can use metasploit to capture https://www.rapid7.com/db/modules/auxiliary/scanner/ipmi/ipmi_dumphashes/
- 



Attack with
- [[05 - Personal/Jonathan/Tools/NMAP|NMAP]] impi scripts
- [[metasploit]] aux scanners
- [[05 - Personal/Jonathan/Tools/Auth/hashcat]] mode 7300 for cracking found hashes
	- hashcat -m 7300 ipmi.txt -a 3 ?1?1?1?1?1?1?1?1 -1 ?d?u # for HPiLO default passwords