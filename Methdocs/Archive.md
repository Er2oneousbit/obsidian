# Scope/Host Data

---

# Remote Enumeration Phase

---

## Network Scans

- ### Nmap
    
    - `nmap -O -oA NMAP/OSDetect $TIP`
    - `nmap -T4 -p- -oA NMAP/allTCPports $TIP` (All ports fast)
    - `nmap -T4 -pXX -A -sV -oA NMAP/refinedTCPports $TIP` (Specific ports full analysis)
    - `nmap -T4 -sU -oA NMAP/topUDPports $TIP` (Scan all UDP ports)
    - `Change source - nmap -sS --source-port XX -p XX -oA NMAP/SpoofedSrcPort $TIP` (Change source port)
    - Scripts
- ### Masscan
    
    - All ports
    - Found ports
- ### Arp-scan
    
    - `arp-scan -l` - arp request entire subnet IP list
    - `arp-scan -r -l` - randomize arp reques
- ### Fping
    
    - `fping -a -g -q $TIP`
    - B
- ### Hping3
    
    - `hping3 $TIP -S --scan known`
    - `hping3 -S $TIP`
    - `hping3 -S -s 53 -p 53 -k $TIP` (change source port)

---

## FileShare

- ### Enum4liux
    
    - `enum4linux –a $TIP` (All options)
    - Other
- ### RDP
    
    - A
    - B
- ### NETBIOS
    
    - A
    - B
- ### SNMP
    
    - A
    - B
- ### FTP
    
- ### NFS
    
    - `showmount -e $TIP`
- ### Other
    

---

## Web Enum

- ### WEB Scan
    
    - Dirbuster
    - ffuf
    - Dirb
    - Gobuster
        - `gobuster dir -u http://$TIP -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -o gobuster.result`
    - Davtest
    - Nikto
        - `nikto -host http://$TIP`
    - AssetFinder
    - Amass
    - Httprobe
    - GoWtiness
- ### SSTI, XXE, JWT. CSRF
    
    - tqlmap for SSTI
- ### XXS
    
    - Polygot
        - ``jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */onerror=alert('THM') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert('THM')//>\x3e``

---

## Vuln Scanns

- ### Windows
    
    - Winpeas
    - Sherlock
    - Windows Exploit Suggestor
    - Other
- ### Linux
    
    - LinEnum
    - Linpeas
    - Other
- ### Web Vulns
    
    - Nikto
    - SQLMap
    - Other
- ### Active Directory
    
    - GPP - Group Policy Preferences
    - Kerberoasting
        - Golden ticket
        - B
    - PowerView

---

# Exploitation Phase

- ## SQLMAP
    
- ## B
    

---

# Local Enum Phase

- ## PrivEsc Enum
    
    - ### Windows
        
        - Unquoeted Service Paths
            - Empire/Powersploit Power Up
        - DLL Hijacking
            - Missing DLLs
            - Search order
            - Replace DLLs
        - Environment Enumeration
            - `systeminfo | findstr /B /C:"OS Name" /C:"OS Version"` OS version
            - `whoami /priv` user name and privs
            - `net users` registered users
            - `net localgroup` groups users is in
            - `wmic qfe get Caption,Description,HotFixID,InstalledOn` look for patches
            - `wmic product get name,version,vendor` list installed software
            - `wmic service list brief` list services
            - `schtasks /query /fo LIST /v` list scheduled tatks
            - `driverquery` list all drivers
        - Find sensitive files
            - `findstr /si password *.txt`
        - Network usage
            - `netstat -ano` all listening ports
            - `route print` routing table
            - `arp -a` arp table
        - Powershell
            - `powershell.exe -nop -exec bypass` Run PS in bypass mode
        - Look for Password or PWD in text files
            - `Get-ChildItem -recurse -exclude *.dll*,*.exe*, \*pdb\* | Select-String -pattern '(?i)\\b(password|pwd)\\b(=|;|:)"*\\w+\[";\]' |Select-Object Path, Linenumber`
    - ### Linux
        
        - `sudo -l`
            - What can the user run with sudo?
            - Environment variable abuse?
        - `ls -l /etc/shadow /etc/passwd`
            - Can we add a new user or alter the hash of existing?
            - Can hashes be cracked?
        - `cat /etc/crontab`
            - Can a process/script be abused/replaced?
            - Abuse search order of PATH with a fake process?
            - Wildcard scripts
        - Find sticky bit apps to abuse
            - `find / -type f -a \( -perm -u+s -o -perm -g+s \) -exec ls -l {} \; 2> /dev/null`
            - `find / -perm -u=s -type f 2>/dev/null`
            - Any known expoits to give root?
            - Can running any give a root shell?
            - Can any be used to download and run more exploits?
            - Can any be used to make a call back for a remote shell?
            - Do any use a shared object that can be hijacked?
                - `strace`
                - Look for higher order search paths
            - Any inheriting user PATH or environtment variables we can abuse?
                - Prepend PATH before calling app
            - Shell functions as file path names
        - Installed apps or services
        - `getcap -r / 2>/dev/null` find files with capabilities set such as SETUID
        - Find Files
            - `find . -name flag1.txt` find the file named “flag1.txt” in the current directory
            - `find /home -name flag1.txt` find the file names “flag1.txt” in the /home directory
            - `find / -type d -name config` find the directory named config under “/”
            - `find / -type f -perm 0777` find files with the 777 permissions
            - `find / -perm a=x` find executable files
            - `find /home -user frank` find all files for user “frank” under “/home”
            - `find / -mtime 10` find files that were modified in the last 10 days
            - `find / -atime 10` find files that were accessed in the last 10 day
            - `find / -cmin -60` find files changed within the last hour (60 minutes)
            - `find / -amin -60` find files accesses within the last hour (60 minutes)
            - `find / -size 50M` find files with a 50 MB size
            - `find / -writable -type d 2>/dev/null` Find world-writable folders
            - `find / -perm -222 -type d 2>/dev/null` Find world-writable folders
            - `find / -perm -o w -type d 2>/dev/null` Find world-writable folders
            - `find / -perm -o x -type d 2>/dev/null` Find world-executable folders
            - `find / -perm -u=s -type f 2>/dev/null` Find files with the SUID bit,
        - Shell History
            - Exposed passwords?
            - Exposed ssh keys?
            - Exposed config files?
        - NFS share abuse
            - check exports `cat /etc/exports`
            - No Root Squash
        - Kernel Exploits
    - ### Services
        
        - MySQL
            - User Defined Function abuse
        - Apcahe
            - Shared Library abuse

---

# Priv Escalation Phase

---

# Pivot and Persistence

---

# Attack path summary

---

# Findings summary

---