#NMAP 

- nmap -sV --open -oA initial_scan 10.129.200.170
- nmap -p- --open -oA full_tcp_scan 10.129.200.170
- nmap -sC -p 22,80 -oA script_scan  10.129.200.170
- sudo nmap 10.129.2.0/24 -sn -oA tnet | grep for | cut -d" " -f5
- `nmap -sn 192.168.0.1/24` Quick check of a network


- nmap 10.129.2.28 --top-ports=10 # Top 10 most common ports
- nmap 10.129.2.28 -p 21 --packet-trace -Pn -n --disable-arp-ping # Show packet sent rcvd, disable DNS, disable ARP ping

###### Convert XML output to nice HTML
- xsltproc target.xml -o target.html

###### NSE Nmap Scripting Engine
- 14 categories based on script function
- -sC default scripts
- --script {1 of the 14 categories}
- --script {specific script} # can use , to list more than 1
- -A an aggressive scan, Performs service detection, OS detection, traceroute and uses defaults scripts to scan the target.

###### Tune timing for more efficient scanning
- --initial-rtt-timeout 50ms # time out to start with
- --max-rtt-timeout 100ms # max timeout 
- --max-retries # tune how many tries before moving on
- --min-rate # how many packets to send

###### IDS/IPS/Firewall bypass
- Change scan types -sS Syn, -sA Ack, etc
- Use decoys -D to mix in random IPs, random IPs should be online
- -S # change source IP
- --dns-server # specify a DNS server to use such as the victims internal
- --source-port # change source port, such as 53. 53 might not be filtered/monitored


###### Scripting
- sudo nmap --script-updatedb # update the cached scripts
- smtp-user-enum -M VRFY -U footprinting-wordlist.txt -t 10.129.209.62 -v # enumerate an open SMTP relay with a user list

###### Formatting
- `cat scan.nmap| awk -F/ '/open/ {b=b","$1} END {print substr(b,2)}'`      # Parse ports into comma list
- `-oA {path/filename}` output all report formats