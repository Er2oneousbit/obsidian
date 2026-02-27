#snmp #simplenetworkmanagementprotocol

- Monitor/control network devices
- SNMPv3 adds increased security
- UDP 161 used for transmitting control commands to clients
- UDP 162 used to send traps to client
	- traps are commands sent when a server side event happens
- Each object must have its own unique address

Management Information Base or MIB
- ASCII format to store device meta data and auth
- Contains a list of OIDs

Object Identifier Registry or OID
- Hierarchical namespace using a dot for each sub tree
	- 1 , 1.1 , 1.1.1 , 1.1.1.1
- Each object has a unique ID
- May refence other objects

SNMPv1 - no built in authentication
SNMPv2 - add in security is in plaintext
SNMPv3 - adds encrypted authentication via pre shared key

Community strings
- configuration strings used to connect to clients, like a password

Default Configs
- linux
	- /etc/snmp/snmpd.conf
- contains basic settings
	- IPs, ports, MIB, OID, Authentication, Community Strings

Foot printing SNMP
- [[snmpwalk]]
- [[onesixtyone]]
- [[braa]]






Dangerous Settings

| **Settings**                                     | **Description**                                                                       |
| ------------------------------------------------ | ------------------------------------------------------------------------------------- |
| `rwuser noauth`                                  | Provides access to the full OID tree without authentication.                          |
| `rwcommunity <community string> <IPv4 address>`  | Provides access to the full OID tree regardless of where the requests were sent from. |
| `rwcommunity6 <community string> <IPv6 address>` | Same access as with `rwcommunity` with the difference of using IPv6.                  |