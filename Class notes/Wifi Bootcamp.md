- WIFI hacking

- iw dev wlan1 set monitor mode
- ifconfig wlan1 up
- iw dev # check transmission power

- Open wireshark and select wlan1 # will only listen to 1 channel at a time

- tcpdump -i wlan1 # CLI version of wireshark like

- airodump-ng wlan1 # will hop channels to find all the things on the channels
- airodump-ng wlan1 -c 1 # sticky to channel 1

- lsusb # list all USB, look for WIFI

- iwconfig # view all wifi 
- iwconfig wlan0 essid {SSID Name} # Connect to SSID {SSID Name}

- ifconfig wlan0 up # turn the wireless on
- Ifconfig wlan0 down # turn the wireless off

- iw phy # List deets about interfaces
- iw reg get # list the power output limits based on your region
- iw reg set # set wireless region
- iw dev wlan0 set channel 6 # set to channel 6
- iw dev wlan0 set channel 6 HT40+ # set to channel 6 AND bonding at 40mhz to the right side channel
- iw dev wlan0 set channel 6 HT40- # set to channel 6 AND bonding at 40mhz to the left side channel
- iw dev wlan0 set channel 36 80mhz # set to 5ghz channel 36 AND bonding at 80mhz
- iw dev # list wlan channel and transmission
- iw dev wlan0 scan # General 'scan' of the Wifi EM bands
- iw dev wlan0 scan | grep "SSID" # All the SSIDs you can see

- Management frames are done on non bonded frames
- If you are sniffing a network with data bonding,  you need to match it on your wlan or you cant see it (this bonding is found in the beacon frame)

- Wireshark

- Wireless -> WLAN Traffic # Table of all clients and analysis on packets
- Can filter on client # MAC, analyze specific targets
- Can filter on frames # like no control frames  
- Statistics -> Protocol Hierarchy # Display data on each protocol, more can be seen with Open SSID
- Can filter based on protocol 

- airodump

- airodump-ng wlan0 # start airodump, which will hope around on all channels looking for clients, then output a table of what it found (Note you can only be on one channel at a time)
- airodump-ng wlan0 -c 6 # Show the probes of devices for channel 6.  You will see the Preferred network List (PNL) that the clients are looking for ie what SSIDs it previously connected to and is trying to connect back to 
- airodump-ng wlan0 --band abg # default is to do 2.4ghz only, you will need to specify other bands - abg = 2.4 and 5

- https://github.com/pentesteracademy/patoolkit

- Basic Attacks
 - ### Open SSIDs don’t have anyway to authenticate what they are connecting to
 
- Honeypot - fake SSID that can be the same that clients are looking for (See PNL)
		- airbase-ng # Limited feature sets
		- hostapd # More supported features than airbase
			- hostapd config file define interface, device, ssid, bssid, channel then save to CONF file like open.conf
			- hostpad open.conf # starts AP based on CONF file (does NOT provide DHCP)
		- WiFiPhisher
		- Bettercap
		- EAPHammer
		
- beacon flood # multiple fake SSIDs
		- MDK4
			- mdk4 wlan0 b
	- Deauth
		- aireplay-ng
			- aireplay-ng -0 {count} -a {bssid} wlan0 -c {MAC} # send {count} deauth frames for {bssid} using wlan0 (-c is to target a specific target based on MAC) 
	- Fake captive portal - use fake SSID and then host captive portal to steal creds
		- SET # social engineering kit
		- NoDogSplash # openwrt
		- Android phone # null byte write up
	- Attack browser - use fake SSID then SET to host payload that attacks browser
		- JS hook from Beef
		- Use known browser exploits
	- Find hidden SSID - do deauth and sniff for PNL
	- Bypass MAC filtering
		- macchanger # spoof MAC to client that is communicating with AP
	- Remote sniffing - Use a remote machine to do the traffic capture and send it back to a local machine for analysis
		- TCPDUMP+SSH+Wireshark
			- ssh root@remotehost tcpdump -U -I wlan0 -w- | wireshark -k -I
		- Custom software that captures raw socket packets then transmit them back to local 
			- such has hak5 pineapple C2
			- python can capture raw packetsn and then transmit
			- ARUBA ERM is included in wireshark
				
- Comes in as UDP packet
					- Edit->Preferences->ARUBA_ERM Enter port (5555)
					- Right click on a packet->Decode AS->ARUBA_ERM PCAP+Radio(Type 3)
	- Find Hidden SSID
		- Has clients
			- Airodump-ng - same channel of hidden SSID
			- Deauth clients
			- Capture packets -> When client auths it will have SSID in frames
		- No clients
			- Use a dictionary attack
				- Get popular SSID dictionary -> https://wigle.net/stats#ssidstats
				- Use automation to test each entry
					- There Are Hidden Wi-Fi Networks All Around You — These Attacks Will Find Them « Null Byte :: WonderHowTo
					- Wireless Penetration Testing: Detect Hidden SSID - Hacking Articles
				- Split list and run on parallel machines/interfaces

		
- Wifi Security
	- WEP - Wired Equivalent Privacy
		- https://en.wikipedia.org/wiki/Wired_Equivalent_Privacy
		- Set up with 4 keys but select which one to use
		- Attacks
			- Capture and filter out beacons and probes
			- Look for IV and which Key is used
			- Pigeonhole or Birthday Paradox
				- Random IV will be reused at some point
			- Passive cracking - silently capture packets but may take a long time to get enough
			- Active cracking - sending traffic to AP to get enough packets
				- Replay Attack - capture and resend ARP packets
		- Aircrack-ng - 
			- Monitoring
			- Attack
			- Cracking
		- Wireshark
			- filter by WEP packets then by BSSID
			- Edit ->Preferences->Protocols->IEEE 802.11->Enable Decryption then EDIT decryption keys
		- airdecao-ng -w {wep key in hex} {pcap file}
		- tshark -r {decrypted pcap}
		- Once you  have cracked AP you can decrypt all clients with same key
		- wpa_supplicant - connect to WEP AP
		- AP needs to be in the area to be sniffed.
			- Be in the building
			- Parking lot
			- Long range antenna
			- Planted device with cellular
		- AP - Less attacks
			- Find clients making probe requests -> The Caffe Latte Attack
			
- Can change Data payload with ICV then RC4 and client wont know its forged
			- Send a forged ARP request over and over
			- Collect the packets to crack
		- WEP Cloaking can be attacked -> DEF CON 15 - Vivek Ramachandran - The Emperor Has No Cloak
		
- WPA/WPA2/WPA3
	- https://en.wikipedia.org/wiki/Wi-Fi_Protected_Access
		- WPA - band aid until something better and hardware could be changed
			- Mostly based on WEP - no need to change hardware
			- Uses dynamic keys instead of static
		- WPA2 - more permeant replacement to WEP/WPA
			- Adding AES - which needs new hardware to handle this new encryption
			- Both sides use Humana password into PBKDF2 to create a 256 bit preshared key
			- PMK = PBKDF2 (Passphrase, SSID, SSID length, 4096, 256)
				- 4096 - iterations of hashing passphrase
				- 256 - bit size of PSK
			- PTK Generation - 4 way handshake
				- Probe requests, Auth, and association requests
				- Send 256 bit key
				- #1 AP sends  ANonce (Authenticator Nonce)- Random string
				- #2 Client creates Snonce (Supplicant Nonce) - Random string
					- Client takes Anonce, Snonce to make PTK
					- PTK (pairwise transient key) = Function(pre shared key, ANonce, SNonce. AP Mac, Client MAC)
						- Unique for each client
					- Client then sends SNonce and MIC (Sort of a validation of key function)
				- #3 AP sends GTK and MIC
					- Group Transient Key - group key is used for broadcast packets as to not encrypt those with unique PTK
						- GTK is changed by AP
						- Encrypted by PTK
							- KCK - Key Confirmation Key - Compute MIC
							- KEK - Key Encryption Key - Key to encrypt things like MIC
							- TK - Temporal Key - Encrypt Unicast packets
							- MIC TX Key - Compute MIC for unicast from AP
							- MIC RC Key - Compute MIC for unicast from STA
				- #4 Client acknowledges all the Keys
			- If PSK is wrong AP will send a deauth at #3
			- Attack client and AP in range
				- Dictionary attack against human passphrase - only known attack at this time
					- Handshake attack 
						- All 4 packets, 1+2, 0r 2+3
				- Force client to disconnect
					- Record Handshake - Record about 100
				- aircrack-ng -w {some word list} [packet capture pcap]
				- Figuring out PMK ahead of time speeds up cracking
					- Find SSID + list of passphrases = PMK
				- Need PMK + Nonces + Both MACs 
				- genpmk - generate a list of PMKs
					- genpmk -f {wordlist of passphrases} -d {output hash file} -s {SSID Name}
				- cowpatty - WPA dictionary attack tool
					- cowpatty -d {genpmk file} -s {SSID name} -r [PCAP file]
				- airolib-ng - convert PMK list to sqlite
					- airolib-ng {SQLite File Output} --import {PMK list from cowpatty}
				- aircrack-ng -r {SQLite file from airolib} {PCAP file} 
				- Do hashcat on cloud
				- Connect with wpa supplicamt
					- create config file
						- network={
							- ssid={SSID name}
							- scan_ssid=1
							- kay-mgmt=WPA-PSK
							- psk={preshared key}
						- }
					- wpa_supplicant -i wlan0 -c {config file}
					- wpa_supplicant -B -I wlan0 -c {config file}
			- Attack without AP
				- hostapd - honeypot
					- same SSID as target AP
					- need a config file
						- interface=wlan1
						- driver=nl80211
						- ssid=FakeSSID
						- bssid:{MAC of AP}
						- wpa=2
						- wpa_passphrase=chocolate {the real one isnt known}
						- wpa_key_mgmt=WPA-PSK
						- rsn_pairwise={TKIP/CCMP or TKIP CCMP} # TKIP is WPA and CCMP is WPA2
						- channel=1
					- hostapd {config file}
						- capture 4way handshake
					- Crack PSK then relaunch honeypot with correct PSK and client should connect
					- Decrypt via wireshark if you want (same as WEP see above)
					- airdecap-ng -e {SSID name} -p {passphrase} {PCAP file}
					
	- Enterprise
		- RADIUS/AAA - Authentication, Authorization, Accounting
			- Started with dial access
			- FreeRADIUS - open source version
		- EAP - Extended Authentication Protocol
			- Peer to server
				- LAN and WLAN 
					- WLAN - 802.1X
			- AP must know AAA server's IP
			- AP's have shared sevret with AAA server
			- AP's know Auth Port - what port the server is running AAA services
			- AP's know Account Port -  accounting services port
			- AAA server knows AP's IP
			- AAA server knows shared secret
			- Client + AP knows ESSID, Network Auth, Data encryption
			- AAA sends random PMK to AP that sends to Client
		- Auth methods
			- EAP-MD5 
				- AAA sends MD5 challenge
				- Client sends MD5 hash of response ID, Password, Challenge
				- AAA matches md5 hash from client
				- Attacks
					- https://github.com/joswr1ght/eapmd5pass
					- eapmd5pass -w {dictionary file} -r {PCAP/dump file}
					- eapmd5pass -w {dictionary file} -U {user to target} -C {HEX of challenge MD5} -R {HEX of response MD5} -E 2
			- EAP-PAP - Plaintext username:password
			- EAP-GTC - Generic Token Card - sever sends challenge client responds with security token (like OTP)
			- EAP-CHAP - challenge based authentication
			- EAP-MSCHAMPv2 - microsoft's attempt at EAP - probably most secure but shouldn’t be used alone
		- Encapsulation
			- PEAP - Protected EAP
				- PEAPv0 with EAP-MSCHAPv2 - most popular
					- Native support in windows
				- PEAPv1 eith EAP-GTC
				- Server side certificate
				- Workflow
					- Client sends association request
					- Client sends EAP request
					- Server sends RADIUS request
					- Client and server agree to start PEAP
					- Client starts TLS then server agrees to TLS - certificate based
					- EAP repeats
					- Client and Server auth based on the list above
					- WPA 4 way handshake process takes place - see above
				- Attack PEAP
					- Create honey pot with target SSID - hostapd
						- passive - wait for user to connect
						- active - Lure - karma attack
							- karma attack - listen for probe requests then answer saying 'I am that SSID connect to me'
						- active - force - deauth attack
					- RADIUS/AAA server - free radius
					- Client conencts to fake SSID-> honepot sends request to fake RADIUS->RADIS sends fake cert to client
					- Then there is a challenge response interaction but we don’t care about the fake challenge, we want the response from the client
					- Client response contains the challenge/auth data to crack
				- Tools
					- Hostapd + FreeRadius - lagacy - hard to get working
					- hostapd-wpe - out of support - still hard to use - https://github.com/OpenSecurityResearch/hostapd-wpe
					- hostapd-mana - sorta supported - easier to use - https://github.com/sensepost/hostapd-mana
						- 2 radios/wlan - 1 in monitor mode 1 to host AP
						- Certificates - CA, Diffie–Hellman cert, server key, server cert - create with openssl
						- Peap.conf - config file
							
					
						- hostapd.eap_user - config file (talk to anything)
							
						- hostapd-mana peap.conf - start the honeypot
							- example of target victim
								
					- eaphammer - very easy to use - https://github.com/s0lst1c3/eaphammer
			- EAP-TTLS - Tunneled Transport Layer Security
				- Certificate server auth
				- client can use certificate
				- Not as popular because of the PKI overhead
				- Cert can impersonated with a globally accepted CA like lets encrypt
					- Can use in ho
			
			
	- Probing - even if WIFI is off
		- Wiggle.net - tracking WIFI SSIDs like war driving
		- CreepyDOL - tracking smartphones
		- Rotate MACs on phones - started by Apple
			- Real MAC is used on connection
	
	
	- dhclient -v wlan0 - get IP address
- Attack WIFI Router
	- NMAP - find open ports and running services - can we leverage a vuln?
	- Try default creds 
		
	
	- Attack services
		
	
	- Find CVEs
		
	
	- Sweep the network to find other devices to attack
	
	- What happens if you cant crack digest of MSCHAMPv2?
		- MITM - client <--> (Hostapd <--> wpa_supplicant) <--> SSID <--> RADIUS
			- Inject between client and AP, relay the challenge are response back and forth
			- Once client sends proper response the AP will allow attacker on WIFI
			- PEAP relay attack
			
