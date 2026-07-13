smbmap -H 10.129.98.114

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.98.114:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	NO ACCESS	Logon server share 
	Users                                             	NO ACCESS	
[*] Closed 1 connections                               


smbmap -u svc_tgs -p GPPstillStandingStrong2k18 -d active.htb -H 10.129.98.114                    

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.98.114:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
[*] Closed 1 connections                                                            


smbmap -d active.htb -u SVC_TGS -p GPPstillStandingStrong2k18 -H 10.129.98.114 -r Users --depth 2

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.98.114:445	Name: active.htb          	Status: Authenticated
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	IPC$                                              	NO ACCESS	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	Replication                                       	READ ONLY	
	SYSVOL                                            	READ ONLY	Logon server share 
	Users                                             	READ ONLY	
	./Users
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	.
	dw--w--w--                0 Sat Jul 21 09:39:20 2018	..
	dr--r--r--                0 Mon Jul 16 05:14:21 2018	Administrator
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	All Users
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Default
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Default User
	fr--r--r--              174 Mon Jul 16 16:01:17 2018	desktop.ini
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Public
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	SVC_TGS
	./Users//Default
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	.
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	..
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	AppData
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Application Data
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Cookies
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Desktop
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Documents
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Downloads
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Favorites
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Links
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Local Settings
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Music
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	My Documents
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	NetHood
	fr--r--r--           262144 Mon Jul 30 08:47:52 2018	NTUSER.DAT
	fr--r--r--             1024 Mon Jul 16 16:01:17 2018	NTUSER.DAT.LOG
	fr--r--r--            95232 Mon Jul 30 08:47:52 2018	NTUSER.DAT.LOG1
	fr--r--r--                0 Mon Jul 16 16:08:47 2018	NTUSER.DAT.LOG2
	fr--r--r--            65536 Mon Jul 16 16:01:17 2018	NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf
	fr--r--r--           524288 Mon Jul 16 16:01:17 2018	NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms
	fr--r--r--           524288 Mon Jul 16 16:01:17 2018	NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000002.regtrans-ms
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Pictures
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	PrintHood
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Recent
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	Saved Games
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	SendTo
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Start Menu
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	Templates
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	Videos
	./Users//Default/AppData
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	.
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	..
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	Local
	dr--r--r--                0 Mon Jul 16 16:08:47 2018	Roaming
	./Users//Default/Documents
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	.
	dw--w--w--                0 Mon Jul 16 16:08:47 2018	..
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	My Music
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	My Pictures
	dr--r--r--                0 Mon Jul 16 16:08:56 2018	My Videos
	./Users//SVC_TGS
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	.
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	..
	dr--r--r--                0 Sat Jul 21 10:14:20 2018	Contacts
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	Desktop
	dr--r--r--                0 Sat Jul 21 10:14:28 2018	Downloads
	dr--r--r--                0 Sat Jul 21 10:14:50 2018	Favorites
	dr--r--r--                0 Sat Jul 21 10:15:00 2018	Links
	dr--r--r--                0 Sat Jul 21 10:15:23 2018	My Documents
	dr--r--r--                0 Sat Jul 21 10:15:40 2018	My Music
	dr--r--r--                0 Sat Jul 21 10:15:50 2018	My Pictures
	dr--r--r--                0 Sat Jul 21 10:16:05 2018	My Videos
	dr--r--r--                0 Sat Jul 21 10:16:20 2018	Saved Games
	dr--r--r--                0 Sat Jul 21 10:16:32 2018	Searches
	./Users//SVC_TGS/Desktop
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	.
	dr--r--r--                0 Sat Jul 21 10:14:42 2018	..
	fw--w--w--               34 Fri Aug  8 08:31:57 2025	user.txt



