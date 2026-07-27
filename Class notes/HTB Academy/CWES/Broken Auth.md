What is Authentication
Authentication is defined as "The process of verifying a claim that a system entity or system resource has a certain attribute value" in RFC 4949. In information security, authentication is the process of confirming an entity's identity, ensuring they are who they claim to be. On the other hand, authorization is an "approval that is granted to a system entity to access a system resource". While this module will not cover authorization in depth, understanding the major difference between it and authentication is vital to approaching this module with the appropriate mindset.

Comparison of Authentication vs. Authorization. Authentication verifies identity, requires credentials, and occurs before authorization. Authorization determines access, follows authentication, and uses policies.

The most widespread authentication method in web applications is login forms, where users enter their username and password to prove their identity. Login forms can be found on many websites, including email providers, online banking, and HTB Academy:

https://academy.hackthebox.com/login
Sign-in page for an account with options to continue with HTB account or email. Fields for email, password, and "Remember me" checkbox. Links for SSO login, password recovery, and registration.
Authentication is probably the most widely used security measure and the first line of defense against unauthorized access. As web application penetration testers, we aim to verify if authentication is implemented securely. This module will focus on various exploitation methods and techniques against login forms to bypass authentication and gain unauthorized access.

Common Authentication Methods
Information technology systems can implement different authentication methods. Typically, they can be divided into the following three major categories:

Knowledge-based authentication
Ownership-based authentication
Inherence-based authentication
Knowledge
Authentication based on knowledge factors relies on something that the user knows to prove their identity. The user provides information such as passwords, passphrases, PINs, or answers to security questions.

Ownership
Authentication based on ownership factors relies on something the user possesses. The user proves their identity by demonstrating the ownership of a physical object or device, such as an ID card, security token, or smartphone with an authentication app. 

Inherence
Lastly, authentication based on inherence factors relies on something the user is or does. This includes biometric factors such as fingerprints, facial patterns, and voice recognition, or signatures. Biometric authentication is highly effective since biometric traits are inherently tied to an individual user.

Knowledge	Ownership	Inherence
Password	ID card	Fingerprint
PIN	Security Token	Facial Pattern
Answer to Security Question	Authenticator App	Voice Recognition
Single-Factor Authentication vs Multi-Factor Authentication
Single-factor authentication relies solely on a single method of authentication. For instance, password authentication solely relies on knowledge of the password. As such, it is a single-factor authentication method.

On the other hand, multi-factor authentication (MFA) involves multiple authentication methods. For instance, if a web application requires a password and a time-based one-time password (TOTP), it relies on knowledge of the password and ownership of the TOTP device for authentication. In the case where exactly two factors are required, MFA is commonly referred to as two-factor authentication (2FA).



Attacks on Authentication
We will categorize attacks on authentication based on the three types of authentication methods discussed in the previous section.

Attacking Knowledge-based Authentication
Knowledge-based authentication is prevalent and comparatively easy to attack. As such, we will mainly focus on knowledge-based authentication in this module. This authentication method suffers from reliance on static personal information that can be potentially obtained, guessed, or brute-forced. As cyber threats evolve, attackers have become adept at exploiting weaknesses in knowledge-based authentication systems through various means, including social engineering and data breaches.

Attacking Ownership-based Authentication
One significant advantage of ownership-based authentication is its resistance to many common cyber threats, including phishing and password-guessing attacks. Authentication methods based on physical possession, such as hardware tokens or smart cards, are inherently more secure because physical items are more difficult for attackers to acquire or replicate compared to information that can be phished, guessed, or obtained through data breaches. However, challenges such as the cost and logistics of distributing and managing physical tokens or devices can sometimes limit the widespread adoption of ownership-based authentication, particularly in large-scale deployments.

Furthermore, systems using ownership-based authentication can be vulnerable to physical attacks, such as theft or cloning of the object, as well as cryptographic attacks on the algorithm it employs. For instance, cloning objects such as NFC badges in public places, like public transportation or cafés, is a feasible attack vector.

Attacking Inherence-based Authentication
Inherence-based authentication provides convenience and user-friendliness. Users don't need to remember complex passwords or carry physical tokens; they simply provide biometric data, such as a fingerprint or facial scan, to gain access. This streamlined authentication process enhances user experience and reduces the likelihood of security breaches resulting from weak passwords or stolen tokens. However, inherence-based authentication systems must address concerns regarding privacy, data security, and potential biases in biometric recognition algorithms to ensure widespread adoption and trust among users.

On the other hand, inherence-based authentication systems can be irreversibly compromised in the event of a data breach. This is because users cannot change their biometric features, such as fingerprints. For instance, in 2019, threat actors breached a company that builds biometric smart locks, which are managed via a mobile or web application, to identify authorized users using their fingerprints and facial patterns. The breach exposed all fingerprints and facial patterns, in addition to usernames and passwords, grants, and the addresses of registered users. While affected users could have easily changed their passwords to mitigate this data breach if the smart locks had used knowledge-based authentication, this was not possible since they utilized inherence-based authentication.


Enumerating Users
User enumeration vulnerabilities occur when a web application responds differently to registered and valid versus invalid inputs for authentication endpoints. User enumeration vulnerabilities often occur in functions that rely on the user's username, such as user login, registration, and password reset.

Web developers frequently overlook user enumeration vectors, assuming that information such as usernames is not confidential. However, usernames can be considered confidential if they are the primary identifier required for authentication in web applications. Moreover, users tend to use the same username across various services, including web applications, as well as FTP, RDP, and SSH. Since many web applications allow us to identify usernames, we can enumerate valid usernames and use them for further attacks on authentication. This is often possible because web applications typically use a username or the user's email address as the primary identifier for users.

User Enumeration Theory
Protection against username enumeration attacks can negatively impact user experience. A web application that reveals whether a username exists can help a legitimate user identify if they have mistyped their username. Still, the same applies to an attacker trying to determine valid usernames. Even well-known and mature applications, like WordPress, allow for user enumeration by default. For instance, if we attempt to log in to WordPress with an invalid username, we get the following error message:

http://wordpress.htb/
WordPress login page with error message: "Unknown username. Check again or try your email address." Fields for username/email, password, and "Remember Me" checkbox.
On the other hand, a valid username results in a different error message:

http://wordpress.htb/
WordPress login page with error message: "The password you entered for the username editor is incorrect." Fields for username/email, password, and "Remember Me" checkbox. Link to reset password.
As we can see, user enumeration can be a security risk that a web application deliberately accepts to provide a service. As another example, consider a chat application enabling users to chat with others. This application might provide a functionality to search for users by their username. While this functionality can be used to enumerate all users on the platform, it is also essential to the service provided by the web application. As such, user enumeration is not always a security vulnerability. Nevertheless, it should be avoided if possible as a defense-in-depth measure. For instance, in our example web application, user enumeration can be avoided by not using the username during login, but an email address instead.

Enumerating Users via Differing Error Messages
To obtain a list of valid users, an attacker typically requires a wordlist of usernames to test. Usernames are often far less complicated than passwords. They rarely contain special characters when they are not email addresses. A list of common users allows an attacker to narrow the scope of a brute-force attack or carry out targeted attacks (leveraging OSINT) against support employees or users. Also, a common password could be easily sprayed against valid accounts, often leading to a successful account compromise. Additional methods for harvesting usernames include crawling a web application or utilizing publicly available information, such as company profiles on social networks. A good starting point is the wordlist collection SecLists. 

When we attempt to log in to the lab with an invalid username, such as abc, we can see the following error message:

http://<SERVER_IP>:<PORT>/
Login page with error message: "Unknown user." Fields for username and password. Options to register an account or reset password.
On the other hand, when we attempt to log in with a registered user such as htb-stdnt and an invalid password, we can see a different error:

http://<SERVER_IP>:<PORT>/
Login page with error message: "Invalid credentials." Fields for username and password. Options to register an account or reset password.
Let us exploit this difference in error messages returned and use SecLists's wordlist xato-net-10-million-usernames.txt to enumerate valid users with ffuf. We can specify the wordlist with the -w parameter, the POST data with the -d parameter, and the keyword FUZZ in the username to fuzz valid users. Finally, we can filter out invalid users by removing responses containing the string Unknown user:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=invalid" -fr "Unknown user"

<SNIP>

[Status: 200, Size: 3271, Words: 754, Lines: 103, Duration: 310ms]
    * FUZZ: consuelo

We successfully identified the valid username consuelo. We could now proceed by attempting to brute-force the user's password, as we will discuss in the following section.

User Enumeration via Side-Channel Attacks
While differences in the web application's response are the simplest and most obvious way to enumerate valid usernames, we might also be able to enumerate valid usernames via side channels. Side-channel attacks do not directly target the web application's response, but rather extra information that can be obtained or inferred from it. An example of a side channel is the response timing, i.e., the time it takes for the web application's response to reach us. Suppose a web application does database lookups only for valid usernames. In that case, we might be able to measure a difference in the response time and enumerate valid usernames this way, even if the response is the same. User enumeration based on response timing is covered in the Whitebox Attacks module.



Brute-Forcing Passwords
After successfully identifying valid users, password-based authentication relies on the password as a sole measure for authenticating the user. Since users tend to select easy-to-remember passwords, attackers may be able to guess or brute-force them.

While password brute-forcing is not the focus of this module (it is covered in more detail in other modules referenced at the end of this section), we will still discuss an example of brute-forcing a password-based login form, as it is one of the most common examples of broken authentication.

Brute-Forcing Passwords
Passwords remain one of the most common online authentication methods, yet they are plagued by many issues. One prominent issue is password reuse, where individuals use the same password across multiple accounts. This practice poses a significant security risk because if one account is compromised, attackers can potentially gain access to other accounts with the same credentials. Password reuse enables an attacker who obtained a list of passwords from a password leak to try the same passwords on other web applications ("Password Spraying"). Another issue is the use of weak passwords based on typical phrases, dictionary words, or simple patterns. These passwords are vulnerable to brute-force attacks, where automated tools systematically try different combinations until they find the correct one, compromising the account's security.

When accessing the sample web application, we can see the following information on the login page:

http://<SERVER_IP>:<PORT>/
Password update notice due to security issue. Requirements: one uppercase, one lowercase, one digit, minimum 10 characters.
The success of a brute-force attack depends entirely on the number of attempts an attacker can perform and the time it takes to complete the attack. As such, ensuring that a good wordlist is used for the attack is crucial. If a web application enforces a password policy, we should ensure that our wordlist only contains passwords that match the implemented password policy. Otherwise, we are wasting valuable time with passwords that users cannot use on the web application, as the password policy does not allow them.

For instance, the popular password wordlist rockyou.txt contains more than 14 million passwords:

        shellsession
er2oneousbit@htb[/htb]$ wc -l /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

14344391 /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt

Now, we can use grep to match only those passwords that match the password policy implemented by our target web application, which brings down the wordlist to about 150,000 passwords, a reduction of about 99%:

        shellsession
er2oneousbit@htb[/htb]$ grep '[[:upper:]]' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt | grep '[[:lower:]]' | grep '[[:digit:]]' | grep -E '.{10}' > custom_wordlist.txt

er2oneousbit@htb[/htb]$ wc -l custom_wordlist.txt

151647 custom_wordlist.txt

Alternatively, we could also combine the search parameters into a single awk command:

        shellsession
er2oneousbit@htb[/htb]$ awk 'length($0) >= 10 && /[a-z]/ && /[A-Z]/ && /[0-9]/' /opt/useful/seclists/Passwords/Leaked-Databases/rockyou.txt > custom_wordlist.txt

To start brute-forcing passwords, we need a user or a list of users to target. Using the techniques covered in the previous section, we determine that admin is a valid username. Therefore, we will attempt brute-forcing the account's password.

However, first, let us intercept the login request to know the names of the POST parameters and the error message returned within the response:

HTTP request and response. Request: POST to /index.php with username and password as "admin". Response: "Invalid username or password."

Upon providing an incorrect username, the login response contains the message (substring) "Invalid username", therefore, we can use this information to build our ffuf command to brute-force the user's password:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -w ./custom_wordlist.txt -u http://172.17.0.2/index.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=FUZZ" -fr "Invalid username"

<SNIP>

[Status: 302, Size: 0, Words: 1, Lines: 1, Duration: 4764ms]
    * FUZZ: Buttercup1

After some time, we can successfully obtain the admin user's password, enabling us to log in to the web application:

http://<SERVER_IP>:<PORT>/admin.php
Dashboard showing statistics: 283,000 monthly visitors, 105 blog posts, 1,200 comments, 350 users. Navigation includes Dashboard, Posts, Categories, Comments, Users.
For more details on creating custom wordlists and attacking password-based authentication, check out the Cracking Passwords with Hashcat and Password Attacks modules. Further details on brute-forcing different variations of web application logins are provided in the Login Brute Forcing module



Brute-Forcing Password Reset Tokens
Many web applications implement a password recovery functionality in case a user forgets their password. This password-recovery functionality typically relies on a one-time reset token, which is transmitted to the user, for instance, via SMS or email. The user can then authenticate using this token, enabling them to reset their password and access their account.

As such, a weak password-reset token may be brute-forced or predicted by an attacker to gain unauthorized access to a victim's account.

Identifying Weak Reset Tokens
Reset tokens (in the form of a code or temporary password) are secret data generated by an application when a user requests a password reset. The user can then change their password by presenting the reset token.

Since password reset tokens enable an attacker to reset an account's password without knowledge of the password, they can be leveraged as an attack vector to take over a victim's account if implemented incorrectly. Password reset flows can be complicated because they consist of several sequential steps; a basic password reset flow is shown below:

Password reset flowchart: User forgets password, requests reset, receives token, uses it to log in, and changes password. Webapp generates and sends token, verifies it, grants login, and forces new password.

To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it to determine its strength. In this example, let us assume we have received the following password reset email:

        txt
Hello,

We have received a request to reset the password associated with your account. To proceed with resetting your password, please follow the instructions below:

1. Click on the following link to reset your password: Click

2. If the above link doesn't work, copy and paste the following URL into your web browser: http://weak_reset.htb/reset_password.php?token=7351

Please note that this link will expire in 24 hours, so please complete the password reset process as soon as possible. If you did not request a password reset, please disregard this email.

Thank you.

As we can see, the password reset link contains the reset token in the GET parameter token. In this example, the token is 7351. Given that the token consists of only a 4-digit number, there can be only 10,000 possible values. This allows us to hijack users' accounts by requesting a password reset and then brute-forcing the token.

Attacking Weak Reset Tokens
We will use ffuf to brute-force all possible reset tokens. First, we need to create a wordlist of all possible tokens from 0000 to 9999, which we can achieve with seq:

        shellsession
er2oneousbit@htb[/htb]$ seq -w 0 9999 > tokens.txt

The -w flag pads all numbers to the same length by prepending zeroes, which we can verify by looking at the first few lines of the output file:

        shellsession
er2oneousbit@htb[/htb]$ head tokens.txt

0000
0001
0002
0003
0004
0005
0006
0007
0008
0009

Assuming that there are users currently in the process of resetting their passwords, we can try to brute-force all active reset tokens. If we want to target a specific user, we should first send a password reset request for that user to create a reset token. We can then specify the wordlist in ffuf to brute-force all active reset-tokens:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"

<SNIP>

[Status: 200, Size: 2667, Words: 538, Lines: 90, Duration: 1ms]
    * FUZZ: 6182

By specifying the reset token in the GET parameter token in the /reset_password.php endpoint, we can reset the password of the corresponding account, enabling us to take over the account:




Brute-Forcing Password Reset Tokens
Many web applications implement a password recovery functionality in case a user forgets their password. This password-recovery functionality typically relies on a one-time reset token, which is transmitted to the user, for instance, via SMS or email. The user can then authenticate using this token, enabling them to reset their password and access their account.

As such, a weak password-reset token may be brute-forced or predicted by an attacker to gain unauthorized access to a victim's account.

Identifying Weak Reset Tokens
Reset tokens (in the form of a code or temporary password) are secret data generated by an application when a user requests a password reset. The user can then change their password by presenting the reset token.

Since password reset tokens enable an attacker to reset an account's password without knowledge of the password, they can be leveraged as an attack vector to take over a victim's account if implemented incorrectly. Password reset flows can be complicated because they consist of several sequential steps; a basic password reset flow is shown below:

Password reset flowchart: User forgets password, requests reset, receives token, uses it to log in, and changes password. Webapp generates and sends token, verifies it, grants login, and forces new password.

To identify weak reset tokens, we typically need to create an account on the target web application, request a password reset token, and then analyze it to determine its strength. In this example, let us assume we have received the following password reset email:

        txt
Hello,

We have received a request to reset the password associated with your account. To proceed with resetting your password, please follow the instructions below:

1. Click on the following link to reset your password: Click

2. If the above link doesn't work, copy and paste the following URL into your web browser: http://weak_reset.htb/reset_password.php?token=7351

Please note that this link will expire in 24 hours, so please complete the password reset process as soon as possible. If you did not request a password reset, please disregard this email.

Thank you.

As we can see, the password reset link contains the reset token in the GET parameter token. In this example, the token is 7351. Given that the token consists of only a 4-digit number, there can be only 10,000 possible values. This allows us to hijack users' accounts by requesting a password reset and then brute-forcing the token.

Attacking Weak Reset Tokens
We will use ffuf to brute-force all possible reset tokens. First, we need to create a wordlist of all possible tokens from 0000 to 9999, which we can achieve with seq:

        shellsession
er2oneousbit@htb[/htb]$ seq -w 0 9999 > tokens.txt

The -w flag pads all numbers to the same length by prepending zeroes, which we can verify by looking at the first few lines of the output file:

        shellsession
er2oneousbit@htb[/htb]$ head tokens.txt

0000
0001
0002
0003
0004
0005
0006
0007
0008
0009

Assuming that there are users currently in the process of resetting their passwords, we can try to brute-force all active reset tokens. If we want to target a specific user, we should first send a password reset request for that user to create a reset token. We can then specify the wordlist in ffuf to brute-force all active reset-tokens:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -w ./tokens.txt -u http://weak_reset.htb/reset_password.php?token=FUZZ -fr "The provided token is invalid"

<SNIP>

[Status: 200, Size: 2667, Words: 538, Lines: 90, Duration: 1ms]
    * FUZZ: 6182

By specifying the reset token in the GET parameter token in the /reset_password.php endpoint, we can reset the password of the corresponding account, enabling us to take over the account:



