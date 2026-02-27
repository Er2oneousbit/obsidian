#Hydra #passwordcracking #auth 

#update

- [GitHub - vanhauser-thc/thc-hydra: hydra](https://github.com/vanhauser-thc/thc-hydra)
- Used to brute force authentication for various protocols 
- basic usage `hydra [login_options] [password_options] [attack_options] [service_options]` 
-  **SSH** `hydra -l susan -P /usr/share/eaphammer/wordlists/rockyou.txt 10.129.86.7 ssh`
- bruteforce **RDP** with username/password lists `hydra -L user.list -P password.list rdp://10.129.42.197` 
- **SSH** username:password format test file`hydra -C user_pass.list ssh://10.129.42.197` **SSH** username:password format test file
- `hydra -l kira -P password.list smb://10.129.132.116 -m SMB2` **SMB** for SMBv1 SMB2 for v2 SMB3 for v3
- `hydra -L usernames.txt -p 'password123' 192.168.2.143 rdp` **RDP** 
- `hydra -l administrator -x 6:8:abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 192.168.1.100 rdp` **RDP** using passwords 6-8 chars and a specific alphanumeric set
- `hydra -L users.txt -p 'Company01!' -f 10.10.110.20 pop3`  **POP3** 
- `hydra -L usernames.txt -P passwords.txt -s 2121 -V ftp.example.com ftp` **FTP**
- `hydra -l admin -P passwords.txt www.example.com http-post-form "/login:user=^USER^&pass=^PASS^:S=302"` **web login** using user and pass as a **POST parameter** and look for a HTTP 302 redirect to indicate successful login
- **web login** using user and pass as a **POST parameter** `hydra -L top-usernames-shortlist.txt -P 2023-200_most_used_passwords.txt -f 83.136.249.46 -s 50516 http-post-form "/:username=^USER^&password=^PASS^:F=Invalid credentials"`  and `Invalid credentials` is a failed attempt
- `hydra -l basic-auth-user -P 2023-200_most_used_passwords.txt 83.136.249.104 http-get / -s 57991` **basic auth** using a HTTP GET @ `/` and use port 81 



Guides
- [A Detailed Guide on Hydra - Hacking Articles](https://www.hackingarticles.in/a-detailed-guide-on-hydra/)


| **Parameter**               | **Explanation**                                                                                                | **Usage Example**                                                                                                   |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `-l LOGIN` or `-L FILE` | Login options: Specify either a single username (`-l`) or a file containing a list of usernames (`-L`).    | `hydra -l admin ...` or `hydra -L usernames.txt ...`                                                            |
| `-p PASS` or `-P FILE`  | Password options: Provide either a single password (`-p`) or a file containing a list of passwords (`-P`). | `hydra -p password123 ...` or `hydra -P passwords.txt ...`                                                      |
| `-t TASKS`              | Tasks: Define the number of parallel tasks (threads) to run, potentially speeding up the attack.           | `hydra -t 4 ...`                                                                                                |
| `-f`                    | Fast mode: Stop the attack after the first successful login is found.                                      | `hydra -f ...`                                                                                                  |
| `-s PORT`               | Port: Specify a non-default port for the target service.                                                   | `hydra -s 2222 ...`                                                                                             |
| `-v` or `-V`            | Verbose output: Display detailed information about the attack's progress, including attempts and results.  | `hydra -v ...` or `hydra -V ...` (for even more verbosity)                                                      |
| `service://server`      | Target: Specify the service (e.g., `ssh`, `http`, `ftp`) and the target server's address or hostname.      | `hydra ssh://192.168.1.100`                                                                                     |
| `/OPT`                  | Service-specific options: Provide any additional options required by the target service.                   | `hydra http-get://example.com/login.php -m "POST:user=^USER^&pass=^PASS^"` (for HTTP form-based authentication) |

| **Hydra Service** | **Service/Protocol**                 | **Description**                                                                                             | **Example Command**                                                                                                |
| ------------- | -------------------------------- | ------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------- |
| ftp           | File Transfer Protocol (FTP)     | Used to brute-force login credentials for FTP services, commonly used to transfer files over a network. | `hydra -l admin -P /path/to/password_list.txt ftp://192.168.1.100`                                             |
| ssh           | Secure Shell (SSH)               | Targets SSH services to brute-force credentials, commonly used for secure remote login to systems.      | `hydra -l root -P /path/to/password_list.txt ssh://192.168.1.100`                                              |
| http-get/post | HTTP Web Services                | Used to brute-force login credentials for HTTP web login forms using either GET or POST requests.       | `hydra -l admin -P /path/to/password_list.txt http-post-form "/login.php:user=^USER^&pass=^PASS^:F=incorrect"` |
| smtp          | Simple Mail Transfer Protocol    | Attacks email servers by brute-forcing login credentials for SMTP, commonly used to send emails.        | `hydra -l admin -P /path/to/password_list.txt smtp://mail.server.com`                                          |
| pop3          | Post Office Protocol (POP3)      | Targets email retrieval services to brute-force credentials for POP3 login.                             | `hydra -l user@example.com -P /path/to/password_list.txt pop3://mail.server.com`                               |
| imap          | Internet Message Access Protocol | Used to brute-force credentials for IMAP services, which allow users to access their email remotely.    | `hydra -l user@example.com -P /path/to/password_list.txt imap://mail.server.com`                               |
| mysql         | MySQL Database                   | Attempts to brute-force login credentials for MySQL databases.                                          | `hydra -l root -P /path/to/password_list.txt mysql://192.168.1.100`                                            |
| mssql         | Microsoft SQL Server             | Targets Microsoft SQL servers to brute-force database login credentials.                                | `hydra -l sa -P /path/to/password_list.txt mssql://192.168.1.100`                                              |
| vnc           | Virtual Network Computing (VNC)  | Brute-forces VNC services, used for remote desktop access.                                              | `hydra -P /path/to/password_list.txt vnc://192.168.1.100`                                                      |
| rdp           | Remote Desktop Protocol (RDP)    | Targets Microsoft RDP services for remote login brute-forcing.                                          | `hydra -l admin -P /path/to/password_list.txt rdp://192.168.1.100`                                             |
