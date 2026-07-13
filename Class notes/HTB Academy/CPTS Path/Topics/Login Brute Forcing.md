#auth #authentication #login #bruteforce #passwords #passwordcracking 

- a trial-and-error method used to crack passwords, login credentials, or encryption keys. It involves systematically trying every possible combination of characters until the correct one is found. The process can be likened to a thief trying every key on a giant keyring until they find the one that unlocks the treasure chest.
- The success of a brute force attack depends on several factors, including:
	- The `complexity` of the password or key. Longer passwords with a mix of uppercase and lowercase letters, numbers, and symbols are exponentially more complex to crack.
	- The `computational power` available to the attacker. Modern computers and specialized hardware can try billions of combinations per second, significantly reducing the time needed for a successful attack.
	- The `security measures` in place. Account lockouts, CAPTCHAs, and other defenses can slow down or even thwart brute-force attempts.

| **Method**                    | **Description**                                                                                                                   | **Example**                                                                                                                                                  | **Best Used When...**                                                                                                                           |
| ------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `Simple Brute Force`      | Systematically tries all possible combinations of characters within a defined character set and length range.                 | Trying all combinations of lowercase letters from 'a' to 'z' for passwords of length 4 to 6.                                                             | No prior information about the password is available, and computational resources are abundant.                                             |
| `Dictionary Attack`       | Uses a pre-compiled list of common words, phrases, and passwords.                                                             | Trying passwords from a list like 'rockyou.txt' against a login form.                                                                                    | The target will likely use a weak or easily guessable password based on common patterns.                                                    |
| `Hybrid Attack`           | Combines elements of simple brute force and dictionary attacks, often appending or prepending characters to dictionary words. | Adding numbers or special characters to the end of words from a dictionary list.                                                                         | The target might use a slightly modified version of a common password.                                                                      |
| `Credential Stuffing`     | Leverages leaked credentials from one service to attempt access to other services, assuming users reuse passwords.            | Using a list of usernames and passwords leaked from a data breach to try logging into various online accounts.                                           | A large set of leaked credentials is available, and the target is suspected of reusing passwords across multiple services.                  |
| `Password Spraying`       | Attempts a small set of commonly used passwords against a large number of usernames.                                          | Trying passwords like 'password123' or 'qwerty' against all usernames in an organization.                                                                | Account lockout policies are in place, and the attacker aims to avoid detection by spreading attempts across multiple accounts.             |
| `Rainbow Table Attack`    | Uses pre-computed tables of password hashes to reverse hashes and recover plaintext passwords quickly.                        | Pre-computing hashes for all possible passwords of a certain length and character set, then comparing captured hashes against the table to find matches. | A large number of password hashes need to be cracked, and storage space for the rainbow tables is available.                                |
| `Reverse Brute Force`     | Targets a single password against multiple usernames, often used in conjunction with credential stuffing attacks.             | Using a leaked password from one service to try logging into multiple accounts with different usernames.                                                 | A strong suspicion exists that a particular password is being reused across multiple accounts.                                              |
| `Distributed Brute Force` | Distributes the brute forcing workload across multiple computers or devices to accelerate the process.                        | Using a cluster of computers to perform a brute-force attack significantly increases the number of combinations that can be tried per second.            | The target password or key is highly complex, and a single machine lacks the computational power to crack it within a reasonable timeframe. |
```mathml
Possible Combinations = Character Set Size^Password Length
```

| **Type**                      | **Password Length** | **Character Set**                                         | **Possible Combinations**               |
| ------------------------- | --------------- | ----------------------------------------------------- | ----------------------------------- |
| `Short and Simple`        | 6               | Lowercase letters (a-z)                               | 26^6 = 308,915,776                  |
| `Longer but Still Simple` | 8               | Lowercase letters (a-z)                               | 26^8 = 208,827,064,576              |
| `Adding Complexity`       | 8               | Lowercase and uppercase letters (a-z, A-Z)            | 52^8 = 53,459,728,531,456           |
| `Maximum Complexity`      | 12              | Lowercase and uppercase letters, numbers, and symbols | 94^12 = 475,920,493,781,698,549,504 |
- Time to crack is combinations / processing rate of combinations per second

| **Feature**         | **Dictionary Attack**                                                    | **Brute Force Attack**                                                   | **Explanation**                                                                                                                                                                                                    |
| --------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Efficiency`    | Considerably faster and more resource-efficient.                     | Can be extremely time-consuming and resource-intensive.              | Dictionary attacks leverage a pre-defined list, significantly narrowing the search space compared to brute-force.                                                                                              |
| `Targeting`     | Highly adaptable and can be tailored to specific targets or systems. | No inherent targeting capability.                                    | Wordlists can incorporate information relevant to the target (e.g., company name, employee names), increasing the success rate.                                                                                |
| `Effectiveness` | Exceptionally effective against weak or commonly used passwords.     | Effective against all passwords given sufficient time and resources. | If the target password is within the dictionary, it will be swiftly discovered. Brute force, while universally applicable, can be impractical for complex passwords due to the sheer volume of combinations.   |
| `Limitations`   | Ineffective against complex, randomly generated passwords.           | Often impractical for lengthy or highly complex passwords.           | A truly random password is unlikely to appear in any dictionary, rendering this attack futile. The astronomical number of possible combinations for lengthy passwords can make brute-force attacks infeasible. |

| **Wordlist**                                    | **Description**                                                                                      | **Typical Use**                                        | **Source**                                                                                                      |
| ------------------------------------------- | ------------------------------------------------------------------------------------------------ | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| `rockyou.txt`                               | A popular password wordlist containing millions of passwords leaked from the RockYou breach.     | Commonly used for password brute force attacks.    | [RockYou breach dataset](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt) |
| `top-usernames-shortlist.txt`               | A concise list of the most common usernames.                                                     | Suitable for quick brute force username attempts.  | [SecLists](https://github.com/danielmiessler/SecLists/tree/master)                                          |
| `xato-net-10-million-usernames.txt`         | A more extensive list of 10 million usernames.                                                   | Used for thorough username brute forcing.          | [SecLists](https://github.com/danielmiessler/SecLists/tree/master)                                          |
| `2023-200_most_used_passwords.txt`          | A list of the 200 most commonly used passwords as of 2023.                                       | Effective for targeting commonly reused passwords. | [SecLists](https://github.com/danielmiessler/SecLists/tree/master)                                          |
| `Default-Credentials/default-passwords.txt` | A list of default usernames and passwords commonly used in routers, software, and other devices. | Ideal for trying default credentials.              | [SecLists](https://github.com/danielmiessler/SecLists/tree/master)                                          |
- hybrid attacks should match password complexity requirements
	-  grab a list and cut out less than 8, then cut missing Capital, then  lower case, then cut any without digits
```shell-session
wget https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/darkweb2017-top10000.txt
grep -E '^.{8,}$' darkweb2017-top10000.txt > darkweb2017-minlength.txt
grep -E '[A-Z]' darkweb2017-minlength.txt > darkweb2017-uppercase.txt
grep -E '[a-z]' darkweb2017-uppercase.txt > darkweb2017-lowercase.txt
grep -E '[0-9]' darkweb2017-lowercase.txt > darkweb2017-number.txt
```
- #Hydra 
- Basic Auth - B64 encoded string that *may* contain cleartext creds
		```http
		GET /protected_resource HTTP/1.1
		Host: www.example.com
		Authorization: Basic YWxpY2U6c2VjcmV0MTIz
		```
- #medusa 
- create custom lists
	- using username anarchy to make a name list
		```shell-session
		sudo apt install ruby -y
		git clone https://github.com/urbanadventurer/username-anarchy.git
		cd username-anarchy
		```
		- `./username-anarchy Jane Smith > jane_smith_usernames.txt` mangle Jane and Smith in different ways
	- `cupp -i` using cupp interactively where it guides the user through creating a password list
	- `grep -E '^.{6,}$' jane.txt | grep -E '[A-Z]' | grep -E '[a-z]' | grep -E '[0-9]' | grep -E '([!@#$%^&*].*){2,}' > jane-filtered.txt` create a filtered list based on characters contained in each line
