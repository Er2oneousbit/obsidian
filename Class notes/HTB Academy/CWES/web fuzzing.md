# Introduction

---

Web fuzzing is a critical technique in web application security to identify vulnerabilities by testing various inputs. It involves automated testing of web applications by providing unexpected or random data to detect potential flaws that attackers could exploit.

In the world of web application security, the terms "`fuzzing`" and "`brute-forcing`" are often used interchangeably, and for beginners, it's perfectly fine to consider them as similar techniques. However, there are some subtle distinctions between the two:

## Fuzzing vs. Brute-forcing

- Fuzzing casts a wider net. It involves feeding the web application with unexpected inputs, including malformed data, invalid characters, and nonsensical combinations. The goal is to see how the application reacts to these strange inputs and uncover potential vulnerabilities in handling unexpected data. Fuzzing tools often leverage wordlists containing common patterns, mutations of existing parameters, or even random character sequences to generate a diverse set of payloads.
- Brute-forcing, on the other hand, is a more targeted approach. It focuses on systematically trying out many possibilities for a specific value, such as a password or an ID number. Brute-forcing tools typically rely on predefined lists or dictionaries (like password dictionaries) to guess the correct value through trial and error.

Here's an analogy to illustrate the difference: Imagine you're trying to open a locked door. Fuzzing would be like throwing everything you can find at the door - keys, screwdrivers, even a rubber duck - to see if anything unlocks it. Brute-forcing would be like trying every combination on a key ring until you find the one that opens the door.

### Why Fuzz Web Applications?

Web applications have become the backbone of modern businesses and communication, handling vast amounts of sensitive data and enabling critical online interactions. However, their complexity and interconnectedness also make them prime targets for cyberattacks. Manual testing, while essential, can only go so far in identifying vulnerabilities. Here's where web fuzzing shines:

- `Uncovering Hidden Vulnerabilities`: Fuzzing can uncover vulnerabilities that traditional security testing methods might miss. By bombarding a web application with unexpected and invalid inputs, fuzzing can trigger unexpected behaviors that reveal hidden flaws in the code.
- `Automating Security Testing`: Fuzzing automates generating and sending test inputs, saving valuable time and resources. This allows security teams to focus on analyzing results and addressing the vulnerabilities found.
- `Simulating Real-World Attacks`: Fuzzers can mimic attackers' techniques, helping you identify weaknesses before malicious actors exploit them. This proactive approach can significantly reduce the risk of a successful attack.
- `Strengthening Input Validation`: Fuzzing helps identify weaknesses in input validation mechanisms, which are crucial for preventing common vulnerabilities like `SQL injection` and `cross-site scripting` (`XSS`).
- `Improving Code Quality`: Fuzzing improves overall code quality by uncovering bugs and errors. Developers can use the feedback from fuzzing to write more robust and secure code.
- `Continuous Security`: Fuzzing can be integrated into the `software development lifecycle` (`SDLC`) as part of `continuous integration and continuous deployment` (`CI/CD`) pipelines, ensuring that security testing is performed regularly and vulnerabilities are caught early in the development process.

In a nutshell, web fuzzing is an indispensable tool in the arsenal of any security professional. By proactively identifying and addressing vulnerabilities through fuzzing, you can significantly enhance the security of your web applications and protect them from potential threats.

## Essential Concepts

Before we dive into the practical aspects of web fuzzing, it's important to understand some key concepts:

| Concept             | Description                                                                                                                                                          | Example                                                                                                                   |
| ------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `Wordlist`          | A dictionary or list of words, phrases, file names, directory names, or parameter values used as input during fuzzing.                                               | Generic: `admin`, `login`, `password`, `backup`, `config`  <br>Application-specific: `productID`, `addToCart`, `checkout` |
| `Payload`           | The actual data sent to the web application during fuzzing. Can be a simple string, numerical value, or complex data structure.                                      | `' OR 1=1 --` (for SQL injection)                                                                                         |
| `Response Analysis` | Examining the web application's responses (e.g., response codes, error messages) to the fuzzer's payloads to identify anomalies that might indicate vulnerabilities. | Normal: 200 OK  <br>Error (potential SQLi): 500 Internal Server Error with a database error message                       |
| `Fuzzer`            | A software tool that automates generating and sending payloads to a web application and analyzing the responses.                                                     | `ffuf`, `wfuzz`, `Burp Suite Intruder`                                                                                    |
| `False Positive`    | A result that is incorrectly identified as a vulnerability by the fuzzer.                                                                                            | A 404 Not Found error for a non-existent directory.                                                                       |
| `False Negative`    | A vulnerability that exists in the web application but is not detected by the fuzzer.                                                                                | A subtle logic flaw in a payment processing function.                                                                     |
| `Fuzzing Scope`     | The specific parts of the web application that you are targeting with your fuzzing efforts.                                                                          | Only fuzzing the login page or focusing on a particular API endpoint.                                                     |


# Tooling

---

In this module, we will utilize four powerful tools designed for web application reconnaissance and vulnerability assessment. To streamline our setup, we'll install them all upfront.

### Installing Go, Python and PIPX

You will require Go and Python installed for these tools. Install them as follows if you don't have them installed already.

`pipx` is a command-line tool designed to simplify the installation and management of Python applications. It streamlines the process by creating isolated virtual environments for each application, ensuring that dependencies don't conflict. This means you can install and run multiple Python applications without worrying about compatibility issues. `pipx` also makes it easy to upgrade or uninstall applications, keeping your system organized and clutter-free.

If you are using a Debian-based system (like Ubuntu), you can install Go, Python, and PIPX using the APT package manager.

1. Open a terminal and update your package lists to ensure you have the latest information on the newest versions of packages and their dependencies.
    
            shellsession
    `er2oneousbit@htb[/htb]$ sudo apt update`
    
2. Use the following command to install Go:
    
            shellsession
    `er2oneousbit@htb[/htb]$ sudo apt install -y golang`
    
3. Use the following command to install Python:
    
            shellsession
    `er2oneousbit@htb[/htb]$ sudo apt install -y python3 python3-pip`
    
4. Use the following command to install and configure pipx:
    
            shellsession
    `er2oneousbit@htb[/htb]$ sudo apt install pipx er2oneousbit@htb[/htb]$ pipx ensurepath er2oneousbit@htb[/htb]$ sudo pipx ensurepath --global`
    
5. To ensure that Go and Python are installed correctly, you can check their versions:
    
            shellsession
    `er2oneousbit@htb[/htb]$ go version er2oneousbit@htb[/htb]$ python3 --version`
    

If the installations were successful, you should see the version information for both Go and Python.

## FFUF

`FFUF` (`Fuzz Faster U Fool`) is a fast web fuzzer written in Go. It excels at quickly enumerating directories, files, and parameters within web applications. Its flexibility, speed, and ease of use make it a favorite among security professionals and enthusiasts.

You can install `FFUF` using the following command:

        shellsession
`er2oneousbit@htb[/htb]$ go install github.com/ffuf/ffuf/v2@latest`

### Use Cases

|Use Case|Description|
|---|---|
|`Directory and File Enumeration`|Quickly identify hidden directories and files on a web server.|
|`Parameter Discovery`|Find and test parameters within web applications.|
|`Brute-Force Attack`|Perform brute-force attacks to discover login credentials or other sensitive information.|

## Gobuster

`Gobuster` is another popular web directory and file fuzzer. It's known for its speed and simplicity, making it a great choice for beginners and experienced users alike.

You can install `GoBuster` using the following command:

        shellsession
`er2oneousbit@htb[/htb]$ go install github.com/OJ/gobuster/v3@latest`

### Use Cases

|Use Case|Description|
|---|---|
|`Content Discovery`|Quickly scan and find hidden web content such as directories, files, and virtual hosts.|
|`DNS Subdomain Enumeration`|Identify subdomains of a target domain.|
|`WordPress Content Detection`|Use specific wordlists to find WordPress-related content.|

## FeroxBuster

`FeroxBuster` is a fast, recursive content discovery tool written in Rust. It's designed for brute-force discovery of unlinked content in web applications, making it particularly useful for identifying hidden directories and files. It's more of a "forced browsing" tool than a fuzzer like `ffuf`.

To install `FeroxBuster`, you can use the following command:

        shellsession
`er2oneousbit@htb[/htb]$ curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin`

### Use Cases

|Use Case|Description|
|---|---|
|`Recursive Scanning`|Perform recursive scans to discover nested directories and files.|
|`Unlinked Content Discovery`|Identify content that is not linked within the web application.|
|`High-Performance Scans`|Benefit from Rust's performance to conduct high-speed content discovery.|

## wfuzz/wenum

`wenum` is an actively maintained fork of `wfuzz`, a highly versatile and powerful command-line fuzzing tool known for its flexibility and customization options. It's particularly well-suited for parameter fuzzing, allowing you to test a wide range of input values against web applications and uncover potential vulnerabilities in how they process those parameters.

If you are using a penetration testing Linux distribution like PwnBox or Kali, `wfuzz` may already be pre-installed, allowing you to use it right away if desired. However, there are currently complications when installing `wfuzz`, so you can substitute it with `wenum` instead. The commands are interchangeable, and they follow the same syntax, so you can simply replace `wenum` commands with `wfuzz` if necessary.

The following commands will use `pipx`, a tool for installing and managing Python applications in isolated environments, to install `wenum`. This ensures a clean and consistent environment for `wenum`, preventing any possible package conflicts:

        shellsession
`er2oneousbit@htb[/htb]$ pipx install git+https://github.com/WebFuzzForge/wenum er2oneousbit@htb[/htb]$ pipx runpip wenum install setuptools`

### Use Cases

| Use Case                         | Description                                                                               |
| -------------------------------- | ----------------------------------------------------------------------------------------- |
| `Directory and File Enumeration` | Quickly identify hidden directories and files on a web server.                            |
| `Parameter Discovery`            | Find and test parameters within web applications.                                         |
| `Brute-Force Attack`             | Perform brute-force attacks to discover login credentials or other sensitive information. |


# Directory and File Fuzzing

---

Web applications often have directories and files that are not directly linked or visible to users. These hidden resources may contain sensitive information, backup files, configuration files, or even old, vulnerable application versions. Directory and file fuzzing aims to uncover these hidden assets, providing attackers with potential entry points or valuable information for further exploitation.

## Uncovering Hidden Assets

Web applications often house a treasure trove of hidden resources — directories, files, and endpoints that aren't readily accessible through the main interface. These concealed areas might hold valuable information for attackers, including:

- `Sensitive data`: Backup files, configuration settings, or logs containing user credentials or other confidential information.
- `Outdated content`: Older versions of files or scripts that may be vulnerable to known exploits.
- `Development resources`: Test environments, staging sites, or administrative panels that could be leveraged for further attacks.
- `Hidden functionalities`: Undocumented features or endpoints that could expose unexpected vulnerabilities.

Discovering these hidden assets is crucial for security researchers and penetration testers. It provides a deeper understanding of a web application's attack surface and potential vulnerabilities.

### The Importance of Finding Hidden Assets

Uncovering these hidden gems is far from trivial. Each discovery contributes to a complete picture of the web application's structure and functionality, essential for a thorough security assessment. These hidden areas often lack the robust security measures found in public-facing components, making them prime targets for exploitation. By proactively identifying these vulnerabilities, you can stay one step ahead of malicious actors.

Even if a hidden asset doesn't immediately reveal a vulnerability, the information gleaned can prove invaluable in the later stages of a penetration test. This could include anything from understanding the underlying technology stack to discovering sensitive data that can be used for further attacks.

`Directory and file fuzzing` are among the most effective methods for uncovering these hidden assets. This involves systematically probing the web application with a list of potential directory and file names and analyzing the server's responses to identify valid resources.

## Wordlists

Wordlists are the lifeblood of directory and file fuzzing. They provide the potential directory and file names your chosen tool will use to probe the web application. Effective wordlists can significantly increase your chances of discovering hidden assets.

Wordlists are typically compiled from various sources. This often includes scraping the web for common directory and file names, analyzing publicly available data breaches, and extracting directory information from known vulnerabilities. These wordlists are then meticulously curated, removing duplicates and irrelevant entries to ensure optimal efficiency and effectiveness during fuzzing operations. The goal is to create a comprehensive list of potential directories and file names that will likely be found on web servers, allowing you to thoroughly probe a target application for hidden assets.

The tools we've discussed – `ffuf`, `wfuzz`, etc – don't have built-in wordlists, but they are designed to work seamlessly with external wordlist files. This flexibility allows you to use pre-existing wordlists or create your own to tailor your fuzzing efforts to specific targets and scenarios.

One of the most comprehensive and widely-used collections of wordlists is `SecLists`. This open-source project on GitHub ([https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists)) provides a vast repository of wordlists for various security testing purposes, including directory and file fuzzing.

**On pwnbox specifically, the seclists folder is located in /usr/share/seclists/, all lowercase, but other distributions might name it as per the repository, SecLists, so if a command doesn't work, double check the wordlist path.**

`SecLists` contains wordlists for:

- Common directory and file names
- Backup files
- Configuration files
- Vulnerable scripts
- And much more

The most commonly used wordlists for fuzzing web directories and files from `SecLists` are:

- `Discovery/Web-Content/common.txt`: This general-purpose wordlist contains a broad range of common directory and file names on web servers. It's an excellent starting point for fuzzing and often yields valuable results.
- `Discovery/Web-Content/directory-list-2.3-medium.txt`: This is a more extensive wordlist specifically focused on directory names. It's a good choice when you need a deeper dive into potential directories.
- `Discovery/Web-Content/raft-large-directories.txt`: This wordlist boasts a massive collection of directory names compiled from various sources. It's a valuable resource for thorough fuzzing campaigns.
- `Discovery/Web-Content/big.txt`: As the name suggests, this is a massive wordlist containing both directory and file names. It's useful when you want to cast a wide net and explore all possibilities.

## Actually Fuzzing

Now that you understand the concept of wordlists, let's dive into the fuzzing process. We'll use `ffuf`, a powerful and flexible fuzzing tool, to uncover hidden directories and files on our target web application.

**To follow along, start the target system via the question section at the bottom of the page, replacing the uses of IP:PORT with the IP:PORT for your spawned instance.**

### ffuf

We will use `ffuf` for this fuzzing task. Here's how `ffuf` generally works:

1. `Wordlist`: You provide `ffuf` with a wordlist containing potential directory or file names.
2. `URL with FUZZ keyword`: You construct a URL with the `FUZZ` keyword as a placeholder where the wordlist entries will be inserted.
3. `Requests`: `ffuf` iterates through the wordlist, replacing the `FUZZ` keyword in the URL with each entry and sending HTTP requests to the target web server.
4. `Response Analysis`: `ffuf` analyzes the server's responses (status codes, content length, etc.) and filters the results based on your criteria.

For example, if you want to fuzz for directories, you might use a URL like this:

        http
`http://localhost/FUZZ`

`ffuf` will replace `FUZZ` with words like "`admin`," "`backup`," "`uploads`," etc., from your chosen wordlist and then send requests to `http://localhost/admin`, `http://localhost/backup`, and so on.

### Directory Fuzzing

The first step is to perform directory fuzzing, which helps us discover hidden directories on the web server. Here's the ffuf command we'll use:

        shellsession
`er2oneousbit@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ         /'___\  /'___\           /'___\       /\ \__/ /\ \__/  __  __  /\ \__/       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         \ \_\   \ \_\  \ \____/  \ \_\          \/_/    \/_/   \/___/    \/_/               v2.1.0-dev ________________________________________________  :: Method           : GET :: URL              : http://IP:PORT/FUZZ :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt :: Follow redirects : false :: Calibration      : false :: Timeout          : 10 :: Threads          : 40 :: Matcher          : Response status: 200-399 ________________________________________________ [...] w2ksvrus                [Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 0ms] :: Progress: [220559/220559] :: Job [1/1] :: 100000 req/sec :: Duration: [0:00:03] :: Errors: 0 ::`

- `-w` (wordlist): Specifies the path to the wordlist we want to use. In this case, we're using a medium-sized directory list from SecLists.
- `-u` (URL): Specifies the base URL to fuzz. The `FUZZ` keyword acts as a placeholder where the fuzzer will insert words from the wordlist.

The output above shows that `ffuf` has discovered a directory called `w2ksvrus` on the target web server, as indicated by the 301 (Moved Permanently) status code. This could be a potential entry point for further investigation.

### File Fuzzing

While directory fuzzing focuses on finding folders, file fuzzing dives deeper into discovering specific files within those directories or even in the root of the web application. Web applications use various file types to serve content and perform different functions. Some common file extensions include:

- `.php`: Files containing PHP code, a popular server-side scripting language.
- `.html`: Files that define the structure and content of web pages.
- `.txt`: Plain text files, often storing simple information or logs.
- `.bak`: Backup files are created to preserve previous versions of files in case of errors or modifications.
- `.js`: Files containing JavaScript code add interactivity and dynamic functionality to web pages.

By fuzzing for these common extensions with a wordlist of common file names, we increase our chances of discovering files that might be unintentionally exposed or misconfigured, potentially leading to information disclosure or other vulnerabilities.

For example, if the website uses PHP, discovering a backup file like `config.php.bak` could reveal sensitive information such as database credentials or API keys. Similarly, finding an old or unused script like `test.php` might expose vulnerabilities that attackers could exploit.

Utilize `ffuf` and a wordlist of common file names to search for hidden files with specific extensions:

        shellsession
`er2oneousbit@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/w2ksvrus/FUZZ -e .php,.html,.txt,.bak,.js -v          /'___\  /'___\           /'___\       /\ \__/ /\ \__/  __  __  /\ \__/       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/         \ \_\   \ \_\  \ \____/  \ \_\          \/_/    \/_/   \/___/    \/_/               v2.1.0-dev ________________________________________________  :: Method           : GET :: URL              : http://IP:PORT/w2ksvrus/FUZZ.html :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt :: Extensions       : .php .html .txt .bak .js :: Follow redirects : false :: Calibration      : false :: Timeout          : 10 :: Threads          : 40 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500 ________________________________________________ [Status: 200, Size: 111, Words: 2, Lines: 2, Duration: 0ms] | URL | http://IP:PORT/w2ksvrus/dblclk.html     * FUZZ: dblclk [Status: 200, Size: 112, Words: 6, Lines: 2, Duration: 0ms] | URL | http://IP:PORT/w2ksvrus/index.html     * FUZZ: index :: Progress: [28362/28362] :: Job [1/1] :: 0 req/sec :: Duration: [0:00:00] :: Errors: 0 ::`

The `ffuf` output shows that it discovered two files within the `/w2ksvrus` directory:

- `dblclk.html`: This file is 111 bytes in size and consists of 2 words and 2 lines. Its purpose might not be immediately apparent, but it's a potential point of interest for further investigation. Perhaps it contains hidden content or functionality.
- `index.html`: This file is slightly larger at 112 bytes and contains 6 words and 2 lines. It's likely the default index page for the `w2ksvrus` directory.

Recursive Fuzzing
So far, we've focused on fuzzing directories directly under the web root and files within a single directory. But what if our target has a complex structure with multiple nested directories? Manually fuzzing each level would be tedious and time-consuming. This is where recursive fuzzing comes in handy.

How Recursive Fuzzing Works
Recursive fuzzing is an automated way to delve into the depths of a web application's directory structure. It's a pretty basic 3 step process:

Initial Fuzzing:
The fuzzing process begins with the top-level directory, typically the web root (/).
The fuzzer starts sending requests based on the provided wordlist containing the potential directory and file names.
The fuzzer analyzes server responses, looking for successful results (e.g., HTTP 200 OK) that indicate the existence of a directory.
Directory Discovery and Expansion:
When a valid directory is found, the fuzzer doesn't just note it down. It creates a new branch for that directory, essentially appending the directory name to the base URL.
For example, if the fuzzer finds a directory named admin at the root level, it will create a new branch like http://localhost/admin/.
This new branch becomes the starting point for a fresh fuzzing process. The fuzzer will again iterate through the wordlist, appending each entry to the new branch's URL (e.g., http://localhost/admin/FUZZ).
Iterative Depth:
The process repeats for each discovered directory, creating further branches and expanding the fuzzing scope deeper into the web application's structure.
This continues until a specified depth limit is reached (e.g., a maximum of three levels deep) or no more valid directories are found.
Imagine a tree structure where the web root is the trunk, and each discovered directory is a branch. Recursive fuzzing systematically explores each branch, going deeper and deeper until it reaches the leaves (files) or encounters a predetermined stopping point.

Why Use Recursive Fuzzing?
Recursive fuzzing is a practical necessity when dealing with complex web applications:

Efficiency: Automating the discovery of nested directories saves significant time compared to manual exploration.
Thoroughness: It systematically explores every branch of the directory structure, reducing the risk of missing hidden assets.
Reduced Manual Effort: You don't need to input each new directory to fuzz manually; the tool handles the entire process.
Scalability: It's particularly valuable for large-scale web applications where manual exploration would be impractical.
In essence, recursive fuzzing is about working smarter, not harder. It allows you to efficiently and comprehensively probe the depths of a web application, uncovering potential vulnerabilities that might be lurking in its hidden corners.

Recursive Fuzzing with ffuf
To follow along, start the target system via the question section at the bottom of the page, replacing the uses of IP:PORT with the IP:PORT for your spawned instance. We will be using the /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt wordlists for these fuzzing tasks.

Let's use ffuf to demonstrate recursive fuzzing:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -v -u http://IP:PORT/FUZZ -e .html -recursion 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://IP:PORT/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .html 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
| URL | http://IP:PORT/level1
| --> | /level1/
    * FUZZ: level1

[INFO] Adding a new job to the queue: http://IP:PORT/level1/FUZZ

[INFO] Starting queued job on target: http://IP:PORT/level1/FUZZ

[Status: 200, Size: 96, Words: 6, Lines: 2, Duration: 0ms]
| URL | http://IP:PORT/level1/index.html
    * FUZZ: index.html

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
| URL | http://IP:PORT/level1/level2
| --> | /level1/level2/
    * FUZZ: level2

[INFO] Adding a new job to the queue: http://IP:PORT/level1/level2/FUZZ

[Status: 301, Size: 0, Words: 1, Lines: 1, Duration: 0ms]
| URL | http://IP:PORT/level1/level3
| --> | /level1/level3/
    * FUZZ: level3

[INFO] Adding a new job to the queue: http://IP:PORT/level1/level3/FUZZ

[INFO] Starting queued job on target: http://IP:PORT/level1/level2/FUZZ

[Status: 200, Size: 96, Words: 6, Lines: 2, Duration: 0ms]
| URL | http://IP:PORT/level1/level2/index.html
    * FUZZ: index.html

[INFO] Starting queued job on target: http://IP:PORT/level1/level3/FUZZ

[Status: 200, Size: 126, Words: 8, Lines: 2, Duration: 0ms]
| URL | http://IP:PORT/level1/level3/index.html
    * FUZZ: index.html

:: Progress: [441088/441088] :: Job [4/4] :: 100000 req/sec :: Duration: [0:00:06] :: Errors: 0 ::

Notice the addition of the -recursion flag. This tells ffuf to fuzz any directories it finds recursively. For example, if ffuf discovers an admin directory, it will automatically start a new fuzzing process on http://localhost/admin/FUZZ. In fuzzing scenarios where wordlists contain comments (lines starting with #), the ffuf -ic option proves invaluable. By enabling this option, ffuf intelligently ignores commented lines during fuzzing, preventing them from being treated as valid inputs.

The fuzzing commences at the web root (http://IP:PORT/FUZZ). Initially, ffuf identifies a directory named level1, indicated by a 301 (Moved Permanently) response. This signifies a redirection and prompts the tool to initiate a new fuzzing process within this directory, effectively branching out its search.

As ffuf recursively explores level1, it uncovers two additional directories: level2 and level3. Each is added to the fuzzing queue, expanding the search depth. Furthermore, an index.html file is discovered within level1.

The fuzzer systematically works through its queue, identifying index.html files in both level2 and level3. Notably, the index.html file within level3 stands out due to its larger file size than the others.

Further analysis reveals this file contains the flag HTB{r3curs1v3_fuzz1ng_w1ns}, signifying a successful exploration of the nested directory structure.

Be Responsible
While recursive fuzzing is a powerful technique, it can also be resource-intensive, especially on large web applications. Excessive requests can overwhelm the target server, potentially causing performance issues or triggering security mechanisms.

To mitigate these risks, ffuf provides options for fine-tuning the recursive fuzzing process:

-recursion-depth: This flag allows you to set a maximum depth for recursive exploration. For example, -recursion-depth 2 limits fuzzing to two levels deep (the starting directory and its immediate subdirectories).
-rate: You can control the rate at which ffuf sends requests per second, preventing the server from being overloaded.
-timeout: This option sets the timeout for individual requests, helping to prevent the fuzzer from hanging on unresponsive targets.
        shellsession
er2oneousbit@htb[/htb]$ ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ic -u http://IP:PORT/FUZZ -e .html -recursion -recursion-depth 2 -rate 500

Parameter and Value Fuzzing
Building upon the discovery of hidden directories and files, we now delve into parameter and value fuzzing. This technique focuses on manipulating the parameters and their values within web requests to uncover vulnerabilities in how the application processes input.

Parameters are the messengers of the web, carrying vital information between your browser and the server that hosts the web application. They're like variables in programming, holding specific values that influence how the application behaves.

GET Parameters: Openly Sharing Information
You'll often spot GET parameters right in the URL, following a question mark (?). Multiple parameters are strung together using ampersands (&). For example:

        http
https://example.com/search?query=fuzzing&category=security

In this URL:

query is a parameter with the value "fuzzing"
category is another parameter with the value "security"
GET parameters are like postcards – their information is visible to anyone who glances at the URL. They're primarily used for actions that don't change the server's state, like searching or filtering.

POST Parameters: Behind-the-Scenes Communication
While GET parameters are like open postcards, POST parameters are more like sealed envelopes, carrying their information discreetly within the body of the HTTP request. They are not visible directly in the URL, making them the preferred method for transmitting sensitive data like login credentials, personal information, or financial details.

When you submit a form or interact with a web page that uses POST requests, the following happens:

Data Collection: The information entered into the form fields is gathered and prepared for transmission.
Encoding: This data is encoded into a specific format, typically application/x-www-form-urlencoded or multipart/form-data:
application/x-www-form-urlencoded: This format encodes the data as key-value pairs separated by ampersands (&), similar to GET parameters but placed within the request body instead of the URL.
multipart/form-data: This format is used when submitting files along with other data. It divides the request body into multiple parts, each containing a specific piece of data or a file.
HTTP Request: The encoded data is placed within the body of an HTTP POST request and sent to the web server.
Server-Side Processing: The server receives the POST request, decodes the data, and processes it according to the application's logic.
Here's a simplified example of how a POST request might look when submitting a login form:

        http
POST /login HTTP/1.1
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=your_username&password=your_password

POST: Indicates the HTTP method (POST).
/login: Specifies the URL path where the form data is sent.
Content-Type: Specifies how the data in the request body is encoded (application/x-www-form-urlencoded in this case).
Request Body: Contains the encoded form data as key-value pairs (username and password).
Why Parameters Matter for Fuzzing
Parameters are the gateways through which you can interact with a web application. By manipulating their values, you can test how the application responds to different inputs, potentially uncovering vulnerabilities. For instance:

Altering a product ID in a shopping cart URL could reveal pricing errors or unauthorized access to other users' orders.
Modifying a hidden parameter in a request might unlock hidden features or administrative functions.
Injecting malicious code into a search query could expose vulnerabilities like Cross-Site Scripting (XSS) or SQL Injection (SQLi).
wenum
In this section, we'll leverage wenum to explore both GET and POST parameters within our target web application, ultimately aiming to uncover hidden values that trigger unique responses, potentially revealing vulnerabilities.

To follow along, start the target system via the question section at the bottom of the page, replacing the uses of IP:PORT with the IP:PORT for your spawned instance. We will be using the /usr/share/seclists/Discovery/Web-Content/common.txt wordlists for these fuzzing tasks.

Let's first ready our tools by installing wenum to our attack host:

        shellsession
er2oneousbit@htb[/htb]$ pipx install git+https://github.com/WebFuzzForge/wenum
er2oneousbit@htb[/htb]$ pipx runpip wenum install setuptools

Then to begin, we will use curl to manually interact with the endpoint and gain a better understanding of its behavior:

        shellsession
er2oneousbit@htb[/htb]$ curl http://IP:PORT/get.php

Invalid parameter value
x:

The response tells us that the parameter x is missing. Let's try adding a value:

        shellsession
er2oneousbit@htb[/htb]$ curl http://IP:PORT/get.php?x=1

Invalid parameter value
x: 1

The server acknowledges the x parameter this time but indicates that the provided value (1) is invalid. This suggests that the application is indeed checking the value of this parameter and producing different responses based on its validity. We aim to find the specific value to trigger a different and hopefully more revealing response.

Manually guessing parameter values would be tedious and time-consuming. This is where wenum comes in handy. It allows us to automate the process of testing many potential values, significantly increasing our chances of finding the correct one.

Let's use wenum to fuzz the "x" parameter's value, starting with the common.txt wordlist from SecLists:

        shellsession
er2oneousbit@htb[/htb]$ wenum -w /usr/share/seclists/Discovery/Web-Content/common.txt --hc 404 -u "http://IP:PORT/get.php?x=FUZZ"

...
 Code    Lines     Words        Size  Method   URL 
...
 200       1 L       1 W        25 B  GET      http://IP:PORT/get.php?x=OA... 

Total time: 0:00:02
Processed Requests: 4731
Filtered Requests: 4730
Requests/s: 1681

-w: Path to your wordlist.
--hc 404: Hides responses with the 404 status code (Not Found), since wenum by default will log every request it makes.
http://IP:PORT/get.php?x=FUZZ: This is the target URL. wenum will replace the parameter value FUZZ with words from the wordlist.
Analyzing the results, you'll notice that most requests return the "Invalid parameter value" message and the incorrect value you tried. However, one line stands out:

        bash
 200       1 L       1 W        25 B  GET      http://IP:PORT/get.php?x=OA...

This indicates that when the parameter x was set to the value "OA...," the server responded with a 200 OK status code, suggesting a valid input.

If you try accessing http://IP:PORT/get.php?x=OA..., you'll see the flag.

        shellsession
er2oneousbit@htb[/htb]$ curl http://IP:PORT/get.php?x=OA...

HTB{...}

POST
Fuzzing POST parameters requires a slightly different approach than fuzzing GET parameters. Instead of appending values directly to the URL, we'll use ffuf to send the payloads within the request body. This enables us to test how the application handles data submitted through forms or other POST mechanisms.

Our target application also features a POST parameter named "y" within the post.php script. Let's probe it with curl to see its default behavior:

        shellsession
er2oneousbit@htb[/htb]$ curl -d "" http://IP:PORT/post.php

Invalid parameter value
y:

The -d flag instructs curl to make a POST request with an empty body. The response tells us that the parameter y is expected but not provided.

As with GET parameters, manually testing POST parameter values would be inefficient. We'll use ffuf to automate this process:

        shellsession
er2oneousbit@htb[/htb]$ ffuf -u http://IP:PORT/post.php -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "y=FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -mc 200 -v

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : http://IP:PORT/post.php
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Data             : y=FUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200
________________________________________________

[Status: 200, Size: 26, Words: 1, Lines: 2, Duration: 7ms]
| URL | http://IP:PORT/post.php
    * FUZZ: SU...

:: Progress: [4730/4730] :: Job [1/1] :: 5555 req/sec :: Duration: [0:00:01] :: Errors: 0 ::

The main difference here is the use of the -d flag, which tells ffuf that the payload ("y=FUZZ") should be sent in the request body as POST data.

Again, you'll see mostly invalid parameter responses. The correct value ("SU...") will stand out with its 200 OK status code:

        bash
000000326:  200     1 L      1 W     26 Ch     "SU..."

Similarly, after identifying "SU..." as the correct value, validate it with curl:

        shellsession
er2oneousbit@htb[/htb]$ curl -d "y=SU..." http://IP:PORT/post.php

HTB{...}

In a real-world scenario, these flags would not be present, and identifying valid parameter values might require a more nuanced analysis of the responses. However, this exercise provides a simplified demonstration of how to leverage ffuf to automate the process of testing many potential parameter values.