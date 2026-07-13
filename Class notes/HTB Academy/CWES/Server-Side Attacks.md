Introduction to Server-side Attacks
Server-side attacks target the application or service provided by a server, whereas client-side attacks occur at the client's machine, not the server itself. Understanding and identifying the differences is essential for penetration testing and bug bounty hunting.

For instance, vulnerabilities like Cross-Site Scripting (XSS) target the web browser, i.e., the client. On the other hand, server-side attacks target the web server. In this module, we will discuss four classes of server-side vulnerabilities:

Server-Side Request Forgery (SSRF)
Server-Side Template Injection (SSTI)
Server-Side Includes (SSI) Injection
eXtensible Stylesheet Language Transformations (XSLT) Server-Side Injection
Server-Side Request Forgery (SSRF)
Server-Side Request Forgery (SSRF) is a vulnerability that allows an attacker to manipulate a web application into sending unauthorized requests from the server. This vulnerability often occurs when an application makes HTTP requests to other servers based on user input. Successful exploitation of SSRF can enable an attacker to access internal systems, bypass firewalls, and retrieve sensitive information.

Server-Side Template Injection (SSTI)
Web applications can utilize templating engines and server-side templates to generate responses, such as HTML content dynamically. This generation is often based on user input, enabling the web application to respond to user input dynamically. When an attacker can inject template code, a Server-Side Template Injection vulnerability can occur. SSTI can lead to various security risks, including data leakage and even full server compromise via remote code execution.

Server-Side Includes (SSI) Injection
Similar to server-side templates, server-side includes (SSI) can be used to generate HTML responses dynamically. SSI directives instruct the web server to include additional content dynamically. These directives are embedded in HTML files. For instance, SSI can be used to include content that is present in all HTML pages, such as headers or footers. When an attacker can inject commands into the SSI directives, Server-Side Includes (SSI) Injection can occur. SSI injection can lead to data leakage or even remote code execution.

XSLT Server-Side Injection
XSLT (Extensible Stylesheet Language Transformations) server-side injection is a vulnerability that arises when an attacker can manipulate XSLT transformations performed on the server. XSLT is a language used to transform XML documents into other formats, such as HTML, and is commonly employed in web applications to generate content dynamically. In the context of XSLT server-side injection, attackers exploit weaknesses in how XSLT transformations are handled, allowing them to inject and execute arbitrary code on the server.



Introduction to SSRF
SSRF vulnerabilities are part of OWASP's Top 10. This type of vulnerability occurs when a web application fetches additional resources from a remote location based on user-supplied data, such as a URL.

Server-side Request Forgery
Suppose a web server fetches remote resources based on user input. In that case, an attacker might be able to coerce the server into making requests to arbitrary URLs supplied by the attacker, i.e., the web server is vulnerable to SSRF. While this might not sound particularly bad at first, depending on the web application's configuration, SSRF vulnerabilities can have devastating consequences, as we will see in the upcoming sections.

Furthermore, if the web application relies on a user-supplied URL scheme or protocol, an attacker might be able to cause even further undesired behavior by manipulating the URL scheme. For instance, the following URL schemes are commonly used in the exploitation of SSRF vulnerabilities:

http:// and https://: These URL schemes fetch content via HTTP/S requests. An attacker might use this in the exploitation of SSRF vulnerabilities to bypass WAFs, access restricted endpoints, or access endpoints in the internal network
file://: This URL scheme reads a file from the local file system. An attacker might use this in the exploitation of SSRF vulnerabilities to read local files on the web server (LFI)
gopher://: This protocol can send arbitrary bytes to the specified address. An attacker might use this in the exploitation of SSRF vulnerabilities to send HTTP POST requests with arbitrary payloads or communicate with other services, such as SMTP servers or databases
For more details on advanced SSRF exploitation techniques, such as filter bypasses and DNS rebinding, check out the Modern Web Exploitation Techniques module



