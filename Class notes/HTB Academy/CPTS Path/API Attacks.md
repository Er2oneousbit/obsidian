#API #APIAttacks

Types of APIs

- [Representational State Transfer](https://ics.uci.edu/~fielding/pubs/dissertation/top.htm) (`REST`) is the most popular API style. It uses a `client-server` model where clients make requests to resources on a server using standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`). `RESTful` APIs are stateless, meaning each request contains all necessary information for the server to process it, and responses are typically serialized as JSON or XML.
- [Simple Object Access Protocol](https://www.w3.org/TR/2000/NOTE-SOAP-20000508/) (`SOAP`) uses XML for message exchange between systems. `SOAP` APIs are highly standardized and offer comprehensive features for security, transactions, and error handling, but they are generally more complex to implement and use than `RESTful` APIs.
- [GraphQL](https://graphql.org/) is an alternative style that provides a more flexible and efficient way to fetch and update data. Instead of returning a fixed set of fields for each resource, `GraphQL` allows clients to specify exactly what data they need, reducing over-fetching and under-fetching of data. `GraphQL` APIs use a single endpoint and a strongly-typed query language to retrieve data.
- [gRPC](https://grpc.io/) is a newer style that uses [Protocol Buffers](https://protobuf.dev/) for message serialization, providing a high-performance, efficient way to communicate between systems. `gRPC` APIs can be developed in a variety of programming languages and are particularly useful for microservices and distributed systems.

- Swagger [REST API Documentation Tool | Swagger UI](https://swagger.io/tools/swagger-ui/) files contain documentation on interacting with API


#### API Attacks
- **Broken Object Level Authorization (BOLA)**
	- API version of **Insecure Direct Object Reference (IDOR)**
	- API fails to verity user is authorized to access requested data
	- Gain authorization token
	- Test token on various endpoints, look for any that require roles or specific authorization
	- Test those endpoints to see if other roles/accounts data can be accessed
	- Can User `A` access user `B's` data when it shouldn't be able
	- Could be by `ID`, `GUID`, `User` or some other form of identification
	- Example on simple automation:
	```shell-session
	for ((i=1; i<= 20; i++)); do
	curl -s -w "\n" -X 'GET' \
	'http://94.237.49.212:43104/api/v1/supplier-companies/yearly-reports/'$i'' \
	-H 'accept: application/json' \
	-H 'Authorization: Bearer {INSERT TOKEN}' | jq
	done
	```
- **Broken Authentication**
	- When authentication can be bypassed
	- Look for any endpoint that doesnt use authentication, what info does it provide
	- Endpoints that require authentication do they work without it or incorrect creds
	- Example of fuff fuzzing email and password
	```shell-session
	ffuf -w /opt/useful/seclists/Passwords/xato-net-10-million-passwords-10000.txt:PASS -w customerEmails.txt:EMAIL -u http://94.237.59.63:31874/api/v1/authentication/customers/sign-in -X POST -H "Content-Type: application/json" -d '{"Email": "EMAIL", "Password": "PASS"}' -fr "Invalid Credentials" -t 100
	```
-**Broken Object Property Level Authorization**
	- `Excessive Data Exposure` reveals sensitive data to authorized users that they are not supposed to access.  aka TMI
		- Check users roles
		- Check all endpoints that return data
		- Any data returned that current user role/access level should not have?
	- `Mass Assignment` permits authorized users to manipulate sensitive object properties beyond their authorized scope, including modifying, adding, or deleting values.
		- Check users roles
		- Check any endpoint that can update (like **POST**) for permissions
		- If user does not have permission, are they allowed to update?
- **Unrestricted Resource Consumption**
	- aka no rate limiting
	- password brute forcing
	- unrestricted data upload, such as files
- **Broken Function Level Authorization (BFLA)**
	- allows unauthorized or unprivileged users to interact with and invoke privileged endpoints, granting access to sensitive operations or confidential information.
	- User shouldn't be be able to access resource 'XYZ' but they can
- **Unrestricted Access to Sensitive Business Flows**
	- exposes a sensitive business flow without appropriately restricting access to it.
- **Server Side Request Forgery (SSRF)**
	- also known as `Cross-Site Port Attack` (`XPSA`)
	- user-controlled input to fetch remote or local resources without validation
	- SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL
