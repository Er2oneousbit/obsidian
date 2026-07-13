## 🧪 Fuzzing

**Tags:** `#Fuzzing` `#WebSecurity` `#BugBounty` `#OWASP`

Fuzzing is a dynamic testing technique used to discover vulnerabilities by automatically injecting malformed, unexpected, or random data into inputs of a target application.

---

### 🔍 What is Fuzzing?

Fuzzing involves sending a large volume of varied inputs to a target to observe how it behaves. It helps uncover:

- Input validation issues
- Buffer overflows
- Logic flaws
- Authorization bypasses
- Unhandled exceptions

---

### 🧰 Types of Fuzzing

|**Type**|**Description**|
|---|---|
|**Black-box**|No knowledge of the internal workings. Focuses on inputs and outputs.|
|**White-box**|Full knowledge of the source code and internal logic.|
|**Grey-box**|Partial knowledge of the system. Often used in real-world testing.|
|**Mutation-based**|Alters existing valid inputs to create test cases.|
|**Generation-based**|Creates inputs from scratch based on input models or protocols.|

---

### 🛠️ Tools for Fuzzing

- **Web Fuzzers**
    - `ffuf` — Fast web fuzzer written in Go
    - `wfuzz` — Flexible web application fuzzer
    - `Burp Suite Intruder` — GUI-based fuzzing with payload sets
    - `dirsearch` — Directory brute-forcing
    - `gobuster` — Directory and DNS fuzzing
- **File Format Fuzzers**
    - `Peach Fuzzer`
    - `boofuzz`
- **Network Protocol Fuzzers**
	- `SPIKE` — Network protocol fuzzing
    - `Sulley`

---

### 📂 Wordlists

- SecLists — Comprehensive collection of wordlists
- PayloadsAllTheThings — Payloads for fuzzing and exploitation
- Custom wordlists based on:
    - Application context
    - Known parameters
    - Observed patterns

---

### 🎯 Fuzzing Targets

- **URL Parameters**
- **Form Fields**
- **HTTP Headers** (`User-Agent`, `Referer`, `X-Forwarded-For`, etc.)
- **Cookies**
- **File Uploads**
- **API Endpoints**
- **Hidden Fields / AJAX Calls**

---

### 🧪 Example: ffuf for Directory Fuzzing

```bash
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt -mc 200
```

- `-u`: Target URL with `FUZZ` keyword
- `-w`: Wordlist path
- `-mc`: Match HTTP status code (e.g., 200 OK)

---

### 🧠 Tips for Effective Fuzzing

- Use **context-aware** payloads (e.g., SQLi payloads for DB inputs)
- Monitor **response length**, **status codes**, and **error messages**
- Use **filters** in tools to reduce noise (e.g., `-fs`, `-fc`, `-mc` in ffuf)
- Combine with **proxy tools** (e.g., Burp Suite) for manual inspection
- Automate with **scripts** or **CI pipelines** for continuous fuzzing

---


