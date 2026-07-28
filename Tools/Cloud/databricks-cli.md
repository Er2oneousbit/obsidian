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

> [!note] **See also** — [[Services/Cloud & Data/Databricks|Databricks]] for the full attack methodology (PAT/OAuth theft, IMDS pivot, secret scopes, init-script abuse).

---

*Created: 2026-07-28*
*Updated: 2026-07-28*
*Model: claude-opus-4-8*
