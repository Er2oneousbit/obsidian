# PurplePanda

**Tags:** `#purplepanda` `#gcp` `#cloud` `#workspace` `#attackpaths` `#privesc` `#neo4j` `#python`

carlospolop's cross-platform attack-path grapher — enumerates cloud/SaaS environments and
builds a **Neo4j graph** (BloodHound-style) of privilege-escalation paths **within and across**
platforms. Its edge over single-cloud tools: it finds chains that hop between GCP, Google
**Workspace**, GitHub, Kubernetes, and more — e.g. a GitHub token → a GCP SA → Workspace admin.
For GCP work it complements the single-platform view of [[Tools/Cloud/gcpwn|gcpwn]] /
[[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] with the cross-platform picture.

**Source:** https://github.com/carlospolop/PurplePanda
**Install:** needs **Neo4j** (Desktop or a container) — create a DB, then:
```bash
git clone https://github.com/carlospolop/PurplePanda && cd PurplePanda
pip install -r requirements.txt
gcloud components install gke-gcloud-auth-plugin      # for the k8s/GKE side
```

---

## Setup — Credentials via Env Vars

Point it at Neo4j and give each platform a **`*_DISCOVERY`** variable holding a base64-encoded
YAML config that describes the credentials/scope to use:

```bash
export PURPLEPANDA_NEO4J_URL="bolt://localhost:7687"
export PURPLEPANDA_PWD="<neo4j-password>"
export GOOGLE_DISCOVERY=$(base64 -w0 google_discovery.yaml)   # GCP + Workspace config
# plus GITHUB_DISCOVERY / K8S_DISCOVERY / … per platform in scope
# optional: export SHODAN_KEY=<key>   # enrich exposed-IP analysis
```

---

## Run

```bash
# Enumerate: pull data from the platforms AND analyse it into the graph
python3 main.py -e -p google,github,k8s --gcp-get-secret-values --k8s-get-secret-values

# Analyze only: (re-)run the privesc analysis over data already in Neo4j
python3 main.py -a -p google
```

- **`-e` enumerate** — collect + analyse (the full run).
- **`-a` analyze** — just re-run path analysis on existing graph data.
- **`-p`** — comma-separated platforms (`google`, `github`, `k8s`, …).
- `--gcp-get-secret-values` pulls actual secret values while enumerating GCP.

---

## What You Get

A Neo4j graph you query in the Neo4j Browser: nodes for principals/resources/roles, edges for
the permissions that let one reach another. Hunt for paths into `roles/owner`,
Workspace **super-admin**, or org-level roles — including chains that cross from GitHub or
Kubernetes into GCP. Export/inspect the same way you would a BloodHound graph.

> [!note] **See also** — single-platform GCP peers: [[Tools/Cloud/gcpwn|gcpwn]] (framework, has its own `opengraph` attack-path analysis), [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] (per-permission privesc), [[Tools/Cloud/gcloud-cli|gcloud-cli]]. The Azure/Entra graph equivalent is [[Tools/Cloud/AzureHound|AzureHound]] → [[Tools/AD/BloodHound|BloodHound]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
