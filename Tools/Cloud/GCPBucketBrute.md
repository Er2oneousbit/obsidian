# GCPBucketBrute

**Tags:** `#gcpbucketbrute` `#gcp` `#cloud` `#storage` `#gcs` `#enumeration` `#bucketbrute` `#python`

RhinoSecurityLabs tool for discovering **Google Cloud Storage buckets** by keyword
permutation, then testing what access each one grants — read, write, and (the prize)
`storage.buckets.setIamPolicy`, which is a bucket-level privilege-escalation path. The GCP
analog of an S3-bucket sweep; runs **authenticated** (with a Google account / service-account
key) or **fully unauthenticated**.

**Source:** https://github.com/RhinoSecurityLabs/GCPBucketBrute
**Install:**
```bash
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute && cd GCPBucketBrute
pip3 install -r requirements.txt
```

---

## Usage

```bash
# Unauthenticated — no creds, no prompts (baseline external check)
python3 gcpbucketbrute.py -k <keyword> -u

# Authenticated with a service-account key — sees more (auth-only buckets, richer perms)
python3 gcpbucketbrute.py -k <keyword> -f ./sa-priv-key.json -o ./out.txt

# Authenticated as the active gcloud user, more parallelism
python3 gcpbucketbrute.py -k <keyword> -s 10

# Feed your own bucket-name wordlist instead of keyword permutations
python3 gcpbucketbrute.py -w buckets.txt -u

# Test permissions on ONE known bucket / a list of buckets (skip permutation)
python3 gcpbucketbrute.py --check <bucket-name>
python3 gcpbucketbrute.py --check-list buckets.txt
```

**Flags:** `-k/--keyword`, `-w/--wordlist`, `-u/--unauthenticated`, `--check <bucket>`,
`--check-list <file>`, `-f/--service-account-credential-file-path`, `-o/--out-file`,
`-s/--subprocesses` (default 5).

---

## What the Result Tells You

For each discovered bucket it reports the access level of your identity (or `allUsers` /
`allAuthenticatedUsers` when unauth):

- **read** — pull objects (`gcloud storage cp gs://<bucket>/… .` — configs, backups, keys).
- **write** — drop/overwrite objects (supply-chain / defacement).
- **`storage.buckets.setIamPolicy` / FULL_CONTROL** — **privilege escalation**: rewrite the
  bucket's IAM policy to grant yourself full control, then read/exfil everything.

> [!tip] A keyword like the target's name/brand surfaces `acme-backups`, `acme-prod-assets`,
> etc. Run **unauth first** (external attack surface), then re-run **authenticated** — many
> buckets deny `allUsers` but allow `allAuthenticatedUsers` (any Google account at all).

> [!note] **See also** — read/exfil found buckets with [[Tools/Cloud/gcloud-cli|gcloud-cli]]
> (`gcloud storage`); [[Tools/Cloud/gcpwn|gcpwn]] wraps the same idea in its `unauth_bucketbrute`
> module; the `setIamPolicy` win feeds [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]]. Multi-cloud
> misconfig audit incl. public buckets: [[Tools/Cloud/ScoutSuite|ScoutSuite]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
