# ScoutSuite

**Tags:** `#scoutsuite` `#aws` `#azure` `#gcp` `#cloud` `#multicloud` `#audit` `#misconfiguration` `#enumeration`

Multi-cloud security auditing tool from NCC Group. Collects configuration data from AWS, Azure, GCP, Alibaba, and Oracle Cloud, then generates an HTML report highlighting security misconfigurations, exposed resources, and dangerous settings. Not an exploitation tool — it's a security posture assessment / configuration audit tool. Excellent for identifying the attack surface before pivoting to exploitation tools.

**Source:** https://github.com/nccgroup/ScoutSuite
**Install:**
```bash
pip install scoutsuite
# Or
git clone https://github.com/nccgroup/ScoutSuite
pip install -r requirements.txt
```

> [!note] **ScoutSuite vs exploitation tools** — ScoutSuite maps what's misconfigured (open S3 buckets, overly permissive IAM, public snapshots, disabled logging, etc.). It doesn't exploit anything. Use it first for a complete picture of the attack surface, then use Pacu / MicroBurst / PowerZure for exploitation.

---

## AWS

```bash
# Authenticate first (AWS CLI config or environment vars)
aws configure    # enter Access Key ID + Secret
# Or: export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN

# Run full audit
scout aws

# Specific regions only
scout aws --regions us-east-1,us-west-2

# Specific services only (faster for targeted checks)
scout aws --services s3,iam,ec2

# With a named profile
scout aws --profile <profile-name>

# With STS assumed role
scout aws --profile <role-profile>

# Skip report generation (just collect data)
scout aws --no-browser
```

---

## Azure

```bash
# Interactive login
scout azure --cli

# Service principal
scout azure --service-principal \
  --client-id <app-id> \
  --client-secret <secret> \
  --tenant-id <tenant-id>

# Specific subscription
scout azure --cli --subscription-id <sub-id>

# Specific services
scout azure --cli --services storageaccounts,keyvaults,virtualmachines,sqldatabases
```

---

## GCP

```bash
# Application default credentials (gcloud auth application-default login)
scout gcp

# Service account key file
scout gcp --service-account /path/to/key.json

# Specific project
scout gcp --project-id <project-id>

# All projects accessible to the account
scout gcp --all-projects

# Specific services
scout gcp --services gcs,iam,compute,cloudsql,cloudfunction
```

---

## Output & Report

```bash
# Default: generates scoutsuite-report/ directory with HTML report
scout aws
# Open in browser:
firefox scoutsuite-report/scoutsuite_report.html

# Custom output directory
scout aws -o /tmp/client-audit

# Generate report from existing data (re-run without re-collecting)
scout aws --no-services    # skips collection, uses existing data

# Export findings as JSON (for automation/parsing)
# JSON is stored in scoutsuite-report/scoutsuite-results/
cat scoutsuite-report/scoutsuite-results/scoutsuite_results_aws-*.js | python3 -c "
import sys, json
data = json.loads(sys.stdin.read().lstrip('scoutsuite_results='))
# parse findings...
"
```

---

## Key Finding Categories

| Category | What to Look For |
|---|---|
| **IAM** | Users without MFA, root account usage, over-permissive policies, unused access keys |
| **S3 / Storage** | Public buckets, buckets without encryption, public access not blocked |
| **EC2 / Compute** | Public snapshots, security groups allowing 0.0.0.0/0, unencrypted volumes |
| **Logging** | CloudTrail disabled, no log validation, S3 access logs off |
| **Networking** | VPC flow logs off, default VPC in use, security groups with open ranges |
| **RDS / Databases** | Public instances, no encryption, automated backups disabled |
| **Key Management** | KMS keys without rotation, secrets in plaintext configs |
| **Serverless** | Lambda with admin IAM role, Functions with public access |
| **Monitoring** | GuardDuty disabled, Security Hub not configured, no alerting |

---

## Parsing Results from CLI

```bash
# Find all high-severity findings
grep -r '"level": "danger"' scoutsuite-report/scoutsuite-results/

# List all flagged resources
python3 - <<'EOF'
import json, glob

for f in glob.glob('scoutsuite-report/scoutsuite-results/*.js'):
    data = open(f).read()
    data = data[data.index('{'):]    # strip JS variable prefix
    results = json.loads(data)
    for service, sdata in results.get('services', {}).items():
        for rule in sdata.get('findings', {}).values():
            if rule.get('level') in ('danger', 'warning') and rule.get('items'):
                print(f"[{rule['level'].upper()}] {service}: {rule['description']}")
EOF
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
