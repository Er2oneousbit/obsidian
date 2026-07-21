# Cloud Security

#CloudSecurity #AWS #Azure #GCP #IAM #Enumeration

## What is this?

**Cloud Security** — Security practices and vulnerabilities specific to cloud environments (AWS, Azure, Google Cloud, etc.). Covers cloud-native risks: misconfigured buckets, overprivileged IAM roles, credential exposure, cloud metadata service abuse, supply chain risks, and compliance in shared responsibility model.

---

## Overview

**Cloud Security Basics:**
- **Purpose**: Identify and mitigate cloud-specific security risks.
- **Scope**: IaaS (EC2, GCP Compute), PaaS (Lambda, CloudRun), data services (S3, BigQuery), identity/access, networking.
- **Audience**: Cloud engineers, DevOps, security teams, architects.

**Why Cloud Adds Risk**:
- **Shared responsibility model** (cloud provider secures infrastructure; customer secures applications/data).
- **API-driven** (security misconfiguration easy; misplaced access control).
- **Massive scale** (mistakes affect 1000s of resources).
- **Speed over security** (development speed prioritized; security checks skipped).

---

## Cloud Shared Responsibility Model

```
AWS/Azure/GCP Provider Responsibility:
├─ Physical infrastructure security
├─ Network security
├─ Host operating system security
└─ Hypervisor security

Customer Responsibility:
├─ Application security
├─ Identity and access management (IAM)
├─ Data classification and encryption
├─ Network configuration
├─ Firewall rules
└─ Operating system patches (on customer-managed instances)
```

**Key Point**: Provider secures infrastructure, but customers must secure applications and data.

---

## Cloud Security Domains

### 1. Identity and Access Management (IAM)

**Risks**:
- **Overprivileged accounts** (more permissions than needed).
- **Credential exposure** (API keys, access keys in code/logs).
- **Long-lived credentials** (never expire; if leaked, compromised indefinitely).
- **No MFA** (password compromise = account takeover).

#### Overprivileged IAM Role

```json
// BAD: Admin role too permissive
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",  // Allows everything
      "Resource": "*"  // On all resources
    }
  ]
}

// GOOD: Least privilege
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject"
      ],
      "Resource": "arn:aws:s3:::my-bucket/app-data/*"
    }
  ]
}
```

#### Mitigation

```bash
# Audit IAM roles for overprivilege
aws iam get-role-policy --role-name MyRole --policy-name MyPolicy

# Use service roles (EC2 instance profile, Lambda execution role)
# App assumes role; credentials temporary (auto-rotated)

# Enable MFA for sensitive accounts
aws iam enable-mfa-device --user-name MyUser --serial-number arn:aws:iam::123456789012:mfa/MyMFADevice --authentication-code1 123456 --authentication-code2 789012

# Use short-lived credentials (STS AssumeRole)
aws sts assume-role --role-arn arn:aws:iam::123456789012:role/MyRole --role-session-name MySession
# Returns AccessKeyId, SecretAccessKey, SessionToken (expires in 1 hour by default)

# Never hardcode credentials
# Use environment variables or AWS credential provider chain
```

---

### 2. Data Protection

**Risks**:
- **Unencrypted data at rest** (database, storage compromise = data exposed).
- **Unencrypted data in transit** (no HTTPS; MITM possible).
- **Public access** (S3 buckets, databases world-accessible).
- **No backup/disaster recovery** (ransomware = permanent data loss).

#### Public S3 Bucket (Critical)

```bash
# BAD: S3 bucket publicly readable
aws s3api put-bucket-acl --bucket my-bucket --acl public-read

# Anyone can list/read objects
curl https://s3.amazonaws.com/my-bucket/
# Returns: list of all objects (can be 10000s of files)

# GOOD: Private bucket with IAM access
aws s3api put-bucket-acl --bucket my-bucket --acl private
aws s3api put-bucket-policy --bucket my-bucket --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:role/AppRole"},
      "Action": "s3:*",
      "Resource": "arn:aws:s3:::my-bucket/*"
    }
  ]
}'
```

#### Encryption at Rest

```bash
# Enable S3 encryption
aws s3api put-bucket-encryption --bucket my-bucket --server-side-encryption-configuration '{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"  # or KMS for customer-managed keys
      }
    }
  ]
}'

# Enable RDS encryption
aws rds create-db-instance \
  --db-instance-identifier mydb \
  --storage-encrypted  # Enable encryption at rest

# Enable EBS encryption
aws ec2 create-volume \
  --availability-zone us-east-1a \
  --size 100 \
  --encrypted  # Enable encryption at rest
```

#### Mitigation

- Encrypt all data at rest (S3: SSE, RDS: encryption, EBS: encrypted volumes).
- HTTPS only (no HTTP).
- Private subnets (databases not internet-accessible).
- VPC security groups (restrict traffic).
- Backup to separate account (ransomware can't delete).

---

### 3. Network Security

**Risks**:
- **Overly permissive security groups** (all traffic allowed).
- **Public databases** (internet-accessible; easily breached).
- **No network segmentation** (one compromise = full network access).
- **No WAF** (web apps vulnerable to common attacks).

#### Security Group (Firewall)

```bash
# BAD: Allow all traffic
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345 \
  --cidr 0.0.0.0/0 \  # All IPs
  --port 22  # SSH from anywhere

# GOOD: Allow from specific IP range
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345 \
  --cidr 10.0.0.0/8 \  # VPC CIDR only
  --port 22

# GOOD: Allow from VPN only
aws ec2 authorize-security-group-ingress \
  --group-id sg-12345 \
  --cidr 203.0.113.0/32 \  # VPN IP only
  --port 22
```

#### Mitigation

- Security groups: deny by default, allow only necessary traffic.
- Network ACLs (stateless; additional layer).
- Databases: private subnets (no internet access).
- WAF (web application firewall) on ALB/CloudFront.
- VPC Flow Logs (monitor network traffic).

---

### 4. Cloud Metadata Service Abuse (SSRF)

**Risks**:
- **Metadata service accessible** (EC2 instance can query its own credentials).
- **No authentication** (IMDSv1 requires no token; IMDSv2 requires token but still accessible from instance).
- **Attacker abuses compromised app** to fetch credentials.

#### AWS Instance Metadata Service Attack

```bash
# Attacker compromises app running on EC2 instance
# App has IAM role with S3 access

# Attacker uses SSRF to fetch credentials from metadata service
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/MyRole
# Returns: AccessKeyId, SecretAccessKey, Token

# Attacker uses credentials to access S3
aws s3 ls --profile compromised-role
# Can read/write S3 data
```

#### Mitigation

```bash
# Use IMDSv2 (requires token; harder to abuse)
aws ec2 run-instances \
  --iam-instance-profile Arn=arn:aws:iam::123456789012:instance-profile/MyRole \
  --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=1"

# On instance: token required to access metadata
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/

# Disable metadata service if not needed
aws ec2 modify-instance-metadata-options \
  --instance-id i-12345 \
  --http-endpoint disabled
```

---

### 5. Credential Exposure

**Risks**:
- **API keys in code** (committed to git; visible in logs).
- **Environment variables exposed** (Docker image, Lambda console).
- **Secrets in CloudFormation templates** (hardcoded passwords).
- **Access keys never rotated** (if leaked, compromise indefinite).

#### Finding Secrets

```bash
# Attacker finds AWS access key in GitHub
# Looks through commit history; finds: AKIAIOSFODNN7EXAMPLE

# Uses key to access AWS account
aws ec2 describe-instances --access-key-id AKIAIOSFODNN7EXAMPLE --secret-access-key ...

# Can access all resources

# AWS detects suspicious usage; disables key
# But attacker already has access; damage done
```

#### Mitigation

```bash
# Use Secrets Manager (not hardcoded)
# Store credentials; rotate automatically

# AWS Secrets Manager
aws secretsmanager create-secret --name MyAppSecret --secret-string '{"username":"admin","password":"secret"}'

# App fetches secret at runtime
aws secretsmanager get-secret-value --secret-id MyAppSecret

# Rotate automatically
aws secretsmanager rotate-secret --secret-id MyAppSecret --rotation-rules AutomaticallyAfterDays=30

# Scan repos for secrets
# GitHub: Secret scanning (built-in)
# Local: git-secrets, TruffleHog

git secrets --install
git secrets --scan

# Use temporary credentials (STS)
# Never use long-lived access keys

# Audit access key usage
aws iam get-credential-report
```

---

### 6. Misconfigured Cloud Services

**Risks**:
- **Public snapshots/AMIs** (EBS snapshots, machine images world-readable).
- **Logging disabled** (no audit trail).
- **Versioning disabled** (accidental deletion unrecoverable).
- **Replication not configured** (single region; disaster = total loss).

#### Public EBS Snapshot

```bash
# BAD: EBS snapshot public
aws ec2 create-snapshot --volume-id vol-12345 --description "Database backup"
aws ec2 modify-snapshot-attribute --snapshot-id snap-12345 --attribute createVolumePermission --operation-type add --group-names all

# Anyone can copy snapshot; access database

# GOOD: Private snapshot with KMS encryption
aws ec2 create-snapshot --volume-id vol-12345 --description "Database backup"
aws ec2 modify-snapshot-attribute --snapshot-id snap-12345 --attribute createVolumePermission --operation-type remove --group-names all
# Default is private
```

#### Mitigation

- Disable public sharing (default, but verify).
- Enable logging (CloudTrail, VPC Flow Logs, S3 access logs).
- Enable versioning (S3, RDS).
- Cross-region replication (disaster recovery).

---

### 7. Supply Chain Security

**Risks**:
- **Vulnerable container images** (public registries; malware possible).
- **Compromised third-party tools** (CI/CD, deployment tools).
- **Unsafe dependencies** (libraries with known vulnerabilities).

#### Mitigation

```bash
# Scan images before deployment
trivy image gcr.io/myproject/myapp:1.0

# Use private registry (only approved images)
# Pull from: gcr.io/myproject/myapp (private)
# Not from: docker.io/random/image (public; untrusted)

# Pin container image versions
# Bad: gcr.io/myproject/myapp:latest
# Good: gcr.io/myproject/myapp:sha256:abc123...

# Verify image signatures
cosign verify --key cosign.pub gcr.io/myproject/myapp:1.0

# Scan dependencies
pip install safety
safety check
# Scan Python dependencies for vulnerabilities
```

---

### 8. Compliance & Auditing

**Risks**:
- **No audit logs** (can't investigate breaches).
- **Logs not retained** (compliance violation).
- **Logs not protected** (attacker deletes evidence).
- **No encryption** (privacy violation; compliance failure).

#### CloudTrail (AWS Audit Logging)

```bash
# Enable CloudTrail (logs all API calls)
aws cloudtrail create-trail --name MyTrail --s3-bucket-name my-audit-logs --is-multi-region-trail

# Start logging
aws cloudtrail start-logging --trail-name MyTrail

# Logs stored in S3 (encrypted)
# Retained per compliance requirements (1-7 years)

# Protect logs
aws s3api put-bucket-versioning --bucket my-audit-logs --versioning-configuration Status=Enabled
# Enables versioning; prevents accidental deletion

# Monitor for tampering
aws cloudtrail create-event-selector --trail-name MyTrail --event-selectors ReadWriteType=All
```

---

## Cloud Security Checklist

### Identity & Access
- [ ] IAM roles follow least privilege.
- [ ] No hardcoded credentials (use Secrets Manager, STS).
- [ ] MFA enabled on sensitive accounts.
- [ ] Credentials rotated regularly.
- [ ] Service accounts used (not personal credentials).

### Data Protection
- [ ] Encryption at rest enabled (S3, RDS, EBS).
- [ ] Encryption in transit (HTTPS only).
- [ ] Databases private (not internet-accessible).
- [ ] Backups encrypted, isolated, tested.
- [ ] Sensitive data classified, handled securely.

### Network Security
- [ ] Security groups restrict traffic (deny by default).
- [ ] WAF deployed on web apps.
- [ ] VPC Flow Logs enabled (monitor traffic).
- [ ] No public databases.
- [ ] Network segmentation (separate dev/prod/data subnets).

### Cloud Services
- [ ] Cloud Metadata Service hardened (IMDSv2, disabled if unused).
- [ ] S3 buckets private (not public-read).
- [ ] Snapshots/AMIs private.
- [ ] Versioning enabled.
- [ ] Cross-region replication (disaster recovery).

### Monitoring & Logging
- [ ] CloudTrail enabled (all API calls logged).
- [ ] Logs retained (compliance timeline).
- [ ] Logs encrypted and protected.
- [ ] CloudWatch alerts (detect anomalies).
- [ ] Regular review of logs.

### Compliance
- [ ] Encryption implemented (GDPR, HIPAA, PCI-DSS).
- [ ] Access controls match requirements.
- [ ] Audit trails sufficient.
- [ ] Incident response plan in place.

---

## Cloud Security Tools

| Tool | Purpose |
|---|---|
| **CloudSploit** | AWS misconfiguration scanner |
| **Prowler** | AWS security best practices checker |
| **ScoutSuite** | Multi-cloud security auditor |
| **Forseti** | GCP security scanner |
| **Dome9** | Cloud security posture |
| **Trivy** | Container/dependency scanner |
| **Snyk** | Vulnerability scanning (code, dependencies) |

---


## See also

[[Container-Security]], [[Supply-Chain-Security]], [[FedRAMP]], [[Zero-Trust-Architecture]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
