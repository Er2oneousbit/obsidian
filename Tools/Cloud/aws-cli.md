# AWS CLI

**Tags:** `#aws` `#cloud` `#awscli` `#postexploitation` `#credentialabuse`

Official command-line client for Amazon Web Services. In an engagement it's the primary tool for using stolen/assumed AWS credentials — validate them (`sts get-caller-identity`), enumerate what they can reach (S3, Secrets Manager, IAM), and pivot. Reads credentials from `~/.aws/credentials`, `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`/`AWS_SESSION_TOKEN` env vars, or instance/container metadata — all of which are credential-hunting targets on a compromised host.

**Source:** https://aws.amazon.com/cli/
**Install:** `pip install awscli` or `sudo apt install awscli`

```bash
# Set stolen temporary credentials (e.g. from IMDS)
export AWS_ACCESS_KEY_ID="<AccessKeyId>"
export AWS_SECRET_ACCESS_KEY="<SecretAccessKey>"
export AWS_SESSION_TOKEN="<Token>"

# Validate + enumerate
aws sts get-caller-identity
aws s3 ls
aws secretsmanager list-secrets
```

> [!note] **See also** — [[Services/Cloud & Data/Databricks|Databricks]] (using cluster-IMDS-stolen IAM role creds). For deeper AWS enumeration/privesc tooling see [[Tools/Cloud/Pacu|Pacu]] and [[Tools/Cloud/ScoutSuite|ScoutSuite]].

---

*Created: 2026-07-28*
*Updated: 2026-07-28*
*Model: claude-opus-4-8*
