# TruffleHog

**Tags:** #secrets #recon #credentials #git #cloud

Secret scanner that hunts for credentials — API keys, tokens, private keys, database strings — across git history, filesystems, S3 buckets, container images, and stdin. Its distinguishing feature is **live verification**: for many detector types it will test a found key against the provider's API and tell you whether it's still valid, cutting the false-positive noise other scanners produce. On a Kubernetes engagement, pipe ConfigMaps/Secrets through it to surface embedded creds.

**Source:** https://github.com/trufflesecurity/trufflehog
**Install:** `brew install trufflehog` / `docker run trufflesecurity/trufflehog`

```bash
trufflehog git https://github.com/org/repo --only-verified
trufflehog filesystem /path --only-verified
kubectl get configmap -A -o json | trufflehog filesystem /dev/stdin   # scan k8s configmaps
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — scanning ConfigMaps/Secrets for embedded credentials. [[Services/Web Services/Azure DevOps|Azure DevOps]] — verified-secret scanning across cloned ADO repos and git history.
> Related tooling: [[Tools/Recon/gitleaks|gitleaks]] (git-focused alternative), [[Tools/Scanning/trivy|trivy]] (image/IaC secrets).

---

*Created: 2026-09-22*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
