# gitleaks

**Tags:** #secrets #recon #credentials #git

A fast, regex/entropy-based secret scanner focused on **git repositories** — it walks the full commit history (not just the working tree), so it catches credentials that were committed and later "removed". Widely used both offensively (find leaked keys in a target's repos) and in CI as a pre-commit guard. Complements [[Tools/Recon/trufflehog|TruffleHog]], which adds live key verification.

**Source:** https://github.com/gitleaks/gitleaks
**Install:** `apt install gitleaks` / `brew install gitleaks`

```bash
gitleaks detect --source . -v            # scan a repo's full history
gitleaks detect --source . --report-format json --report-path out.json
gitleaks dir /path                        # scan a directory (non-git)
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — scanning configs/manifests pulled from a cluster for secrets.
> Related tooling: [[Tools/Recon/trufflehog|TruffleHog]] (adds live verification), [[Tools/Scanning/trivy|trivy]].

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
