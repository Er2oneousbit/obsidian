# Trivy

**Tags:** #scanner #containers #CVE #IaC #secrets #cloud

Aqua Security's all-in-one security scanner. Most used for **container image** vulnerability scanning (OS packages + language dependencies against known CVEs), but it also scans filesystems, git repos, Kubernetes clusters, and IaC (Terraform/Dockerfile/K8s manifests) for misconfigurations and embedded secrets. On an engagement it's the fastest way to find a vulnerable image or a hardcoded credential baked into a container.

**Source:** https://github.com/aquasecurity/trivy
**Install:** `apt install trivy` / `brew install trivy`

```bash
trivy image <image:tag>                       # CVEs in an image
trivy image --scanners secret <image:tag>     # secrets baked into layers
trivy k8s --report summary cluster            # scan a whole cluster
trivy fs --scanners vuln,secret,misconfig .   # local repo/dir
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — image CVE + manifest scanning.
> Related tooling: [[Tools/Cloud/kubeaudit|kubeaudit]] (cluster config), [[Tools/Cloud/kube-hunter|kube-hunter]] (runtime).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
