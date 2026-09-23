# kubeaudit

**Tags:** #Kubernetes #k8s #audit #hardening #defensive

Shopify's Kubernetes configuration auditor. It checks manifests, a live cluster, or a kubeconfig against a set of security best-practice controls — privileged containers, missing `runAsNonRoot`, `automountServiceAccountToken`, dangerous capabilities, hostPath mounts, missing network policies — and reports each deviation. Primarily a defensive/hardening tool, but on an engagement it quickly surfaces the misconfigurations worth attacking.

**Source:** https://github.com/Shopify/kubeaudit
**Install:** `go install github.com/Shopify/kubeaudit@latest` or a release binary.

```bash
kubeaudit all -f kubeconfig.yaml        # audit a cluster via kubeconfig
kubeaudit all                            # audit the cluster in current context
kubeaudit privileged -f manifest.yaml    # check one control against a manifest
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — maps directly to its Dangerous Settings table.
> Related tooling: [[Tools/Cloud/kube-hunter|kube-hunter]] (active scanner), [[Tools/Scanning/trivy|trivy]] (image/IaC scanning).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
