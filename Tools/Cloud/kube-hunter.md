# kube-hunter

**Tags:** #Kubernetes #k8s #scanner #enumeration #cloud

Aqua Security's Kubernetes vulnerability scanner — probes a cluster from the outside (`--remote`), from inside a pod (`--pod`), or across a network, reporting exposed kubelets, open etcd, anonymous API access, dashboard exposure, and known CVEs. Good for a fast first-pass map of what's reachable and misconfigured.

> [!warning] **Archived (2024).** Aqua archived the kube-hunter repository — it still runs but is no longer maintained and won't know newer CVEs. Treat its output as a starting point and cross-check with [[Tools/Cloud/kubeaudit|kubeaudit]] / manual enumeration; for image CVEs use [[Tools/Scanning/trivy|trivy]].

**Source:** https://github.com/aquasecurity/kube-hunter (archived)
**Install:** `pip install kube-hunter` or run the container image.

```bash
kube-hunter --remote <target>            # external scan
kube-hunter --pod                        # from inside a compromised pod
kube-hunter --remote <target> --active   # active exploitation attempts (intrusive)
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — cluster enumeration.
> Related tooling: [[Tools/Cloud/kubeaudit|kubeaudit]] (config audit), [[Tools/Cloud/kubeletctl|kubeletctl]] (kubelet exploitation), [[Tools/Cloud/peirates|peirates]].

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
