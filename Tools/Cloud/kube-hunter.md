# kube-hunter

**Tags:** #Kubernetes #k8s #scanner #enumeration #cloud

Aqua Security's Kubernetes vulnerability scanner — probes a cluster from the outside (`--remote`), from inside a pod (`--pod`), or across a network, reporting exposed kubelets, open etcd, anonymous API access, dashboard exposure, and known CVEs. Good for a fast first-pass map of what's reachable and misconfigured.

> [!warning] **Archived (2024).** Aqua archived the kube-hunter repository — it still runs but is no longer maintained and won't know newer CVEs. Treat its output as a starting point and cross-check with [[Tools/Cloud/kubeaudit|kubeaudit]] / manual enumeration; for image CVEs use [[Tools/Scanning/trivy|trivy]].

**Source:** https://github.com/aquasecurity/kube-hunter (archived)
**Install:** `pip install kube-hunter` or run the container image.

```bash
kube-hunter --remote <target>            # external scan of one host
kube-hunter --cidr 10.0.0.0/24           # sweep a subnet for cluster components
kube-hunter --pod                        # from inside a compromised pod
kube-hunter --interface                  # scan all local interfaces (broad, from a pod/node)
kube-hunter --remote <target> --active   # active exploitation attempts (intrusive!)
kube-hunter --mapping                    # just map components found, don't run hunters
kube-hunter --remote <target> --report json --log warning > kh.json   # machine-readable output
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — cluster enumeration.
> Related tooling: [[Tools/Cloud/kubeaudit|kubeaudit]] (config audit), [[Tools/Cloud/kubeletctl|kubeletctl]] (kubelet exploitation), [[Tools/Cloud/peirates|peirates]].

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
