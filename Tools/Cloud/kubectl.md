# kubectl

**Tags:** #Kubernetes #k8s #cloud #enumeration #client

The official Kubernetes command-line client. It talks to the API server (6443) using a bearer token, client cert, or kubeconfig, and is the primary tool for enumerating and manipulating a cluster on an engagement — listing pods/secrets/service-accounts, checking your own effective permissions, and (with the right RBAC) creating privileged pods or role bindings.

**Source:** https://kubernetes.io/docs/reference/kubectl/
**Install:** `apt install kubectl` / `curl -LO https://dl.k8s.io/release/$(curl -Ls https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl`

```bash
# Point at a target with a stolen token, skip TLS verify
kubectl --server=https://<target>:6443 --token=<bearer-token> --insecure-skip-tls-verify get pods -A

# The two most important recon calls
kubectl auth can-i --list                       # my effective permissions
kubectl auth can-i '*' '*' --all-namespaces     # am I effectively cluster-admin?

kubectl get secrets -A                          # dump/enumerate secrets
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — the full API/RBAC/escape methodology.
> Related tooling: [[Tools/Cloud/kubeletctl|kubeletctl]] (node-level kubelet API), [[Tools/Cloud/peirates|peirates]] (automated in-pod abuse), [[Tools/Cloud/kube-hunter|kube-hunter]] (scanner).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
