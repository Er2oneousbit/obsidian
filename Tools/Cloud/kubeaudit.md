# kubeaudit

**Tags:** #Kubernetes #k8s #audit #hardening #defensive

Shopify's Kubernetes configuration auditor. It checks manifests, a live cluster, or a kubeconfig against a set of security best-practice controls — privileged containers, missing `runAsNonRoot`, `automountServiceAccountToken`, dangerous capabilities, hostPath mounts, missing network policies — and reports each deviation. Primarily a defensive/hardening tool, but on an engagement it quickly surfaces the misconfigurations worth attacking.

**Source:** https://github.com/Shopify/kubeaudit
**Install:** `go install github.com/Shopify/kubeaudit@latest` or a release binary.

```bash
kubeaudit all                                        # live cluster via local kubeconfig / current context
kubeaudit all --kubeconfig config --context <name>   # explicit kubeconfig + context (local mode)
kubeaudit all -f manifest.yaml                       # audit a MANIFEST file (-f/--manifest is for YAML manifests, NOT a kubeconfig)
kubeaudit privileged -f manifest.yaml                # one control against a manifest
kubeaudit all -p json --minseverity error            # machine-readable, high-severity only
```

### Reading It Offensively — control → attack primitive

Run the specific auditor that finds the primitive you want:

| kubeaudit control | What a finding gives an attacker |
|---|---|
| `privileged` | Privileged container → trivial **node escape** |
| `hostns` | `hostPID`/`hostNetwork`/`hostIPC` → `nsenter` breakout, sniff host traffic |
| `mounts` | hostPath / `docker.sock` mounted → host filesystem / daemon takeover |
| `capabilities` | Dangerous caps (`SYS_ADMIN`, `SYS_PTRACE`) → escape / inject |
| `privesc` | `allowPrivilegeEscalation` set → setuid path to root in-container |
| `asat` | `automountServiceAccountToken` on → the pod's SA token is stealable |
| `nonroot`/`rootfs` | Runs as root / writable root FS → easier persistence |
| `netpols` | Missing NetworkPolicy → free lateral movement between pods |

> [!tip] `kubeaudit mounts`, `hostns`, and `privileged` are the fastest "where do I break out?"
> triage on a cluster you can read — the hits line up with the escapes in [[Tools/Cloud/kubectl|kubectl]] / [[Techniques/Container Escape|Container Escape]].

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — maps directly to its Dangerous Settings table.
> Related tooling: [[Tools/Cloud/kube-hunter|kube-hunter]] (active scanner), [[Tools/Scanning/trivy|trivy]] (image/IaC scanning).

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
