# peirates

**Tags:** #Kubernetes #k8s #privesc #post-exploitation #cloud

InGuardians' Kubernetes penetration-testing tool, designed to run **from inside a compromised pod**. It presents an interactive menu that automates the common in-cluster escalation moves: harvesting the pod's service-account token, listing and dumping secrets, enumerating what the token can do, pulling cloud-instance credentials from the metadata service, and attempting pod→node escapes. It turns the manual token-abuse workflow into a guided menu.

**Source:** https://github.com/inguardians/peirates
**Install:** download the release binary and drop it into the target pod.

```bash
peirates            # interactive menu (numbers vary by version — read the menu, don't memorise)
```

It ships its **own kubectl**, so you don't need one in the pod, and it auto-loads the pod's
mounted service-account token on start. What the menu automates, and the manual equivalent if
you'd rather do it by hand (see [[Tools/Cloud/kubectl|kubectl]] / [[Tools/Cloud/kubeletctl|kubeletctl]]):

| Peirates action | Manual equivalent |
|---|---|
| Harvest / switch service-account tokens | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` |
| List & dump secrets | `kubectl get secrets -A -o json` |
| Enumerate token privileges | `kubectl auth can-i --list` |
| Pull cloud-instance creds (AWS/GCP/Azure) | `curl` the metadata service → [[Tools/Cloud/aws-cli|aws]]/[[Tools/Cloud/azure-cli|az]]/[[Tools/Cloud/gcloud-cli|gcloud]] |
| Privileged-pod / hostPath / hostPID escape | the `kubectl run --privileged` node-escape |
| Exec into pods via the kubelet API | `kubeletctl exec …` |

> [!tip] Use peirates for the fast guided sweep from a fresh pod foothold, then drop to
> `kubectl` with the best captured token for precise, quiet follow-up.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — service-account token abuse and cloud-metadata pivot.
> Related tooling: [[Tools/Cloud/kubectl|kubectl]], [[Tools/Cloud/kubeletctl|kubeletctl]]; generic breakout in [[Techniques/Container Escape|Container Escape]].

---

*Created: 2026-09-22*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
