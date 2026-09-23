# peirates

**Tags:** #Kubernetes #k8s #privesc #post-exploitation #cloud

InGuardians' Kubernetes penetration-testing tool, designed to run **from inside a compromised pod**. It presents an interactive menu that automates the common in-cluster escalation moves: harvesting the pod's service-account token, listing and dumping secrets, enumerating what the token can do, pulling cloud-instance credentials from the metadata service, and attempting pod→node escapes. It turns the manual token-abuse workflow into a guided menu.

**Source:** https://github.com/inguardians/peirates
**Install:** download the release binary and drop it into the target pod.

```bash
peirates            # interactive menu:
                    #  - dump service-account tokens / secrets
                    #  - switch between captured tokens
                    #  - request cloud metadata creds (AWS/GCP/Azure)
                    #  - attempt privileged-pod / hostPath escape
```

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Cloud & Data/Kubernetes|Kubernetes]] — service-account token abuse and cloud-metadata pivot.
> Related tooling: [[Tools/Cloud/kubectl|kubectl]], [[Tools/Cloud/kubeletctl|kubeletctl]]; generic breakout in [[Techniques/Container Escape|Container Escape]].

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
