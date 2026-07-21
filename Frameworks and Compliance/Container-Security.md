# Container Security

#ContainerSecurity #Docker #Kubernetes #DevSecOps

## What is this?

**Container Security** — Security practices and vulnerabilities specific to containerized applications (Docker, Kubernetes, Podman, etc.). Covers container image security, runtime security, orchestration security, and supply chain risks unique to container ecosystems.

---

## Overview

**Container Security Basics:**
- **Purpose**: Identify and mitigate container-specific security risks.
- **Scope**: Container images, registries, runtime, orchestration platforms.
- **Audience**: DevOps engineers, security teams, platform engineers, developers.

**Why Containers Add Risk**:
- **Shared kernel** (host compromise = container compromise).
- **Image supply chain** (base images, dependencies vulnerabilities).
- **Orchestration complexity** (many moving parts; misconfigurations easy).
- **Rapid deployment** (security checks sometimes skipped for speed).

---

## Container Layers (Attack Surface)

### 1. Image Layer (Build-Time)

**Risks**:
- Vulnerable base images (outdated OS, packages).
- Vulnerable application dependencies.
- Secrets in image (API keys, credentials).
- Malicious code in image layers.

**Mitigation**:
- Scan images for vulnerabilities (Trivy, Grype, Clair).
- Use minimal base images (Alpine, distroless).
- Multi-stage builds (remove build tools from final image).
- No secrets in Dockerfile (use secrets at runtime).

**Example Dockerfile**:
```dockerfile
# BAD: Large base image, secrets in file
FROM ubuntu:latest
RUN apt-get update && apt-get install -y python3
COPY app.py /app/
ENV API_KEY=secret123  # Secrets in image; visible to attacker

# GOOD: Minimal base, no secrets, secrets at runtime
FROM python:3.11-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY app.py .
# Secrets passed at runtime (environment, volume, or secrets manager)

# Multi-stage build: remove build artifacts
FROM python:3.11-alpine as builder
RUN apk add --no-cache gcc
COPY requirements.txt .
RUN pip install -r requirements.txt

FROM python:3.11-alpine
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY app.py .
```

---

### 2. Registry Layer (Distribution)

**Risks**:
- Unauthorized access to registry (push/pull).
- Man-in-the-middle (image tampering in transit).
- Vulnerable registry software.
- Stale/unpatched images stored in registry.

**Mitigation**:
- Registry authentication (credentials, IAM roles).
- Image signing (verify images haven't been tampered).
- HTTPS for registry (TLS encryption).
- Regular cleanup (remove old, unpatched images).
- Private registry (not public; access controlled).

**Example: Image Signing (Cosign)**:
```bash
# Sign image
cosign sign --key cosign.key gcr.io/myproject/myapp:1.0

# Verify signature
cosign verify --key cosign.pub gcr.io/myproject/myapp:1.0

# If signature invalid, deployment blocked (Kubernetes policy)
```

---

### 3. Runtime Layer (Execution)

**Risks**:
- Container escape (break out of container; compromise host).
- Privilege escalation (run as root inside container).
- Vulnerable container runtime (Docker daemon, containerd).
- Insecure image configuration (exposed ports, volumes).

**Mitigation**:
- Run containers as non-root user.
- Use read-only filesystems (if possible).
- Capability dropping (remove unnecessary Linux capabilities).
- Security context (seccomp, AppArmor, SELinux).
- Image scanning at runtime (check for new vulnerabilities).

**Example: Secure Dockerfile**:
```dockerfile
FROM alpine:latest

# Create non-root user
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser

# Copy application
WORKDIR /app
COPY app.py .

# Run as non-root
USER appuser

# Make filesystem read-only (depends on app needs)
RUN echo "server { root /app; }" > /etc/nginx/nginx.conf

# Drop capabilities (more restrictive)
# (Kubernetes: securityContext.capabilities.drop)
```

**Example: Kubernetes SecurityContext**:
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  containers:
  - name: app
    image: myapp:latest
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
      seccompProfile:
        type: RuntimeDefault
    volumeMounts:
    - name: tmp
      mountPath: /tmp
  volumes:
  - name: tmp
    emptyDir: {}
```

---

### 4. Orchestration Layer (Kubernetes)

**Risks**:
- Misconfigured RBAC (excessive permissions).
- Insecure API access (unencrypted, no authentication).
- Pod escape (break out to other pods on same node).
- Secrets in etcd (database for cluster config; must be encrypted).
- Cluster takeover (compromise API server; control entire cluster).

**Mitigation**:
- Network policies (restrict pod-to-pod communication).
- RBAC (principle of least privilege).
- API encryption (TLS, secret encryption at rest).
- Pod security policies (restrict what containers can do).
- Audit logging (log all API calls).

**Example: Network Policy**:
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
  # Deny all by default

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

**Example: RBAC (Role-Based Access Control)**:
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]  # Can only read pods; no delete, create, etc.

---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: production
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: app-sa
  namespace: production
```

---

## Container Security Best Practices

### Image Security

| Practice | Why | Implementation |
|---|---|---|
| **Scan Images** | Detect known vulnerabilities | Trivy, Grype, Clair in CI/CD |
| **Minimal Base Images** | Reduce attack surface | Alpine, distroless, scratch |
| **Multi-Stage Builds** | Remove build tools | Copy only final artifacts |
| **No Secrets in Image** | Prevent credential leakage | Use environment variables, secrets manager |
| **Image Signing** | Prevent tampering | Cosign, Notary |
| **Registry Auth** | Prevent unauthorized access | Private registry, authentication |
| **Immutable Tags** | Ensure reproducibility | Avoid 'latest' tag; use specific versions |

### Runtime Security

| Practice | Why | Implementation |
|---|---|---|
| **Run as Non-Root** | Limit privilege escalation | USER directive in Dockerfile |
| **Read-Only Filesystem** | Prevent code modification | readOnlyRootFilesystem: true |
| **Drop Capabilities** | Remove unnecessary privileges | capabilities.drop: [ALL] |
| **Seccomp** | Restrict system calls | seccomp profiles |
| **AppArmor/SELinux** | Mandatory access control | AppArmor profiles or SELinux policies |
| **Resource Limits** | Prevent DoS | memory, CPU limits in Kubernetes |

### Orchestration Security

| Practice | Why | Implementation |
|---|---|---|
| **Network Policies** | Restrict container communication | Network policy resources |
| **RBAC** | Principle of least privilege | Role, RoleBinding resources |
| **Secret Encryption** | Protect sensitive data at rest | kube-apiserver --encryption-provider-config |
| **Pod Security Policies** | Restrict pod capabilities | Pod security policy resources |
| **Audit Logging** | Track all API calls | --audit-log-maxage, --audit-log-maxbackup |
| **API Authentication** | Prevent unauthorized access | Certificates, tokens, authentication plugins |

---

## Container Vulnerability Types

### Vulnerable Base Images

```bash
# Scan image for vulnerabilities
trivy image alpine:3.10
# Output:
# sqlite3 (debian): CVE-2022-1234 (Critical)
# openssl (debian): CVE-2023-5678 (High)

# Upgrade base image to patched version
docker build --base alpine:3.18 .
```

### Privilege Escalation

```dockerfile
# VULNERABLE: Running as root
FROM ubuntu:latest
CMD ["/app"]
# Container runs as root (UID 0); can modify system, escape

# SECURE: Running as non-root
FROM ubuntu:latest
RUN useradd -m appuser
USER appuser
CMD ["/app"]
# Container runs as appuser (UID 1000); limited privileges
```

### Container Escape

```bash
# VULNERABLE: Privileged container
docker run --privileged myimage
# Can mount host filesystem, load kernel modules, escape

# SECURE: No privileged mode
docker run --cap-drop=ALL myimage
```

### Secrets Exposure

```dockerfile
# VULNERABLE: Secrets in image
FROM node:latest
ENV API_KEY=sk_prod_abc123  # Visible in image layers

# SECURE: Secrets at runtime
FROM node:latest
# Build secret secret from volume, environment, or secret manager at runtime
```

---

## Container Image Scanning

### Common Scanners

| Scanner | Type | Details |
|---|---|---|
| **Trivy** | Open-source | Fast, comprehensive; detects OS vulns, app dependencies |
| **Grype** | Open-source | Focuses on application dependencies |
| **Clair** | Open-source | Kubernetes-native; integrates with registry |
| **Snyk** | Commercial | Cloud-based; continuous monitoring |
| **JFrog Xray** | Commercial | Artifact repository security |

### Scanning Workflow

```bash
# Local scan before push
trivy image myapp:1.0

# Scan in CI/CD
trivy image --severity HIGH,CRITICAL myapp:1.0 --exit-code 1
# Fails build if HIGH/CRITICAL vulns found

# Scan registry after push (continuous)
trivy image --severity CRITICAL gcr.io/myproject/myapp:1.0
```

---

## Container Security Checklist

### Build-Time
- [ ] Dockerfile uses minimal base image (Alpine, distroless).
- [ ] Multi-stage build (removes build tools).
- [ ] No secrets in Dockerfile (environment variables, secrets manager).
- [ ] Image scanned for vulnerabilities (Trivy, Grype).
- [ ] Dependencies pinned to specific versions (no 'latest').
- [ ] Non-root user defined (USER directive).

### Registry
- [ ] Private registry (access controlled).
- [ ] Images signed (Cosign, Notary).
- [ ] HTTPS enabled (TLS encryption).
- [ ] Old images cleaned up (no stale images).
- [ ] Access logs monitored.

### Runtime
- [ ] Container runs as non-root.
- [ ] Filesystem read-only (if possible).
- [ ] Capabilities dropped (drop ALL, re-add only necessary).
- [ ] Resource limits set (memory, CPU).
- [ ] Logging configured.

### Orchestration (Kubernetes)
- [ ] Network policies restrict traffic (deny all, allow specific).
- [ ] RBAC configured (least privilege).
- [ ] Secrets encrypted at rest.
- [ ] Pod security policies/standards enforce restrictions.
- [ ] Audit logging enabled.
- [ ] API authentication/authorization configured.

---


## See also

[[Cloud-Security]], [[Supply-Chain-Security]], [[Secure-SDLC]]  ·  Index: [[_Frameworks and Compliance]]

*Created: 2026-07-17*
*Updated: 2026-07-21*
*Model: claude-haiku-4-5*
