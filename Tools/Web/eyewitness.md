# EyeWitness

**Tags:** `#eyewitness` `#webenumeration` `#screenshots` `#recon` `#web` `#defaultcreds`

Web screenshot and reconnaissance tool. Visits a list of hosts, takes screenshots, captures response headers, and identifies default credentials for common applications. Similar to aquatone but with built-in default credential detection and support for RDP/VNC screenshots in addition to HTTP/HTTPS.

**Source:** https://github.com/RedSiege/EyeWitness
**Install:** `sudo apt install eyewitness`

```bash
eyewitness --web -f urls.txt -d ./output
```

> [!note]
> EyeWitness is particularly useful during internal network assessments — it handles large host lists from Nmap, identifies default credential pages (Tomcat manager, Jenkins, routers, printers), and groups similar-looking sites in the report. Aquatone is faster for external subdomain recon; EyeWitness excels for internal network sweeps.

---

## Basic Usage

```bash
# Web screenshots from URL file
eyewitness --web -f urls.txt -d ./eyewitness_output

# From Nmap XML output
eyewitness --web --nmap nmap.xml -d ./eyewitness_output

# From Nmap XML (all ports)
eyewitness --web --nmap-open nmap.xml -d ./eyewitness_output

# Single URL
eyewitness --web --single http://target.com -d ./output

# CIDR range
eyewitness --web --cidr 10.10.10.0/24 -d ./output
```

---

## Protocol Options

```bash
# HTTP/HTTPS (default --web)
eyewitness --web -f urls.txt -d ./output

# RDP screenshots (internal assessments)
eyewitness --rdp -f hosts.txt -d ./output

# VNC
eyewitness --vnc -f hosts.txt -d ./output

# All protocols
eyewitness --all-protocols -f hosts.txt -d ./output
```

---

## Timeout & Threading

```bash
# Timeout per page (default 7s)
eyewitness --web -f urls.txt --timeout 15 -d ./output

# Threads (default 10)
eyewitness --web -f urls.txt --threads 20 -d ./output

# Delay between requests
eyewitness --web -f urls.txt --delay 2 -d ./output
```

---

## Proxy & Auth

```bash
# Through proxy
eyewitness --web -f urls.txt --proxy-ip 127.0.0.1 --proxy-port 8080 -d ./output

# With authentication header
eyewitness --web -f urls.txt \
  --add-http-headers "Authorization: Bearer token" -d ./output

# Cookies
eyewitness --web -f urls.txt \
  --add-http-headers "Cookie: session=abc123" -d ./output
```

---

## Key Flags

| Flag | Description |
|------|-------------|
| `--web` | HTTP/HTTPS screenshots |
| `--rdp` | RDP screenshots |
| `--vnc` | VNC screenshots |
| `-f <file>` | Input file (URLs or hosts) |
| `--nmap <file>` | Nmap XML input |
| `--nmap-open` | Only open ports from Nmap XML |
| `--single <url>` | Single target |
| `--cidr` | CIDR range |
| `-d <dir>` | Output directory |
| `--timeout <sec>` | Page load timeout (default 7) |
| `--threads <n>` | Concurrent threads (default 10) |
| `--delay <sec>` | Delay between requests |
| `--proxy-ip` | Proxy IP |
| `--proxy-port` | Proxy port |
| `--add-http-headers` | Custom headers |
| `--no-prompt` | Skip interactive prompts |
| `--resume` | Resume interrupted scan |

---

## Workflow — Internal Network Assessment

```bash
# 1. Nmap sweep for web ports
nmap -sV -p 80,443,8080,8443,8888,8008 10.10.0.0/16 -oX web_hosts.xml

# 2. Screenshot all discovered web services
eyewitness --web --nmap-open web_hosts.xml -d ./eyewitness --no-prompt

# 3. Open report
firefox ./eyewitness/report.html

# 4. Focus on:
# - Default credential pages (Tomcat, Jenkins, Jira, Confluence)
# - Login panels without branding (internal apps)
# - Error pages revealing tech stack
# - Management interfaces (iDRAC, iLO, IPMI, router admin)
```

---

## Default Credentials EyeWitness Identifies

```
Apache Tomcat Manager    → tomcat:tomcat, admin:admin
Jenkins                  → (unauthenticated by default in old versions)
Cisco devices            → admin:cisco, cisco:cisco
Juniper                  → admin:admin
Netgear / Linksys        → admin:admin, admin:password
Printers (various)       → admin:admin, admin:(blank)
VMware vCenter           → administrator@vsphere.local:VMware1!
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
