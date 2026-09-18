# HTB - Editor

#HTB #Editor #XWiki #Jetty #nginx #vhost #Unfinished

Target: 10.129.216.221 (`editor.htb`)

> [!warning] **Unfinished box.** The recorded work stops at enumeration — no exploitation, no creds, no flags. What follows is everything that was captured.

## Services

- 22/tcp    ssh        OpenSSH 8.9p1 Ubuntu 3ubuntu0.13
- 80/tcp    http       **nginx 1.18.0 (Ubuntu)** — does not follow redirect to `http://editor.htb/`
- 8080/tcp  http-proxy **Jetty 10.0.20** — XWiki, "XWiki - Main - Intro"

Full output: [[CTF Notes/HTB/Boxes/editor/nmap|nmap]]

```
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
```

The redirect on 80 means `editor.htb` needs a `/etc/hosts` entry before the site resolves.

## Findings

**XWiki on 8080** — version recorded as **XWiki Debian 15.10.8**, served by Jetty 10.0.20 at:

```
http://10.129.216.221:8080/xwiki/bin/view/Main/
```

Notable scan observations:

| Observation | Why it matters |
|---|---|
| `JSESSIONID` — **httponly flag not set** | Session cookie readable from JS; pairs with any XSS |
| `http-open-proxy: Proxy might be redirecting requests` | Worth probing for an open relay / SSRF pivot |
| WebDAV methods allowed: `PROPFIND`, `LOCK`, `UNLOCK` | Flagged by nmap as potentially risky |
| `robots.txt` — 50 disallowed entries | A free map of every XWiki action endpoint — see [[CTF Notes/HTB/Boxes/editor/robots.txt\|robots.txt]] |

## Users

- `neal` — found in XWiki

## Where to pick up

Nothing past enumeration was attempted. The obvious next steps from what's here: confirm the exact XWiki version from the UI, check it against XWiki's security advisories, and work the `/xwiki/bin/` action surface the `robots.txt` exposes.

## Files in this folder

| File | Contents |
|---|---|
| [[CTF Notes/HTB/Boxes/editor/nmap\|nmap]] | Full + refined scans |
| [[CTF Notes/HTB/Boxes/editor/robots.txt\|robots.txt]] | Complete XWiki `robots.txt` |
