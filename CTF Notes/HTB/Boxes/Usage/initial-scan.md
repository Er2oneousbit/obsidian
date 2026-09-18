# HTB - Usage — Initial scan

#HTB #Usage #Laravel #nginx

Target: 10.129.91.231

> [!note] First-session scratch, kept as evidence. The full write-up is [[CTF Notes/HTB/Boxes/Usage/notes|notes]] — go there first. This file holds only the initial scan (against an earlier IP, `10.129.91.231` vs `10.129.55.135` in the main note) and one captured session cookie.

## Services

- 22/tcp  ssh    OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
- 80/tcp  http   nginx 1.18.0 (Ubuntu) — redirects to `http://usage.htb/`

## Recon

```bash
nmap -p- -sC -sV -oA nmap/usage 10.129.91.231
```

The redirect to `usage.htb` means a `/etc/hosts` entry is required before the site is reachable.

## Artifacts

Laravel encrypted session cookie captured during testing — `iv`/`value`/`mac` structure is the Laravel `APP_KEY` AES-CBC envelope, which is what makes the leaked `APP_KEY` on this box exploitable:

```json
{"iv":"Cc0knLa0AxAoDhUmC 3nww==","value":"GuTLz9kKwbvt1lR3fqRF5qyZd 64xycrQbQf56DUKAVH9NiL8gvhTgCHB ZoSZjHgJ8gnIubVRsHc4wJmOlVonaCapZDvN1UpfSCQ/LTiJ6Z3eNdiDXhAyOPjXUIMBPi","mac":"0055a70efdae071a3cf5ee422d2965147c4633ad676adcdb5d868824f477647b","tag":""}
```
