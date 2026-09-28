# gcp_scanner

**Tags:** `#gcpscanner` `#gcp` `#cloud` `#enumeration` `#credentialabuse` `#python` `#google`

Google's **own** credential-scope scanner — point it at a set of stolen GCP credentials and
it enumerates exactly what those creds can reach across the org/projects (compute, storage,
IAM, Cloud SQL, functions, service accounts, …) and dumps it to JSON. Answers the first
post-compromise question — *"what does this key/token actually get me?"* — using whatever
credential form you looted.

**Source:** https://github.com/google/gcp_scanner
**Install:**
```bash
pip install gcp_scanner
python3 -m gcp_scanner --help        # or: gcp-scanner --help
```

---

## Point It at Whatever You Stole

Its strength is the range of credential inputs — feed it the artifact you found on the host:

```bash
# gcloud profile on a compromised box (- = default ~/.config/gcloud path)
python3 -m gcp_scanner -g - -o ./out

# a directory of service-account JSON keys
python3 -m gcp_scanner -k ./sa-keys/ -o ./out

# GCE instance metadata (run on/through a compromised VM)
python3 -m gcp_scanner -m -o ./out

# raw access token(s) / refresh token(s) you captured
python3 -m gcp_scanner -at tokens.txt -o ./out
python3 -m gcp_scanner -rt refresh.json -o ./out
```

**Flags:** `-g/--gcloud-profile-path`, `-k/--sa-key-path` (dir of JSON keys),
`-m/--use-metadata`, `-at/--access-token-files`, `-rt/--refresh-token-files`,
`-o/--output-dir` (**required**).

---

## Output

Writes a standard **JSON** report per identity to the output dir — parse with `jq`/`gron`
or the repo's visualizer. It's read-only reconnaissance (no exploitation): use it to decide
which project/SA to pivot into, then act with [[Tools/Cloud/gcloud-cli|gcloud-cli]] or
[[Tools/Cloud/gcpwn|gcpwn]].

> [!tip] Because it accepts **metadata** and **SA-key directories** directly, it's ideal
> right after an IMDS token grab or after looting a box full of `*.json` SA keys — one run
> maps the blast radius of everything you collected.

> [!note] **See also** — [[Tools/Cloud/gcloud-cli|gcloud-cli]] (source the creds / act on findings), [[Tools/Cloud/gcpwn|gcpwn]] (framework that exploits what this finds), [[Tools/Cloud/GCP-IAM-PrivEsc|GCP-IAM-PrivEsc]] (privesc paths), [[Tools/Cloud/ScoutSuite|ScoutSuite]] (misconfig posture). Peers: AWS [[Tools/Cloud/Pacu|Pacu]], the `Get-AzPasswords`-style sweep in [[Tools/Cloud/MicroBurst|MicroBurst]].

---

*Created: 2026-09-28*
*Updated: 2026-09-28*
*Model: claude-opus-4-8*
