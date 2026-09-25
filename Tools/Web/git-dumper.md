# git-dumper

**Tags:** `#git-dumper` `#git` `#sourcedisclosure` `#recon` `#web`

Reconstructs a Git repository from a web-exposed `.git/` directory. When a site deploys with its `.git/` folder left under the web root, git-dumper walks the objects/refs/index (even without directory listing enabled) and rebuilds the working tree locally — recovering source code, hardcoded secrets, and full commit history. First signal: `curl http://host/.git/HEAD` returns `ref: refs/heads/...`.

**Source:** https://github.com/arthaud/git-dumper
**Install:** `pipx install git-dumper` (or `pip install git-dumper`).

```bash
# Detect exposure
curl -s http://<target>/.git/HEAD

# Dump and rebuild the repo
git-dumper http://<target>/.git /tmp/repo
cd /tmp/repo && git log --all -p | grep -iE "password|secret|api_key|token"
```

---

> [!note] **See also** — [[Services/Web Services/HTTP-HTTPS|HTTP/HTTPS]] — exposed `.git/` is a top web-recon finding; git-dumper reconstructs the full source + history for secret hunting.

---

*Created: 2026-09-24*
*Updated: 2026-09-24*
*Model: claude-opus-4-8*
