# recon-ng

**Tags:** #reconng #OSINT #Recon #PassiveRecon #Enumeration #Framework #Python

`recon-ng` is a modular OSINT framework with a Metasploit-style console — workspaces, a local database, and installable modules for host, contact, credential, and domain discovery. Its real advantage is the **database**: results accumulate into normalised tables that later modules consume automatically, so a domain harvested by one module becomes input to the next without any manual plumbing, and reporting modules export the lot.

**Source:** https://github.com/lanmaster53/recon-ng
**Install:** ships in Kali (`recon-ng`), or `pipx install recon-ng`

```bash
recon-ng
```

```text
# Modules live in a marketplace — nothing is installed by default
[recon-ng][default] > marketplace search subdomain
[recon-ng][default] > marketplace install hackertarget
[recon-ng][default] > marketplace install all          # grab everything (some need API keys)

# Workspace per engagement — keeps databases separate
[recon-ng][default] > workspaces create example_corp

# Seed the database, then run modules against it
[recon-ng][example_corp] > db insert domains example.com
[recon-ng][example_corp] > modules load recon/domains-hosts/hackertarget
[recon-ng][example_corp][hackertarget] > run

# Results land in tables — inspect and pivot
[recon-ng][example_corp] > show hosts
[recon-ng][example_corp] > modules load recon/hosts-hosts/resolve
[recon-ng][example_corp] > run

# API keys for the modules that need them
[recon-ng][example_corp] > keys add shodan_api <KEY>
[recon-ng][example_corp] > keys list

# Export
[recon-ng][example_corp] > modules load reporting/html
[recon-ng][example_corp][html] > run
```

| Command | Purpose |
|---|---|
| `marketplace search/install` | Find and install modules |
| `workspaces create/select/list` | Per-engagement databases |
| `db insert <table>` | Seed data manually |
| `modules load <path>` | Load a module |
| `show <table>` | Inspect collected results (`hosts`, `contacts`, `domains`, `credentials`) |
| `keys add` | Store third-party API keys |

> [!note] Largely superseded by [[Tools/Recon/bbot|bbot]], which does the same recursive chaining without the console workflow and is far more actively maintained. Recon-ng still earns its place when you want a **queryable database** of findings and formal HTML/CSV reporting rather than a stream of output.

> [!tip] Most of the high-value modules need API keys. With none configured you'll get a fraction of the coverage — check `keys list` before concluding a target has a small footprint.

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Info Gathering|Info Gathering]] — modular OSINT collection and reporting.

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-5*
