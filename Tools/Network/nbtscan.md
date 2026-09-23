# nbtscan

**Tags:** #nbtscan #NetBIOS #enumeration #network

`nbtscan` is a fast command-line NetBIOS name-service scanner — it sends NBNS status queries (UDP 137) across a host or whole subnet and returns each machine's NetBIOS name table: hostname, logged-on user, workgroup/domain, and the service suffixes (`<00>`, `<20>`, `<1C>` etc.). On an internal engagement it is the quickest way to sweep a range for Windows hosts, spot domain controllers (`<1C>`), and pull usernames before touching SMB. `-r` sources packets from the local UDP/137 port (matches some hosts' response filtering) and needs root.

**Source:** https://github.com/resurrecting-open-source-projects/nbtscan
**Install:** `sudo apt install nbtscan`

```bash
nbtscan <target>          # single host name table
nbtscan <subnet>/24       # sweep a range
nbtscan -r <subnet>/24    # source from UDP/137 (root) — bypasses some filters
```

> [!note] **See also** — [[Services/Network management/NetBIOS|NetBIOS]] (the service note: name types, LLMNR/NBNS poisoning, null-session enum, RID cycling).

---

*Created: 2026-09-23*
*Updated: 2026-09-23*
*Model: claude-opus-4-8*
