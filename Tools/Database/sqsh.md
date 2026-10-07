# sqsh

**Tags:** #sqsh #MSSQL #Sybase #Database #Enumeration

`sqsh` ("skwish") is an interactive SQL shell for Sybase/Microsoft SQL Server (TDS protocol) that runs on Linux — the classic alternative to `impacket-mssqlclient` when you want a raw, scriptable client. It's the tool the HTB material reaches for to connect to MSSQL from Kali with SQL or local-Windows auth and run `xp_cmdshell`, `EXECUTE AS`, and linked-server queries. It speaks **TDS only** (Sybase ASE / Microsoft SQL Server) — it is **not** a MySQL/PostgreSQL client.

**Source:** https://sourceforge.net/projects/sqsh/
**Install:** `sudo apt install sqsh`

```bash
# Connect (SQL auth) — -h suppresses headers/footers for cleaner output
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h

# Local Windows account (note the .\ prefix, quoted)
sqsh -S 10.10.10.10 -U '.\julio' -P 'Password123' -h

# Non-standard port — sqsh has NO -p flag; use host:port on -S
sqsh -S 10.10.10.10:14330 -U sa -P 'Password123' -h

# Pick a starting database with -D
sqsh -S 10.10.10.10 -U sa -P 'Password123' -D master -h

# Run a query then terminate the batch with GO on its own line
1> SELECT SYSTEM_USER
2> GO
```

**Non-interactive (scriptable) with `-C`** — runs one SQL batch and exits (no `GO` needed; the string may not contain double quotes, so use single quotes inside):

```bash
# Version / identity one-liner
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h -C "SELECT @@version"

# xp_cmdshell OS command (SQL auth as sysadmin) — the reason to reach for sqsh
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h \
  -C "EXEC xp_cmdshell 'whoami'"

# Enable it first if disabled (sysadmin):
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h \
  -C "EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE"
```

> [!tip] `-C` batches are the value for looting/spraying — drop them into a bash loop over hosts or credentials. For interactive linked-server / `EXECUTE AS` work (`enum_links`-style navigation) the impacket client's built-ins are friendlier; see [[Tools/Database/mssqlclient|impacket-mssqlclient]].

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] — MSSQL CLI access; pairs with [[Tools/Database/mssqlclient|impacket-mssqlclient]]. Service: [[Services/Database Services/MSSQL|MSSQL]].

---

*Created: 2026-07-30*
*Updated: 2026-09-29*
*Model: claude-opus-4-8*
