# sqsh

**Tags:** #sqsh #MSSQL #MySQL #Database #Enumeration

`sqsh` ("skwish") is an interactive SQL shell for Sybase/Microsoft SQL Server (TDS protocol) that runs on Linux — the classic alternative to `impacket-mssqlclient` when you want a raw, scriptable client. It's the tool the HTB material reaches for to connect to MSSQL from Kali with SQL or local-Windows auth and run `xp_cmdshell`, `EXECUTE AS`, and linked-server queries.

**Source:** https://sourceforge.net/projects/sqsh/
**Install:** `sudo apt install sqsh`

```bash
# Connect (SQL auth) — -h suppresses headers/footers for cleaner output
sqsh -S 10.10.10.10 -U sa -P 'Password123' -h

# Local Windows account (note the .\ prefix, quoted)
sqsh -S 10.10.10.10 -U '.\julio' -P 'Password123' -h

# Run a query then terminate the batch with GO on its own line
1> SELECT SYSTEM_USER
2> GO
```

> [!note] **See also** — [[Class notes/HTB Academy/CPTS v2 (claude)/Attacking Common Services|Attacking Common Services]] — MSSQL/MySQL CLI access; pairs with [[Tools/Database/mssqlclient|impacket-mssqlclient]].

---

*Created: 2026-07-30*
*Updated: 2026-07-30*
*Model: claude-opus-4-8*
