# braa

**Tags:** `#braa` `#snmp` `#snmpattack` `#enumeration`

Mass SNMP scanner that sends multiple requests simultaneously and brute-forces OID values across one or many hosts. Much faster than snmpwalk for large subnets or bulk OID enumeration.

**Source:** https://github.com/mteg/braa
**Install:** `sudo apt install braa`

```bash
braa public@10.129.14.128:.1.3.6.*
```

> [!note]
> Use after `onesixtyone` identifies valid community strings. braa is faster than snmpwalk for OID sweeping across multiple hosts, but snmpwalk gives cleaner parsed output for a single target.

---

## Syntax

```bash
braa [community]@[target]:[OID]

# Multiple targets (space-separated queries, or a host1-host2 dash range)
braa public@10.129.14.1:.1.3.6.* public@10.129.14.2:.1.3.6.*
braa public@10.129.14.1-10.129.14.20:.1.3.6.*
```

Full spec: `[community@]host1[-host2][:port]:query1[/id][,query2...]` — the OID trailing `*` triggers a walk. CIDR is **not** accepted; ranges are `start-end` only.

---

## Common OID Targets

| OID | Description |
|-----|-------------|
| `.1.3.6.1.2.1.1` | System info (hostname, OS, uptime) |
| `.1.3.6.1.2.1.25.4.2.1.2` | Running processes |
| `.1.3.6.1.2.1.25.6.3.1.2` | Installed software |
| `.1.3.6.1.2.1.6.13.1.3` | Open TCP ports |
| `.1.3.6.1.2.1.4.34.1.3` | Network interfaces |
| `.1.3.6.1.4.1.77.1.2.25` | Windows user accounts |
| `.1.3.6.*` | Walk everything |

---

## Workflow

```bash
# 1. Find community strings first
onesixtyone -c /usr/share/seclists/Discovery/SNMP/snmp.txt 10.129.14.128

# 2. Sweep all OIDs with found community string
braa public@10.129.14.128:.1.3.6.*

# 3. Target specific OID (Windows users)
braa public@10.129.14.128:.1.3.6.1.4.1.77.1.2.25.*

# 4. Multi-host sweep — braa uses a DASH RANGE, not CIDR.
#    (`public@10.129.14.0/24:...` silently fails — /24 is not valid braa syntax.)
braa public@10.129.14.1-10.129.14.254:.1.3.6.1.2.1.1.5.0
```

---

## OPSEC

- SNMP v1/v2c is unencrypted — community strings and data visible on wire
- SNMP enumeration typically not logged unless traps are configured on the target
- Large OID sweeps generate significant UDP traffic — noisy on monitored networks

---

> [!note] **See also** — Find community strings first with [[Tools/Network/onesixtyone|onesixtyone]]; [[Tools/Network/snmpwalk|snmpwalk]] gives cleaner parsed output for a single host once braa flags a live one. Service-level context and the attack surface: [[Services/Network management/SNMP|SNMP]].

---

*Created: 2026-03-13*
*Updated: 2026-08-31*
*Model: claude-opus-5*
