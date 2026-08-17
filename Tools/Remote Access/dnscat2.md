# dnscat2

**Tags:** `#dnscat2` `#dns` `#tunneling` `#c2` `#pivoting` `#covert`

Encrypted command-and-control channel tunnelled entirely over **DNS**. Because many egress-filtered networks still resolve DNS (often via an internal resolver that recurses out), dnscat2 gives a covert C2/pivot path when nothing else leaves the network. A server runs on an authoritative host for a domain you control; the client (native binary or a PowerShell port) beacons out as DNS queries. Slow and low-bandwidth, but frequently the *only* channel that works.

**Source:** https://github.com/iagox86/dnscat2 · PowerShell client: https://github.com/lukebaggett/dnscat2-powershell
**Install:** `git clone` + `gem install bundler; bundle install` for the Ruby server

```bash
# Attacker — start the DNS C2 server for a domain whose NS points at you
sudo ruby dnscat2.rb --dns host=10.10.14.18,port=53,domain=inlanefreight.local --no-cache
```

> [!note] **See also**
> Covered as the "firewall allows only DNS" pivot in [[Class notes/HTB Academy/CPTS v2 (claude)/Pivoting, Tunneling & Port Forwarding|Pivoting, Tunneling & Port Forwarding]]. For a full routable IP-over-DNS link (rather than C2), `iodine` is the more capable alternative.

---

*Created: 2026-08-14*
*Updated: 2026-08-14*
*Model: claude-opus-5*
