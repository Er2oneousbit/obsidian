# HTB - Redeemer

#HTB #Redeemer #Redis #NoSQL #Easy

Target: 10.129.244.85

## Services

- 6379/tcp  redis   Unauthenticated Redis instance

## Recon

```bash
nmap -sV --open -oA initial_scan 10.129.244.85
nmap -p- --open -oA full_tcp_scan 10.129.244.85
nmap -sC -p 22,80 -oA script_scan 10.129.244.85
```

The full TCP sweep is what found it — 6379 is outside the default top-1000 service set, so the `-sV` pass alone missed it.

## Foothold

Redis with no auth — connect and read straight out of the keyspace:

```bash
sudo apt install redis-tools
redis-cli -h 10.129.244.85
```

```
> info          # server/keyspace stats, confirms no AUTH required
> keys *        # enumerate every key
> get flag      # read the flag key
```

## Flags

- Read directly from the Redis keyspace via `get flag` (value not recorded).

> [!note] See [[Services/Database Services/Redis|Redis]] for the wider surface this box only scratches — `CONFIG GET requirepass`, module loading, and the webshell-write / SSH-key-write RCE paths.
