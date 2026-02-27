#wpscan
- [wpscan](https://github.com/wpscanteam/wpscan)
- api token `VGiIfhgIkrdfdpzC5ZfmCm3rZaS79Nd1mxsDMJr9C7Y`
- an automated WordPress scanner and enumeration tool. It determines if the various themes and plugins used by a blog are outdated or vulnerable.
- `sudo wpscan --url http://blog.inlanefreight.local --enumerate --api-token VGiIfhgIkrdfdpzC5ZfmCm3rZaS79Nd1mxsDMJr9C7Y`
- `sudo wpscan --password-attack xmlrpc -t 20 -U john -P /usr/share/wordlists/rockyou.txt --url http://blog.inlanefreight.local` attack wordpress login API
- `sudo wpscan --url http://blog.inlanefreight.local --enumerate u` user enumeration