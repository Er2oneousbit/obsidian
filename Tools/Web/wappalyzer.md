# Wappalyzer

**Tags:** `#wappalyzer` `#fingerprinting` `#techdetect` `#webenumeration` `#web`

Technology fingerprinting tool. Identifies the tech stack of a website — CMS, frameworks, web servers, CDNs, analytics, JavaScript libraries, e-commerce platforms, and more. Available as a browser extension (passive, real-time) and CLI tool. Used to identify attack surface and find version-specific vulnerabilities.

**Source:** https://www.wappalyzer.com / https://github.com/wappalyzer/wappalyzer
**Install:**
```bash
# Browser extension (Firefox/Chrome) — primary usage
# CLI
npm install -g wappalyzer
```

```bash
wappalyzer http://target.com
```

> [!note]
> The browser extension is the most practical way to use Wappalyzer during manual testing — it runs passively as you browse. For bulk analysis or automation, use httpx with `-tech-detect` (uses Wappalyzer signatures internally) or whatweb. Wappalyzer CLI requires Node.js.

---

## Browser Extension Usage

```
1. Install from Firefox Add-ons or Chrome Web Store
2. Browse to target site
3. Click Wappalyzer icon → see detected technologies
4. Categories: CMS, frameworks, web server, JS libraries, CDN, analytics

What it detects (examples):
- WordPress 6.x, Drupal 9.x, Joomla 3.x
- PHP, Python, Ruby, .NET, Java
- Apache, nginx, IIS, LiteSpeed
- jQuery, React, Vue, Angular, Bootstrap
- Cloudflare, Akamai, AWS CloudFront
- Shopify, WooCommerce, Magento
- Google Analytics, Hotjar
```

---

## CLI Usage

```bash
# Single URL
wappalyzer http://target.com

# JSON output
wappalyzer http://target.com --pretty

# Batch from file
cat urls.txt | xargs -I{} wappalyzer {}

# With proxy
wappalyzer http://target.com --proxy http://127.0.0.1:8080
```

---

## httpx Tech Detection (Recommended for Bulk)

```bash
# httpx uses Wappalyzer signatures internally
cat hosts.txt | httpx -tech-detect -silent

# With status + title
cat hosts.txt | httpx -tech-detect -status-code -title -silent

# Filter by technology
cat hosts.txt | httpx -tech-detect -silent | grep -i "wordpress"
cat hosts.txt | httpx -tech-detect -silent | grep -i "joomla"
cat hosts.txt | httpx -tech-detect -silent | grep -i "drupal"
cat hosts.txt | httpx -tech-detect -silent | grep -i "apache"
```

---

## Post-Fingerprint Workflow

```bash
# After identifying tech stack:
# 1. Note CMS + version → search for exploits
searchsploit wordpress 6.x
searchsploit drupal 9.x

# 2. Note JS libraries + versions → check retire.js
npm install -g retire
retire --url http://target.com

# 3. Note web server → check for known vulns
searchsploit apache 2.4
searchsploit nginx 1.18

# 4. CMS-specific scanning
wpscan --url http://target.com           # WordPress
droopescan scan drupal -u http://target.com
joomscan -u http://target.com           # Joomla

# 5. Framework-specific checks
# PHP → LFI, deserialization, file upload vulns
# .NET → ViewState deserialization, YSOSERIAL
# Java → deserialization (ysoserial), JNDI injection
```

---

## Wappalyzer Categories

| Category | Examples |
|---|---|
| CMS | WordPress, Drupal, Joomla, Ghost, Typo3 |
| Ecommerce | WooCommerce, Shopify, Magento, PrestaShop |
| Web frameworks | Laravel, Django, Rails, Express, Spring |
| JavaScript | jQuery, React, Vue, Angular, Next.js |
| Web servers | Apache, nginx, IIS, LiteSpeed, Caddy |
| CDN | Cloudflare, Akamai, Fastly, AWS CloudFront |
| Security | reCAPTCHA, Imperva, ModSecurity |
| Analytics | Google Analytics, Hotjar, Mixpanel |
| Databases | MySQL, PostgreSQL, MongoDB (via error disclosure) |

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
