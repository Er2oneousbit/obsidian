# Scrapy

**Tags:** `#scrapy` `#webcrawler` `#spider` `#webenumeration` `#web` `#recon`

Python web crawling and scraping framework. Used in pentesting to spider websites and extract links, emails, hidden paths, comments, JavaScript files, and API endpoints. More powerful and scriptable than simple link grabbers — handles JavaScript-heavy sites (with Splash), authentication, and custom extraction logic.

**Source:** https://scrapy.org / https://github.com/scrapy/scrapy
**Install:** `pip3 install scrapy`

```bash
scrapy startproject myspider
scrapy crawl myspider
```

> [!note]
> For quick recon spidering, the HTB ReconSpider script (single-file Scrapy-based spider) is the easiest entry point. For real engagements, Katana (ProjectDiscovery) or Burp's crawler are more practical. Scrapy shines when you need customized extraction — pulling all API endpoints, all form fields, all email addresses, etc.

---

## HTB ReconSpider (Quick Start)

```bash
# HTB Academy's pre-built spider (wraps Scrapy)
wget https://academy.hackthebox.com/storage/modules/279/ReconSpider.zip
unzip ReconSpider.zip
python3 ReconSpider.py http://target.com

# Output: JSON file with links, emails, hosts, JS files, form fields
cat results.json | python3 -m json.tool
```

---

## Scrapy Shell (Interactive)

```bash
# Test selectors interactively
scrapy shell "http://target.com"

# Inside shell:
response.status               # HTTP status
response.headers              # response headers
response.url                  # final URL (after redirects)
response.text                 # full HTML body

# CSS selectors
response.css('a::attr(href)').getall()           # all links
response.css('input::attr(name)').getall()       # all form field names
response.css('form::attr(action)').getall()      # form action URLs
response.css('script::attr(src)').getall()       # JS file URLs
response.css('meta[name="description"]::attr(content)').get()

# XPath
response.xpath('//a/@href').getall()
response.xpath('//comment()').getall()           # HTML comments
response.xpath('//@data-*').getall()             # data attributes
```

---

## Quick Spider — Extract Links

```python
# spider.py — minimal link extractor
import scrapy

class LinkSpider(scrapy.Spider):
    name = "links"
    start_urls = ["http://target.com"]
    allowed_domains = ["target.com"]

    custom_settings = {
        'DEPTH_LIMIT': 3,
        'DOWNLOAD_DELAY': 1,
        'USER_AGENT': 'Mozilla/5.0',
        'ROBOTSTXT_OBEY': False,
    }

    def parse(self, response):
        # Extract all links
        for link in response.css('a::attr(href)').getall():
            yield {"url": response.urljoin(link), "found_on": response.url}
        # Follow internal links
        for href in response.css('a::attr(href)').getall():
            yield response.follow(href, self.parse)
```

```bash
# Run spider, output to JSON
scrapy runspider spider.py -o links.json
```

---

## Recon-Focused Spider

```python
# Extracts links, emails, forms, JS files, comments
import scrapy, re

class ReconSpider(scrapy.Spider):
    name = "recon"
    start_urls = ["http://target.com"]
    allowed_domains = ["target.com"]

    custom_settings = {
        'DEPTH_LIMIT': 3,
        'ROBOTSTXT_OBEY': False,
        'DOWNLOAD_DELAY': 0.5,
    }

    def parse(self, response):
        # Links
        links = response.css('a::attr(href)').getall()
        # Emails
        emails = re.findall(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', response.text)
        # Forms
        forms = response.css('form').getall()
        # JS files
        scripts = response.css('script::attr(src)').getall()
        # Comments
        comments = response.xpath('//comment()').getall()

        yield {
            "url": response.url,
            "links": links,
            "emails": emails,
            "forms": len(forms),
            "scripts": scripts,
            "comments": [c for c in comments if len(c) > 20],
        }

        for href in links:
            yield response.follow(href, self.parse)
```

---

## Useful Settings

```python
custom_settings = {
    'DEPTH_LIMIT': 3,                # max crawl depth
    'DOWNLOAD_DELAY': 1,             # seconds between requests
    'CONCURRENT_REQUESTS': 8,        # parallel requests
    'ROBOTSTXT_OBEY': False,         # ignore robots.txt
    'USER_AGENT': 'Mozilla/5.0',
    'COOKIES_ENABLED': True,
    'HTTPCACHE_ENABLED': True,       # cache responses
    'LOG_LEVEL': 'ERROR',            # quiet output
    # Proxy
    'DOWNLOADER_MIDDLEWARES': {
        'scrapy.downloadermiddlewares.httpproxy.HttpProxyMiddleware': 1,
    },
    'HTTP_PROXY': 'http://127.0.0.1:8080',
}
```

---

## Alternative: Katana (ProjectDiscovery)

```bash
# Faster, purpose-built for pentest recon
go install github.com/projectdiscovery/katana/cmd/katana@latest

# Basic crawl
katana -u http://target.com

# With depth + JS parsing
katana -u http://target.com -d 3 -jc

# Output endpoints for fuzzing
katana -u http://target.com -d 3 -ef css,png,jpg,woff | tee endpoints.txt

# Pipe to dalfox for XSS
katana -u http://target.com -d 3 -silent | dalfox pipe
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
