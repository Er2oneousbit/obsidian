# Ruby

**Tags:** `#ruby` `#scripting` `#metasploit` `#exploit` `#moduledev`

Ruby is the language of the Metasploit Framework. Relevant for writing custom Metasploit modules, modifying existing modules, using the Metasploit console's Ruby interpreter (`irb`), and adapting public PoCs written in Ruby.

**Version check:** `ruby --version`

> [!note]
> You don't need to be a Ruby expert for most pentest work — focus on reading existing Metasploit modules and adapting them. The MSF module API handles most heavy lifting. `msfconsole`'s `irb` command drops you into a live Ruby session with full MSF API access.

---

## Quick Reference

```ruby
# Run inline
ruby -e "puts 'hello'"

# Run file
ruby script.rb

# IRB (interactive)
irb

# Inside msfconsole
msf6 > irb
```

---

## Metasploit Module Structure

```ruby
# Skeleton for a Metasploit exploit module
class MetasploitModule < Msf::Exploit::Remote
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'App Name RCE',
      'Description' => 'CVE-XXXX-XXXX exploitation',
      'Author'      => ['Your Name'],
      'License'     => MSF_LICENSE,
      'References'  => [
        ['CVE', 'XXXX-XXXX'],
        ['URL', 'https://example.com/advisory'],
      ],
      'Targets'     => [
        ['Automatic', {}],
      ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => '2024-01-01',
      'DefaultOptions' => { 'RPORT' => 8080 }
    ))
    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('USERNAME',  [true, 'Username', 'admin']),
      OptString.new('PASSWORD',  [true, 'Password', 'admin']),
    ])
  end

  def check
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path, 'login')
    })
    return CheckCode::Unknown unless res
    return CheckCode::Appears if res.body.include?('VulnApp')
    CheckCode::Safe
  end

  def exploit
    # authenticate
    res = send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, 'login'),
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD']
      }
    })
    fail_with(Failure::NoAccess, 'Login failed') unless res && res.code == 302

    # get session cookie
    session_cookie = res.get_cookies

    # trigger RCE
    cmd = payload.encoded
    res = send_request_cgi({
      'method'  => 'POST',
      'uri'     => normalize_uri(target_uri.path, 'exec'),
      'cookie'  => session_cookie,
      'vars_post' => { 'cmd' => cmd }
    })
    fail_with(Failure::UnexpectedReply, 'Exploit failed') unless res && res.code == 200
  end
end
```

---

## Metasploit Module Types

```ruby
# Exploit module
class MetasploitModule < Msf::Exploit::Remote
  include Msf::Exploit::Remote::HttpClient    # HTTP
  include Msf::Exploit::Remote::Tcp           # raw TCP

# Auxiliary module (no payload — scanners, bruteforce, etc.)
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner             # adds RHOSTS iteration
  include Msf::Auxiliary::Report              # add to DB
  include Msf::Auxiliary::AuthBrute           # brute force helpers

  def run_host(ip)
    # called per host
  end

# Post module
class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry        # registry access
  include Msf::Post::File                     # file operations

  def run
    session.sys.process.execute("cmd.exe /c whoami", nil, {'Hidden' => true})
  end
```

---

## MSF HTTP Helpers

```ruby
# GET request
res = send_request_cgi({
  'method'  => 'GET',
  'uri'     => '/path',
  'headers' => { 'X-Custom' => 'value' },
})

# POST with form data
res = send_request_cgi({
  'method'    => 'POST',
  'uri'       => '/login',
  'vars_post' => { 'user' => 'admin', 'pass' => 'password' }
})

# POST with raw body
res = send_request_cgi({
  'method'  => 'POST',
  'uri'     => '/api',
  'ctype'   => 'application/json',
  'data'    => '{"key":"value"}'
})

# Response handling
res.code         # HTTP status code
res.body         # response body string
res.headers      # headers hash
res.get_cookies  # Set-Cookie value
res.body.include?("success")
res.body =~ /token=([a-f0-9]+)/; $1   # regex capture
```

---

## MSF Auxiliary Scanner Pattern

```ruby
class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'    => 'My Scanner',
      'Description' => 'Scans for X',
    ))
    register_options([
      Opt::RPORT(80),
      OptString.new('PATH', [true, 'Path to check', '/admin']),
    ])
  end

  def run_host(ip)
    res = send_request_cgi({
      'rhost'  => ip,
      'method' => 'GET',
      'uri'    => datastore['PATH']
    })
    if res && res.code == 200
      print_good("#{ip} - Found: #{res.code}")
      report_web_vuln(
        host: ip,
        port: datastore['RPORT'],
        ssl:  datastore['SSL'],
        path: datastore['PATH'],
        name: 'Exposed Admin Panel',
        risk: 2
      )
    else
      vprint_status("#{ip} - Not found")
    end
  rescue Rex::ConnectionError => e
    vprint_error("#{ip} - Connection failed: #{e.message}")
  end
end
```

---

## Install / Load Custom Module

```bash
# Copy to MSF module path
mkdir -p ~/.msf4/modules/exploits/custom/
cp my_module.rb ~/.msf4/modules/exploits/custom/

# Load in msfconsole
msf6 > reload_all
msf6 > use exploit/custom/my_module

# Or load a single file
msf6 > loadpath /path/to/modules/
```

---

## Ruby Basics for PoC Adaptation

```ruby
# String operations
"hello world".upcase
"hello".include?("ell")
"GET /path HTTP/1.1".split(" ")
"  trim  ".strip
"abc".gsub("a", "X")        # → "Xbc"
"%s:%d" % ["host", 80]      # → "host:80"

# Arrays
arr = [1, 2, 3]
arr << 4                     # append
arr.first; arr.last
arr.include?(2)
arr.map { |x| x * 2 }
arr.select { |x| x > 1 }
arr.join(", ")

# Hashes
h = { "key" => "value", :sym => 123 }
h["key"]
h[:sym]
h.keys; h.values
h.each { |k, v| puts "#{k}: #{v}" }
h.merge({ "new" => "pair" })

# Conditionals
if x > 0
  puts "positive"
elsif x == 0
  puts "zero"
else
  puts "negative"
end

x > 0 ? "positive" : "negative"   # ternary

# Loops
10.times { |i| puts i }
(1..5).each { |i| puts i }
arr.each { |x| puts x }
while condition; end

# Exception handling
begin
  risky_operation
rescue SomeError => e
  puts e.message
rescue => e
  puts "Unknown: #{e}"
ensure
  cleanup
end

# Regex
"id: 12345" =~ /id: (\d+)/
$1    # → "12345"
"text".scan(/\d+/)
"text".match(/(\w+)/)[1]
```

---

## Net/HTTP (without MSF)

```ruby
require 'net/http'
require 'uri'
require 'json'
require 'openssl'

uri = URI("http://10.10.10.10/api")
http = Net::HTTP.new(uri.host, uri.port)
http.use_ssl = uri.scheme == "https"
http.verify_mode = OpenSSL::SSL::VERIFY_NONE

# GET
req = Net::HTTP::Get.new(uri)
req['Authorization'] = 'Bearer token'
res = http.request(req)
puts res.code, res.body

# POST JSON
req = Net::HTTP::Post.new(uri)
req.content_type = 'application/json'
req.body = { key: "value" }.to_json
res = http.request(req)

# POST form
req = Net::HTTP::Post.new(uri)
req.set_form_data({ 'user' => 'admin', 'pass' => 'password' })
res = http.request(req)
```

---

## Encoding / Crypto

```ruby
require 'base64'
require 'digest'
require 'openssl'

# Base64
Base64.encode64("data")
Base64.strict_encode64("data")   # no newlines
Base64.decode64("ZGF0YQ==")

# Hex
"hello".unpack1("H*")            # → "68656c6c6f"
["68656c6c6f"].pack("H*")        # → "hello"

# Hashing
Digest::MD5.hexdigest("password")
Digest::SHA256.hexdigest("password")
Digest::SHA256.digest("password")   # raw bytes

# HMAC
OpenSSL::HMAC.hexdigest("SHA256", "secret", "message")

# AES
cipher = OpenSSL::Cipher.new('AES-128-CBC')
cipher.encrypt
cipher.key = key_bytes   # 16 bytes
cipher.iv  = iv_bytes    # 16 bytes
encrypted = cipher.update(plaintext) + cipher.final
```

---

## IRB Inside msfconsole

```ruby
# Drop into Ruby from MSF console
msf6 > irb

# Access framework
framework.db.hosts.each { |h| puts h.address }
framework.sessions.each { |id, s| puts "#{id}: #{s.info}" }

# Run MSF module programmatically
mod = framework.modules.create('auxiliary/scanner/portscan/tcp')
mod.datastore['RHOSTS'] = '10.10.10.0/24'
mod.datastore['RPORTS'] = '22,80,443'
mod.run_simple('LocalInput' => driver.input, 'LocalOutput' => driver.output)

# Interact with session
s = framework.sessions[1]
s.sys.config.sysinfo
s.fs.file.stat("C:\\Windows\\System32\\cmd.exe")
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
