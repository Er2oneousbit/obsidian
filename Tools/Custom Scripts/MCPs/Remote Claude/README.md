# Pentest MCP Server

Bridges **Claude Code CLI** (running on Kali) to remote Linux targets via SSH.
Once connected, Claude Code can run commands, read/write files, and chain
local Kali tools -- all without you copy-pasting between terminals.

Generated with Claude Sonnet 4.6
Made with ❤️ from your friendly hacker - er2oneousbit

---

## Architecture

```
[Claude Code CLI on Kali]
         |
    [pentest_mcp]          <-- this server (stdio MCP)
         |
    [paramiko SSH]
         |
[Remote Target: Linux]
```

The MCP server runs locally on Kali via stdio transport.
Claude Code talks to it over the MCP protocol.
The server manages persistent SSH connections to targets.

---

## Installation

```bash
cd pentest_mcp
chmod +x install.sh
./install.sh
```

The installer will print the exact config block you need to add to Claude Code.

### Manual config (~/.claude/claude_desktop_config.json)

```json
{
  "mcpServers": {
    "pentest": {
      "command": "python3",
      "args": ["/path/to/pentest_mcp/server.py"]
    }
  }
}
```

Restart Claude Code after updating config.

---

## Available Tools

| Tool | What it does |
|------|-------------|
| `pentest_add_ssh_target` | Connect to a target via SSH (password or key auth) |
| `pentest_list_targets` | Show all registered targets and connection status |
| `pentest_remove_target` | Disconnect and deregister a target |
| `pentest_execute_command` | Run any shell command on a target |
| `pentest_read_file` | Read a file from a target via SFTP |
| `pentest_upload_file` | Push a local file to a target via SFTP |
| `pentest_download_file` | Pull a file from a target to Kali via SFTP |
| `pentest_run_local` | Run a local Kali command (nmap, gobuster, etc.) |

---

## Example Workflows

### Scenario 1: Post-exploitation after getting SSH creds

Tell Claude Code:
> "Add target 10.129.201.102 as 'weblogic-box', username root, password toor.
>  Then run whoami, id, and find any flag files."

Claude Code will call:
1. `pentest_add_ssh_target` -- connects and confirms access
2. `pentest_execute_command` x3 -- runs your recon commands
3. Reports findings inline in the chat

---

### Scenario 2: Upload linpeas, run it, save output

Tell Claude Code:
> "Upload /opt/linpeas.sh to /tmp/linpeas.sh on weblogic-box,
>  chmod +x it, run it, and download the output to /tmp/loot/linpeas.out"

Claude Code will:
1. `pentest_upload_file` -- pushes linpeas.sh
2. `pentest_execute_command` -- chmod +x
3. `pentest_execute_command` -- runs linpeas, captures output
4. `pentest_download_file` -- saves output locally

---

### Scenario 3: Parallel local recon + remote enumeration

Tell Claude Code:
> "Run nmap -sV against 10.129.201.102 locally while also running
>  'netstat -tlnp' and 'ps aux' on weblogic-box."

Claude Code runs `pentest_run_local` and `pentest_execute_command` in sequence.

---

## Auth Methods

### Password auth
```
alias: dc01
host: 10.129.5.10
username: administrator
password: Password123!
```

### Key auth (most common for HTB/labs)
```
alias: pivot-box
host: 10.10.14.5
username: root
key_path: /root/.ssh/id_rsa
```

### Encrypted key
```
alias: target
host: 10.129.x.x
username: user
key_path: ~/.ssh/encrypted_key
key_passphrase: keypassword
```

---

## Limitations and Notes

- **Targets are session-scoped** -- if you kill the MCP server, connections drop.
  Re-add targets after a Claude Code restart.

- **Reverse shells NOT directly supported** -- this server bridges SSH only.
  For reverse shells, you need SSH on the target (drop an authorized_key,
  enable SSH in /etc/ssh/sshd_config, or use a pivot).

- **Long-running commands** -- increase timeout for things like linpeas,
  hashcat, or slow nmap scans. Max is 600s (10 min).

- **Large output** -- truncated at 50,000 chars to protect Claude's context
  window. Download to a file first for large outputs.

- **Windows targets** -- not supported yet. SSH on Windows works via
  OpenSSH but commands need to be Windows-compatible.

---

## Future Enhancements

- [ ] Metasploit RPC API integration (session management via MSF)
- [ ] Netcat/socat listener management
- [ ] Multi-hop pivot support (ProxyJump style)
- [ ] Windows target support
- [ ] Session persistence across MCP restarts
- [ ] Credential vault integration
