#!/usr/bin/env python3
"""
================================================================================
  Pentest MCP Server - Claude Code <-> Remote Shell Bridge
  Connects Claude Code CLI (on Kali) to remote Linux targets via SSH
  Supports: command execution, file read/write/transfer, local tool execution

  Generated with: Claude Sonnet 4.6
  Made with ❤️ from your friendly hacker - er2oneousbit
================================================================================
"""

import asyncio
import json
import os
import subprocess
from contextlib import asynccontextmanager
from typing import Any, Dict, List, Optional

import paramiko
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, ConfigDict, Field, field_validator

# ==============================================================================
# CONSTANTS
# ==============================================================================
VERSION             = "1.0.0"
DEFAULT_SSH_PORT    = 22
DEFAULT_TIMEOUT     = 30        # seconds -- SSH connection timeout
DEFAULT_CMD_TIMEOUT = 60        # seconds -- command execution timeout
MAX_OUTPUT_CHARS    = 50_000    # truncate output beyond this to protect context window

# ==============================================================================
# IN-MEMORY TARGET REGISTRY
# alias -> { host, port, username, auth_method, client (paramiko.SSHClient) }
# NOTE: targets persist only for the lifetime of this server process
# ==============================================================================
_targets: Dict[str, Dict[str, Any]] = {}


# ==============================================================================
# LIFESPAN -- clean up SSH connections on shutdown
# ==============================================================================
@asynccontextmanager
async def app_lifespan():
    """Manage SSH connection lifecycle."""
    yield {}
    for alias, info in list(_targets.items()):
        client = info.get("client")
        if client:
            try:
                client.close()
            except Exception:
                pass


mcp = FastMCP("pentest_mcp", lifespan=app_lifespan)


# ==============================================================================
# SHARED HELPERS
# ==============================================================================

def _get_target(alias: str) -> Dict[str, Any]:
    """Look up a target by alias; raise ValueError with helpful message if missing."""
    if alias not in _targets:
        available = list(_targets.keys()) or ["(none -- use pentest_add_ssh_target first)"]
        raise ValueError(f"Target '{alias}' not found. Available: {available}")
    return _targets[alias]


def _truncate(text: str, max_chars: int = MAX_OUTPUT_CHARS) -> str:
    """Truncate large output to protect Claude's context window."""
    if len(text) > max_chars:
        return (
            text[:max_chars]
            + f"\n\n[... OUTPUT TRUNCATED -- {len(text):,} total chars, showing first {max_chars:,} ...]"
        )
    return text


def _run_ssh_command(
    client: paramiko.SSHClient,
    command: str,
    timeout: int = DEFAULT_CMD_TIMEOUT,
) -> Dict[str, Any]:
    """Execute a command over an established SSH connection."""
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    exit_code = stdout.channel.recv_exit_status()
    return {
        "stdout":    _truncate(stdout.read().decode("utf-8", errors="replace")),
        "stderr":    _truncate(stderr.read().decode("utf-8", errors="replace")),
        "exit_code": exit_code,
    }


def _format_result(source: str, command: str, result: Dict[str, Any]) -> str:
    """Render SSH/local command results as clean markdown for Claude Code."""
    lines = [
        f"## Command Result",
        f"**Source**: `{source}`",
        f"**Command**: `{command}`",
        f"**Exit Code**: `{result['exit_code']}`",
        "",
    ]
    if result["stdout"].strip():
        lines += ["### stdout", "```", result["stdout"].strip(), "```", ""]
    if result["stderr"].strip():
        lines += ["### stderr", "```", result["stderr"].strip(), "```", ""]
    if not result["stdout"].strip() and not result["stderr"].strip():
        lines.append("_(no output)_")
    return "\n".join(lines)


def _check_connection(alias: str, client: paramiko.SSHClient) -> Optional[str]:
    """Return an error string if the SSH connection is no longer active."""
    transport = client.get_transport()
    if not transport or not transport.is_active():
        return (
            f"Connection to '{alias}' is no longer active. "
            f"Re-connect with pentest_add_ssh_target."
        )
    return None


# ==============================================================================
# PYDANTIC INPUT MODELS
# ==============================================================================

class AddSSHTargetInput(BaseModel):
    """Input model for adding/connecting an SSH target."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    alias: str = Field(
        ...,
        description="Friendly name for this target, used in all other tools (e.g. 'weblogic-box', 'dc01', 'pivot-01')",
        min_length=1, max_length=50,
    )
    host: str = Field(
        ...,
        description="Target IP address or hostname (e.g. '10.129.201.102')",
        min_length=1,
    )
    username: str = Field(
        ...,
        description="SSH username (e.g. 'root', 'kali', 'administrator')",
        min_length=1,
    )
    port: int = Field(
        default=DEFAULT_SSH_PORT,
        description="SSH port (default: 22)",
        ge=1, le=65535,
    )
    password: Optional[str] = Field(
        default=None,
        description="SSH password. Leave None to use key auth.",
    )
    key_path: Optional[str] = Field(
        default=None,
        description="Absolute path to SSH private key on Kali (e.g. '/root/.ssh/id_rsa', '~/.ssh/target_key')",
    )
    key_passphrase: Optional[str] = Field(
        default=None,
        description="Passphrase if the private key is encrypted. Leave None if not encrypted.",
    )
    timeout: int = Field(
        default=DEFAULT_TIMEOUT,
        description="Connection timeout in seconds",
        ge=5, le=120,
    )

    @field_validator("host")
    @classmethod
    def validate_host(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("host cannot be empty")
        return v.strip()


class AliasInput(BaseModel):
    """Simple single-alias input for tools that only need a target name."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")
    alias: str = Field(..., description="Target alias as registered with pentest_add_ssh_target", min_length=1)


class ExecuteCommandInput(BaseModel):
    """Input model for remote command execution."""
    model_config = ConfigDict(str_strip_whitespace=True, validate_assignment=True, extra="forbid")

    alias: str = Field(..., description="Target alias", min_length=1)
    command: str = Field(
        ...,
        description=(
            "Shell command to run on the target. Examples: "
            "'whoami', 'id', 'cat /root/flag.txt', "
            "'find / -name flag.txt 2>/dev/null', "
            "'ps aux | grep weblogic'"
        ),
        min_length=1,
    )
    timeout: int = Field(
        default=DEFAULT_CMD_TIMEOUT,
        description="Max seconds to wait for command output before timing out",
        ge=5, le=600,
    )


class ReadFileInput(BaseModel):
    """Input model for reading a remote file."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    alias: str = Field(..., description="Target alias", min_length=1)
    remote_path: str = Field(
        ...,
        description="Full absolute path to file on target (e.g. '/root/flag.txt', '/etc/passwd')",
        min_length=1,
    )


class UploadFileInput(BaseModel):
    """Input model for uploading a local file to target via SFTP."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    alias: str = Field(..., description="Target alias", min_length=1)
    local_path: str = Field(
        ...,
        description="Absolute path to file on Kali to upload (e.g. '/tmp/exploit.py', '~/tools/linpeas.sh')",
        min_length=1,
    )
    remote_path: str = Field(
        ...,
        description="Absolute destination path on target (e.g. '/tmp/exploit.py')",
        min_length=1,
    )


class DownloadFileInput(BaseModel):
    """Input model for downloading a remote file to Kali via SFTP."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    alias: str = Field(..., description="Target alias", min_length=1)
    remote_path: str = Field(
        ...,
        description="Absolute path to file on target to download",
        min_length=1,
    )
    local_path: str = Field(
        ...,
        description="Absolute destination path on Kali (e.g. '/tmp/loot/shadow.txt')",
        min_length=1,
    )


class RunLocalInput(BaseModel):
    """Input model for running a local Kali command."""
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    command: str = Field(
        ...,
        description=(
            "Shell command to run on local Kali. Examples: "
            "'nmap -sV 10.129.x.x', 'searchsploit weblogic 12', "
            "'gobuster dir -u http://x -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files-lowercase.txt', "
            "'hashcat -m 1000 hash.txt rockyou.txt'"
        ),
        min_length=1,
    )
    timeout: int = Field(
        default=DEFAULT_CMD_TIMEOUT,
        description="Max seconds before killing the process",
        ge=5, le=600,
    )
    working_dir: Optional[str] = Field(
        default=None,
        description="Working directory for the command. Defaults to current dir.",
    )


# ==============================================================================
# MCP TOOLS
# ==============================================================================

@mcp.tool(
    name="pentest_add_ssh_target",
    annotations={
        "title":          "Add / Connect SSH Target",
        "readOnlyHint":   False,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint":  True,
    },
)
async def pentest_add_ssh_target(params: AddSSHTargetInput) -> str:
    """Register and connect to a remote target via SSH.

    Establishes an SSH session and stores it under a friendly alias.
    Supports password auth, private key auth, and SSH agent.
    Re-adding an existing alias closes the old connection first.

    Args:
        params (AddSSHTargetInput): Connection parameters including:
            - alias (str): Friendly name (e.g. 'weblogic-box')
            - host (str): Target IP or hostname
            - username (str): SSH username
            - port (int): SSH port, default 22
            - password (Optional[str]): Password auth
            - key_path (Optional[str]): Path to private key on Kali
            - key_passphrase (Optional[str]): Key passphrase if encrypted
            - timeout (int): Connection timeout in seconds

    Returns:
        str: Connection summary with whoami output, or error message
    """
    # Close any existing connection under this alias
    if params.alias in _targets:
        old = _targets[params.alias].get("client")
        if old:
            try:
                old.close()
            except Exception:
                pass

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: Dict[str, Any] = {
        "hostname": params.host,
        "port":     params.port,
        "username": params.username,
        "timeout":  params.timeout,
    }

    # Determine auth method
    auth_method = "ssh-agent / default keys"
    if params.key_path:
        key_path = os.path.expanduser(params.key_path)
        if not os.path.exists(key_path):
            return f"Error: Private key not found at '{key_path}'"
        try:
            pkey = paramiko.RSAKey.from_private_key_file(
                key_path, password=params.key_passphrase
            )
            connect_kwargs["pkey"] = pkey
            auth_method = f"key ({key_path})"
        except paramiko.ssh_exception.PasswordRequiredException:
            return "Error: Private key is encrypted -- provide key_passphrase"
        except Exception as e:
            return f"Error loading private key: {e}"
    elif params.password:
        connect_kwargs["password"] = params.password
        auth_method = "password"
    else:
        connect_kwargs["allow_agent"] = True
        connect_kwargs["look_for_keys"] = True

    # Attempt connection
    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException:
        return (
            f"Error: Authentication failed for {params.username}@"
            f"{params.host}:{params.port} using {auth_method}"
        )
    except paramiko.ssh_exception.NoValidConnectionsError:
        return (
            f"Error: Could not connect to {params.host}:{params.port} -- "
            f"host unreachable or SSH not listening"
        )
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"

    # Store in registry
    _targets[params.alias] = {
        "host":        params.host,
        "port":        params.port,
        "username":    params.username,
        "auth_method": auth_method,
        "client":      client,
    }

    # Confirm with a quick whoami
    try:
        result    = _run_ssh_command(client, "id", timeout=10)
        whoami    = result["stdout"].strip()
    except Exception:
        whoami = "(could not run id)"

    return "\n".join([
        f"## Target Connected: {params.alias}",
        f"**Host**: {params.host}:{params.port}",
        f"**SSH User**: {params.username}",
        f"**Auth**: {auth_method}",
        f"**Running as**: {whoami}",
        "",
        f"Ready. Use `pentest_execute_command` with alias='{params.alias}'",
    ])


@mcp.tool(
    name="pentest_list_targets",
    annotations={
        "title":           "List Registered Targets",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   False,
    },
)
async def pentest_list_targets() -> str:
    """List all registered SSH targets and live connection status.

    Shows each alias with host, port, username, auth method, and
    whether the SSH transport is currently active.

    Returns:
        str: Markdown summary of all registered targets
    """
    if not _targets:
        return "No targets registered. Use pentest_add_ssh_target to add one."

    lines = ["## Registered Targets", ""]
    for alias, info in _targets.items():
        client    = info.get("client")
        transport = client.get_transport() if client else None
        status    = "🟢 connected" if (transport and transport.is_active()) else "🔴 disconnected"

        lines += [
            f"### {alias}",
            f"- **Host**: `{info['host']}:{info['port']}`",
            f"- **User**: `{info['username']}`",
            f"- **Auth**: {info['auth_method']}",
            f"- **Status**: {status}",
            "",
        ]
    return "\n".join(lines)


@mcp.tool(
    name="pentest_remove_target",
    annotations={
        "title":           "Remove / Disconnect Target",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   False,
    },
)
async def pentest_remove_target(params: AliasInput) -> str:
    """Disconnect and deregister a target.

    Closes the SSH session and removes the alias from the registry.
    Re-add with pentest_add_ssh_target if needed.

    Args:
        params (AliasInput): alias of the target to remove

    Returns:
        str: Confirmation message
    """
    info   = _get_target(params.alias)
    client = info.get("client")
    if client:
        try:
            client.close()
        except Exception:
            pass
    del _targets[params.alias]
    return f"Target '{params.alias}' ({info['host']}) disconnected and removed."


@mcp.tool(
    name="pentest_execute_command",
    annotations={
        "title":           "Execute Command on Remote Target",
        "readOnlyHint":    False,
        "destructiveHint": True,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def pentest_execute_command(params: ExecuteCommandInput) -> str:
    """Execute any shell command on a registered SSH target.

    Runs the command and returns stdout, stderr, and exit code.
    Use for enumeration, exploitation, post-exploitation, flag hunting.

    Common use cases:
        - 'whoami' / 'id' / 'hostname'
        - 'find / -name flag.txt 2>/dev/null'
        - 'cat /etc/passwd'
        - 'ps aux | grep java'
        - 'netstat -tlnp'

    Args:
        params (ExecuteCommandInput): Parameters including:
            - alias (str): Target alias
            - command (str): Shell command to execute
            - timeout (int): Seconds before timeout (default 60)

    Returns:
        str: Formatted stdout/stderr/exit_code output
    """
    info   = _get_target(params.alias)
    client = info["client"]

    # Guard: check connection is alive
    err = _check_connection(params.alias, client)
    if err:
        return f"Error: {err}"

    try:
        result = _run_ssh_command(client, params.command, timeout=params.timeout)
        return _format_result(
            f"{params.alias} ({info['host']})", params.command, result
        )
    except Exception as e:
        return f"Error executing on '{params.alias}': {type(e).__name__}: {e}"


@mcp.tool(
    name="pentest_read_file",
    annotations={
        "title":           "Read Remote File",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def pentest_read_file(params: ReadFileInput) -> str:
    """Read and display the contents of a file on a remote target via SFTP.

    Retrieves file contents without needing a cat command.
    Ideal for reading flags, config files, /etc/passwd, private keys, etc.

    Args:
        params (ReadFileInput): Parameters including:
            - alias (str): Target alias
            - remote_path (str): Full path to file on target

    Returns:
        str: File contents in a code block, or error message
    """
    info   = _get_target(params.alias)
    client = info["client"]

    err = _check_connection(params.alias, client)
    if err:
        return f"Error: {err}"

    try:
        sftp = client.open_sftp()
        with sftp.open(params.remote_path, "r") as f:
            content = f.read().decode("utf-8", errors="replace")
        sftp.close()

        return "\n".join([
            f"## File: `{params.remote_path}`",
            f"**Target**: {params.alias} ({info['host']})",
            "",
            "```",
            _truncate(content),
            "```",
        ])
    except IOError as e:
        if "No such file" in str(e):
            return f"Error: File not found on target: {params.remote_path}"
        if "Permission denied" in str(e):
            return f"Error: Permission denied reading {params.remote_path}"
        return f"Error reading file: {e}"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


@mcp.tool(
    name="pentest_upload_file",
    annotations={
        "title":           "Upload File to Target",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def pentest_upload_file(params: UploadFileInput) -> str:
    """Upload a local file from Kali to a remote target via SFTP.

    Transfers tools, exploit scripts, payloads, or any file to the target.
    Examples: uploading linpeas.sh, a custom payload, a config file.

    Args:
        params (UploadFileInput): Parameters including:
            - alias (str): Target alias
            - local_path (str): Source path on Kali
            - remote_path (str): Destination path on target

    Returns:
        str: Transfer confirmation with file size, or error message
    """
    info       = _get_target(params.alias)
    client     = info["client"]
    local_path = os.path.expanduser(params.local_path)

    err = _check_connection(params.alias, client)
    if err:
        return f"Error: {err}"

    if not os.path.exists(local_path):
        return f"Error: Local file not found: {local_path}"

    file_size = os.path.getsize(local_path)

    try:
        sftp = client.open_sftp()
        sftp.put(local_path, params.remote_path)
        sftp.close()
        return "\n".join([
            f"## Upload Complete",
            f"**Local**:  `{local_path}` ({file_size:,} bytes)",
            f"**Remote**: `{params.alias}:{params.remote_path}`",
            "",
            "Transfer successful.",
        ])
    except Exception as e:
        return f"Error uploading to '{params.alias}': {type(e).__name__}: {e}"


@mcp.tool(
    name="pentest_download_file",
    annotations={
        "title":           "Download File from Target",
        "readOnlyHint":    True,
        "destructiveHint": False,
        "idempotentHint":  True,
        "openWorldHint":   True,
    },
)
async def pentest_download_file(params: DownloadFileInput) -> str:
    """Download a file from a remote target to Kali via SFTP.

    Pulls files for local analysis -- hashes, shadow files, binaries,
    config files, loot, flags, etc.

    Args:
        params (DownloadFileInput): Parameters including:
            - alias (str): Target alias
            - remote_path (str): Source path on target
            - local_path (str): Destination path on Kali

    Returns:
        str: Transfer confirmation with file size, or error message
    """
    info       = _get_target(params.alias)
    client     = info["client"]
    local_path = os.path.expanduser(params.local_path)

    err = _check_connection(params.alias, client)
    if err:
        return f"Error: {err}"

    # Create local directory if needed
    local_dir = os.path.dirname(local_path)
    if local_dir:
        os.makedirs(local_dir, exist_ok=True)

    try:
        sftp = client.open_sftp()
        sftp.get(params.remote_path, local_path)
        file_size = os.path.getsize(local_path)
        sftp.close()
        return "\n".join([
            f"## Download Complete",
            f"**Remote**: `{params.alias}:{params.remote_path}`",
            f"**Local**:  `{local_path}` ({file_size:,} bytes)",
            "",
            "File saved locally.",
        ])
    except IOError as e:
        if "No such file" in str(e):
            return f"Error: Remote file not found: {params.remote_path}"
        return f"Error downloading file: {e}"
    except Exception as e:
        return f"Error: {type(e).__name__}: {e}"


@mcp.tool(
    name="pentest_run_local",
    annotations={
        "title":           "Run Local Kali Command",
        "readOnlyHint":    False,
        "destructiveHint": False,
        "idempotentHint":  False,
        "openWorldHint":   True,
    },
)
async def pentest_run_local(params: RunLocalInput) -> str:
    """Run a command on the local Kali attack box.

    Executes any local Kali tool and returns output.
    Use for nmap scans, gobuster, searchsploit, msfvenom payload generation,
    hashcat/john cracking, or any other local enumeration/attack tool.

    Args:
        params (RunLocalInput): Parameters including:
            - command (str): Shell command to run locally
            - timeout (int): Seconds before killing process (default 60)
            - working_dir (Optional[str]): Working directory

    Returns:
        str: Command output with exit code
    """
    try:
        proc = subprocess.run(
            params.command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=params.timeout,
            cwd=params.working_dir,
        )
        result = {
            "stdout":    _truncate(proc.stdout),
            "stderr":    _truncate(proc.stderr),
            "exit_code": proc.returncode,
        }
        return _format_result("localhost (Kali)", params.command, result)
    except subprocess.TimeoutExpired:
        return f"Error: Command timed out after {params.timeout}s. Consider increasing timeout or running in background."
    except Exception as e:
        return f"Error running local command: {type(e).__name__}: {e}"


# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    mcp.run()
