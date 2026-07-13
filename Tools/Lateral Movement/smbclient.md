# smbclient

**Tags:** `#smbclient` `#smb` `#lateral` `#enumeration` `#filetransfer` `#passthehash`

Linux SMB client for interactive access to Windows file shares. Enumerate shares, browse directories, upload/download files, and interact with SYSVOL/NETLOGON. Supports null sessions, password auth, PTH, and Kerberos. Pre-installed on Kali.

**Source:** Pre-installed on Kali (`samba-client`)

```bash
# List shares (null session)
smbclient -N -L //192.168.1.10

# Connect to share
smbclient //192.168.1.10/share -u user -p Password
```

---

## Listing Shares

```bash
# Null session (no credentials)
smbclient -N -L //192.168.1.10
smbclient -L \\\\192.168.1.10 -N

# With credentials
smbclient -L //192.168.1.10 -u Administrator -p Password
smbclient -L //192.168.1.10 -u 'DOMAIN\user' -p Password

# Pass the Hash
smbclient -L //192.168.1.10 -u Administrator --pw-nt-hash NTLMhash

# Kerberos
smbclient //dc01/C$ -k -no-pass
```

---

## Connecting to Shares

```bash
# Connect interactively
smbclient //192.168.1.10/share -u Administrator -p Password
smbclient //192.168.1.10/C$ -u Administrator -p Password
smbclient //192.168.1.10/ADMIN$ -u Administrator -p Password

# Null session
smbclient -N //192.168.1.10/share

# PTH
smbclient //192.168.1.10/C$ -u Administrator --pw-nt-hash NTLMhash

# Kerberos
KRB5CCNAME=ticket.ccache smbclient //dc01.domain.local/C$ -k -no-pass

# Specify workgroup/domain
smbclient //192.168.1.10/share -u user -p Password -W DOMAIN

# Non-standard port
smbclient //192.168.1.10/share -u user -p Password -p 4445
```

---

## In-Session Commands

```bash
# Once connected — FTP-style interface
ls                          # list directory
ls *.txt                    # list with filter
cd <dir>                    # change directory
get <file>                  # download file
get <file> /local/path      # download to specific path
put <local_file>            # upload file
put <local> <remote>        # upload with rename
mget *.txt                  # download multiple files
mput *.exe                  # upload multiple files
mkdir <dir>                 # create directory
del <file>                  # delete file
rename <old> <new>          # rename
pwd                         # current remote path
lcd <local_dir>             # change local directory
!ls                         # run local command
!cat /etc/passwd            # run any local command
recurse on                  # recursive mode for mget/mput
prompt off                  # disable confirmation prompts
exit / quit                 # disconnect
```

---

## Non-Interactive (Scripted)

```bash
# Run command without interactive shell
smbclient //192.168.1.10/share -u user -p Password -c "ls"
smbclient //192.168.1.10/share -u user -p Password -c "get passwords.txt /tmp/passwords.txt"
smbclient //192.168.1.10/share -u user -p Password -c "put /opt/tools/tool.exe tool.exe"

# Recursive list
smbclient //192.168.1.10/share -u user -p Password -c "recurse on; ls"

# Recursive download (all files in share)
smbclient //192.168.1.10/share -u user -p Password -c "recurse on; prompt off; mget *"
```

---

## SYSVOL / NETLOGON (GPP / Scripts)

```bash
# Browse SYSVOL
smbclient //dc01/SYSVOL -u 'DOMAIN\user' -p Password
# Navigate to: DOMAIN/Policies/<GUID>/Machine/Preferences/Groups/Groups.xml
# Look for cpassword= values → decrypt with gpp-decrypt

# Search for GPP XML files
smbclient //dc01/SYSVOL -u 'DOMAIN\user' -p Password \
  -c "recurse on; prompt off; ls" 2>/dev/null | grep -i ".xml"

# Download all XML files
smbclient //dc01/SYSVOL -u 'DOMAIN\user' -p Password \
  -c "recurse on; prompt off; mget *.xml"

# Browse NETLOGON (logon scripts)
smbclient //dc01/NETLOGON -u 'DOMAIN\user' -p Password -c "ls"
```

---

## File Hunting

```bash
# Interactive search — look for interesting files
smbclient //192.168.1.10/share -u user -p Password
> recurse on
> ls *.config
> ls *.xml
> ls *.ini
> ls *password*
> ls *credential*
> ls *secret*

# Recursive download of entire share
smbclient //192.168.1.10/share -u user -p Password \
  -c "recurse on; prompt off; mget *" --directory /tmp/share_dump/
```

---

## OPSEC Notes

- SMB connections generate Event ID **4624** (logon type 3) and **4648** on the target
- File access generates **4663** (object access) if file auditing is enabled
- Null session auth attempts generate **4625** (failed logon) if the server requires auth
- SYSVOL access is normal domain behavior — less suspicious than C$ / ADMIN$ access

---

*Created: 2026-03-06*
*Updated: 2026-03-06*
*Model: claude-sonnet-4-6*
