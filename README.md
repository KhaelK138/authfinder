# AuthFinder

A tool for executing commands across multiple Windows systems using various remote execution methods. Automatically tries multiple techniques until one succeeds, based on return codes and output. Makes executing commands given credentials a hell of a lot easier.

Big thanks to NetExec, Impacket, and Evil-Winrm, as this tool just essentially acts as a wrapper around those (making it more of a script, I suppose).

## Features

- **Multiple RCE Methods**: Automatically tries various Windows remote execution techniques:
  - WinRM (HTTP/HTTPS)
  - PSExec (Impacket)
  - SMBExec (NetExec)
  - WMI (NetExec)
  - AtExec (Impacket)
  - RDP (NetExec)
  - SSH (NetExec)
  - MSSQL (Impacket)
- **Multi-threaded**: Execute commands across multiple hosts simultaneously
- **Automatic Pass-the-Hash**: Just paste the NTLM hash as the credential

## Installation

```bash
pipx install authfinder
```

### External Dependencies

This tool requires the following external tools to be installed:

```bash
# Impacket (for PSExec, AtExec, MSSQL)
pipx install impacket

# NetExec (for SMBExec, WMI, RDP, SSH)
pipx install git+https://github.com/Pennyw0rth/NetExec

# Evil-WinRM (for WinRM)
gem install evil-winrm
```

## Usage

### Basic Usage

```bash
# Execute command on single host
authfinder 192.168.1.10 administrator Password123 whoami

# Execute across IP range of 192.168.1.1 to 192.168.1.50
authfinder 192.168.1.1-50 admin Pass123 "net user"

# Use nthash instead of password
authfinder 10.0.0.1-10 admin :{32-bit-hash} whoami
```

### IP Range Format

Supports various formats:
- Single IP: `192.168.1.10`
- Multi-IP: `192.168.1.15,17,29,153` 
- Range: `192.168.1.1-254`
- Multiple ranges: `10.0.1-5.10-20` (expands to all combinations)
- File with IP ranges: `targets.txt`

### Credential File Format

Create a text file with alternating username/password lines:

```
administrator
Password123!
admin
Pass123
backup_admin
:12345678123456781234567812345678
```

Lines starting with `#` are treated as comments. For NT hashes, use them directly as the password.

## Command-Line Options

```
Options:
  -v                      Verbose output (shows all tool attempts)
  -o                      Show successful command output (WARNING: may trigger AV)
  -f <file>               Use credential file instead of single username/password
  --threads <n>           Number of concurrent threads (default: 10)
  --tools <list>          Comma-separated list of tools to try in order
  --timeout <seconds>     Command timeout in seconds (default: 15)
  --run-all               Run all tools instead of stopping at first success
  --skip-portscan         Skip port scanning and attempt all tools
```


## Todo

Add kerberos support lol
- Requires supporting hostnames and configuring `/etc/krb5.conf` for tools like evil-winrm

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is intended for authorized security assessments only. Ensure you have proper authorization before using this tool on any systems you do not own or have explicit permission to test.