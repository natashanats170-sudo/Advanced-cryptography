/Nmap Commands (Shell/Terminal)./

bash
# 1. Basic host/port discovery
nmap localhost

# 2. Service version detection (-sV shows software versions on open ports)
nmap -sV localhost

# 3. Scan a specific IP on your local network
nmap 192.168.1.10

# 4. Scan a range of hosts
nmap 192.168.1.1-20

# 5. Run default NSE vulnerability scripts
nmap --script vuln localhost


/Python Script — Automated Port Scanner./
python
import socket

def scan_ports(host, ports):
    """Scan a list of TCP ports on a host and report open ones."""
    print(f"Scanning {host}...")
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)
                print(f"  [OPEN]   Port {port}")
            else:
                print(f"  [CLOSED] Port {port}")
            sock.close()
        except Exception as e:
            print(f"  [ERROR]  Port {port}: {e}")
    return open_ports

common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
results = scan_ports("127.0.0.1", common_ports)
print(f"\nOpen ports found: {results}")


/CVE Example Format./
text
# CVE-2025-12345 (example)
# Description : Remote code execution in ExampleApp v2.1 via crafted HTTP request.
# CVSS Score  : 9.8 (Critical)
# Affected    : ExampleApp < 2.2
# Fix         : Upgrade to ExampleApp 2.2 or apply vendor patch.
# Reference   : https://nvd.nist.gov/vuln/detail/CVE-2025-12345
