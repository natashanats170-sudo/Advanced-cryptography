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
