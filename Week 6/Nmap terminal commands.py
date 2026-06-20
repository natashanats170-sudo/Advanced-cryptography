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
