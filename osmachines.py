import socket

# Instantiate a new PortScanner object

class PortScanner:
    def __init__(self, target_host, port_range=(1, 65535)):
        self.target_host = target_host
        self.port_range = port_range

    def scan(self):
        for port in range(self.port_range[0], self.port_range[1]+1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            result = sock.connect_ex((self.target_host, port))
            if result == 0:
                print(f"Port {port} is open")
            sock.close()

# Prompt the user to enter an IP address
ip_address = input("Enter the target IP address: ")

# Scan the target host for operating system and service versions
PortScanner.scan(ip_address, arguments='-O -sV')

# Print the scan results for each host
for host in PortScanner.all_hosts():
    print('Host : %s (%s)' % (host, PortScanner[host].hostname()))
    print('State : %s' % PortScanner[host].state())
    for proto in PortScanner[host].all_protocols():
        print('Protocol : %s' % proto)

        lport = list(PortScanner[host][proto].keys())
        lport.sort()
        for port in lport:
            print('port : %s\tstate : %s\tname : %s\tproduct : %s\tversion : %s' %
                  (port, PortScanner[host][proto][port]['state'], PortScanner[host][proto][port]['name'],
                   PortScanner[host][proto][port]['product'], PortScanner[host][proto][port]['version']))
