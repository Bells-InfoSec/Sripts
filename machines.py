from scapy.all import ARP,Ether,srp


t_ip= input("enter the ip like 192.168.100.2/24:  ")

arp = ARP(pdst=t_ip)
ether = Ether(dst="ff:ff:ff:ff:ff:ff")

packet = ether/arp

result = srp(packet, timeout=3,verbose=0)[0]

clients =[]

for sent, received in result:
      clients.append({'ip': received.psrc, 'mac': received.hwsrc})

print("Available devices in the network")

print("IP" + " "*18+"MAC")

for client in clients:
        print("{:16}    {}".format(client['ip'],client['mac']))