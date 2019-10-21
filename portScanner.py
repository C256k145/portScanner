from scapy.all import *
import sys

print("Enter Target IP:")
target = input()

openPorts = []
closedPorts = []
filteredPorts = []

flag = 0
portTotal = 1023
# Sends a null packet with no flags to a port. An open port will send no response, a closed port would send a 
# response packet with a RST(reset) flag, and an ICMP filtered port will send an ICMP error response.
for port in range(1,portTotal):
    packet = sr1(IP(dst=target)/TCP(dport=port,flags=""),timeout=10,verbose=False)
    if packet is None:
        openPorts.append(port)
    elif(packet.haslayer(TCP)):
        if(packet.getlayer(TCP).flags == 0x14):
            closedPorts.append(port)
        elif(packet.haslayer(ICMP)):
            if(int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                filteredPorts.append(port)
    progress = round((port/portTotal)*100)
    if(port % 20 == 0):
        flag += 1
    sys.stdout.write(f'\r{str(progress)}% [{"="*(flag)}{"_"*(round(portTotal/20)-flag)}]')
    sys.stdout.flush()

print()
print("Open ports: " + str(openPorts))
print("Filtered ports: " + str(filteredPorts))

