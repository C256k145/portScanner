from scapy.all import *
import sys

print("Enter Target IP:")
target = input()

openPorts = []
closedPorts = []
filteredPorts = []

progressIncrement = 0
portTotal = 1000
# Sends a null packet with no flags to a port. An open port will send no response, a closed port would send a 
# response packet with a RST(reset) flag, and an ICMP filtered port will send an ICMP error response.
for port in range(1,portTotal):
    # This is just for the progress indicator
    progress = round((port/portTotal)*100)
    if(port % 20 == 0):
        progressIncrement += 1
    sys.stdout.write(f'\r{str(progress)}% [{"="*(progressIncrement)}{"_"*(round(portTotal/20)-progressIncrement)}]')
    sys.stdout.flush()
    # This is where the actual packet sending starts
    packet = sr1(IP(dst=target)/TCP(dport=port,flags="S"),timeout=1,verbose=False)
    if packet is None:
        closedPorts.append(port)
    elif(packet.haslayer(TCP)):
        if(packet.getlayer(TCP).flags == 0x12):
            openPorts.append(port)
        elif(packet.getlayer(TCP).flags == 0x14):
            # if(int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                # filteredPorts.append(port)
            closedPorts.append(port)

print("\nOpen ports: " + str(openPorts))
# print("Filtered ports: " + str(filteredPorts))

