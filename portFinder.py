from scapy.all import *

print("Enter Target IP:")
target = input()

openPorts = []
closedPorts = []
filteredPorts = []

for port in range(1,1023):
    packet = sr1(IP(dst=target)/TCP(dport=port,flags=""),timeout=10)
    if (str(type(packet))=="<class 'NoneType'>"):
        openPorts.append(port)
    # elif(packet.haslayer(TCP)):
    #     if(packet.getlayer(TCP).flags == 0x14):
    #         closedPorts.append(port)
    #     elif(packet.haslayer(ICMP)):
    #         if(int(packet.getlayer(ICMP).type)==3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]):
    #             filteredPorts.append(port)

print("Open ports: " + str(openPorts))
print("Filtered ports: " + str(filteredPorts))

