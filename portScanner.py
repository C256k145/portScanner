from scapy.all import *
import sys
from pythonping import ping

openPorts = []
closedPorts = []
filteredPorts = []
portTotal = 1023

def getPing(ip):
    """ Gets the ping Time to the target IP, so as to make the scan run as quickly as possible. Returns the timeout
        in seconds that the scanning packets should use """
    response = ping(ip, size=20, count=3)
    if response.rtt_max == 2:
        return False
    else:
        return(1.5*(response.rtt_max))


# 10.104.255.254 default gateway
# 10.104.162.43 her ip
def scanPorts(ip, ports, pingTime):
    """ Sends a null packet with no flags to a port. An open port will send no response, a closed port would send a 
        response packet with a RST(reset) flag, and an ICMP filtered port will send an ICMP error response """
    progressIncrement = 0
    for port in range(1,ports):
        # This is just for the progress indicator
        progress = round((port/ports)*100)
        if(port % 20 == 0):
            progressIncrement += 1
        sys.stdout.write(f'\r{str(progress)}% [{"="*(progressIncrement)}{"_"*(round(ports/20)-progressIncrement)}]')
        sys.stdout.flush()
        # This is where the actual packet sending starts
        packet = sr1(IP(dst=ip)/TCP(dport=port,flags="S"),timeout=pingTime,verbose=False)
        if packet is None:
            closedPorts.append(port)
        elif(packet.haslayer(TCP)):
            if(packet.getlayer(TCP).flags == 0x12):
                openPorts.append(port)
            elif(packet.getlayer(TCP).flags == 0x14):
                if int(packet.haslayer(ICMP)):
                    if int(packet.getlayer(ICMP).type) == 3 and int(packet.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                        filteredPorts.append(port)
                    else:
                        closedPorts.append(port)
                else:
                    closedPorts.append(port)

                # int(packet.getlayer(ICMP).type) == 3 and 

def run():
    """ Calls all of the other functions. Starts by getting input and getting ping time to check if it is valid, then
        commences the scan """
    print("Enter Target IP:")
    target = input()
    ping = getPing(target)

    if(ping == False):
        print(f'Could not find host {target}')
    else:
        scanPorts(target, portTotal, ping)
        print("\nOpen ports: " + str(openPorts))
        print("Filtered ports: " + str(filteredPorts))

if __name__ == '__main__':
    run()

