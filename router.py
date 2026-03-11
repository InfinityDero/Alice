from scapy.all import *

FIRST_PACKET = 0


def main():
    while(True):
        packet = sniff()
        s = packet[FIRST_PACKET]
        if s[Ether].dst == '08:00:27:9a:ce:39':
            s[Ether].dst = '0a:00:27:00:00:3A'
            if ARP in s:
                s[ARP].pdst = '192.168.240.1'
                s[ARP].hwsrc = '0a:00:27:00:00:3A'
            if IP in s:
                s[IP].dst = '192.168.240.1'
            sendp(s, iface="enp0s8")
        else:
            s[Ether].src = '08:00:27:9a:ce:39'
            if ARP in s:
                s[ARP].psrc = '192.168.240.4'
                s[ARP].hwsrc = '08:00:27:9a:ce:39'
            if IP in s:
                s[IP].src = '192.168.240.4'
            sendp(s, iface="enp0s9")



if __name__ == "__main__":
    main()
