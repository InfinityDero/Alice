from scapy.all import *

FIRST_PACKET = 0


def main():
    while(True):
        packet = sniff(iface = "enp0s8", count=1)
    p = packet[FIRST_PACKET]
        sendp(p, iface = "enp0s9")


if __name__ == "__main__":
    main()
