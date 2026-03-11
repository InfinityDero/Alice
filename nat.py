from scapy.all import *

FIRST_PACKET = 0
OUT_MAC = '08:00:27:9a:ce:39'
OUT_IP = '192.168.240.4'
OUT_IFACE = "enp0s9"
IN_IFACE = "enp0s8"
BAD_PORT = 12345


def main():
    nat_table = []
    while(True):
        packets = sniff(iface=[OUT_IFACE, IN_IFACE], count=1)
        p = packets[FIRST_PACKET]
        if p.sniffed_on == IN_IFACE:
            send_packet_out(p, nat_table)
        elif p.sniffed_on == OUT_IFACE:
            if not check_if_bad_packet(p):      
                send_packet_in(p, nat_table)


def check_if_bad_packet(packet):
    if UDP in packet:
        if packet[UDP].sport == BAD_PORT:
            return True
    return False
   

def send_packet_out(p, nat_table):
    nat_line = NatTableLine(p)
    nat_table.append(nat_line)
    p[Ether].src = OUT_MAC
    if IP in p:
        p[IP].src = OUT_IP
    sendp(p, iface=OUT_IFACE)


def send_packet_in(p, nat_table):
    nat_line = check_matching_nat_line(p, nat_table)
    if not nat_line:
        return 
    p[Ether].dst = nat_line.src_mac
    if IP in p:
        p[IP].dst = nat_line.src_ip
    sendp(p, iface=IN_IFACE)


def check_matching_nat_line(p, nat_table):
    check_line = NatTableLine(p)
    for line in nat_table:
        if check_line.src_mac == line.dst_mac and check_line.src_ip == line.dst_ip and check_line.sport == line.dport:
            return line


class NatTableLine:
    def __init__(self, p):
        self.src_mac = p[Ether].src
        self.dst_mac = p[Ether].dst
        self.src_ip = ''
        self.dst_ip = ''
        self.sport = 0
        self.dport = 0
        if IP in p:
            self.src_ip = p[IP].src
            self.dst_ip = p[IP].dst
        if UDP in p:
            self.sport = p[UDP].sport
            self.dport = p[UDP].dport
        if TCP in p:
            self.sport = p[TCP].sport
            self.dport = p[TCP].dport

    def my_print(self):
        print(self.src_mac, self.dst_mac, self.src_ip, self.dst_ip, self.sport, self.dport)

        
if __name__ == "__main__":
    main();
