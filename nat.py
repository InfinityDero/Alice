from scapy.all import *
import argparse

FIRST_PACKET = 0
OUT_MAC = '08:00:27:9a:ce:39'
OUT_IP = '192.168.240.4'
OUT_IFACE = "enp0s9"
IN_IFACE = "enp0s8"
BAD_PORT = 12345
DEFAULT_PORT = -1


def main():
    rules = set_up_rules()
    nat_table = []
    while(True):
        packets = sniff(iface=[OUT_IFACE, IN_IFACE], count=1)
        p = packets[FIRST_PACKET]
        if p.sniffed_on == IN_IFACE:
            send_packet_out(p, nat_table)
        elif p.sniffed_on == OUT_IFACE:
            if pass_firewall(p, rules): 
                send_packet_in(p, nat_table)
            else:
                print("blocked packet")


def pass_firewall(recived_packet, rules):
    if check_if_fall_ether_rules(recived_packet, rules):
        return False
    if check_if_fall_ip_rules(recived_packet, rules):
        return False
    if check_if_fall_transport_rules(recived_packet, rules):
        return False
    return True


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


def set_up_rules():
    parser = argparse.ArgumentParser(description="A way to add rules to a firewall, for each argument here blocks all the packets with the given argument(if given)")
    parser.add_argument('--ether_src', type=str, default='')
    parser.add_argument('--ether_dst', type=str, default='')
    parser.add_argument('--ip', action="store_true")
    parser.add_argument('--ip_src', type=str, default='')
    parser.add_argument('--ip_dst', type=str, default='')
    parser.add_argument('--udp', action="store_true")
    parser.add_argument('--udp_sport', type=int, default=DEFAULT_PORT)
    parser.add_argument('--udp_dport', type=int, default=DEFAULT_PORT)
    parser.add_argument('--tcp', action="store_true")
    parser.add_argument('--tcp_sport', type=int, default=DEFAULT_PORT)
    parser.add_argument('--tcp_dport', type=int, default=DEFAULT_PORT)
    args = parser.parse_args()
    rules = Rules(args.ether_src, args.ether_dst, args.ip, args.ip_src, args.ip_dst, args.udp, args.udp_sport, args.udp_dport, args.tcp, args.tcp_sport, args.tcp_dport)
    return rules


def check_if_fall_ether_rules(recived_packet, rules):
    if recived_packet[Ether].src == rules.ether_src or recived_packet[Ether].dst == rules.ether_dst:
        return True
    return False


def check_if_fall_ip_rules(recived_packet, rules):
    if IP in recived_packet:
        if rules.ip:
            return True
        if recived_packet[IP].src == rules.ip_src or recived_packet[IP].dst == rules.ip_dst:
            return True
    return False


def check_if_fall_transport_rules(recived_packet, rules):
    if UDP in recived_packet:
        if rules.udp:
            return True
        if recived_packet[UDP].sport == rules.udp_sport or recived_packet[UDP].dport == rules.udp_dport:
            return True
    elif TCP in recived_packet:
        if rules.tcp:
            return True
        if recived_packet[TCP].sport == rules.tcp_sport or recived_packet[TCP].dport == rules.tcp_dport:
            return True
    return False


class Rules:
    def __init__(self, ether_src, ether_dst, ip, ip_src, ip_dst, udp, udp_sport, udp_dport, tcp, tcp_sport, tcp_dport):
        self.ether_src = ether_src
        self.ether_dst = ether_dst
        self.ip = ip
        self.ip_src = ip_src
        self.ip_dst = ip_dst
        self.udp = udp
        self.udp_sport = udp_sport
        self.udp_dport = udp_dport
        self.tcp = tcp
        self.tcp_sport = tcp_sport
        self.tcp_dport = tcp_dport


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
