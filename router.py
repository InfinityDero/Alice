from scapy.all import *
import argparse

FIRST_PACKET = 0
DST_IP = 0
DST_IFACE = 1
TIME_EXCEEDED = 0
NOT_FOUND = -1
TTL_EXPIRED_CODE = 0
HOST_UNREACHABLE_CODE = 1
TIME_EXCEEDED_TYPE = 11
DESTINATION_HOST_UNREACHABLE = 3
IFACE_1 = 'enp0s8'
IFACE_2 = 'enp0s9'


def main():
    routing_table = []
    setup_rules(routing_table)
    while(True):
        packets = sniff(iface=[IFACE_1, IFACE_2], count=1)
        p = packets[FIRST_PACKET]
        if IP in p:
            p[IP].ttl -= 1
            if p[IP].ttl <= TIME_EXCEEDED:
                ttl_time_exceeded(p)
            else:
                route_packet_by_rules(p, routing_table)
            
def ttl_time_exceeded(packet):
    sendp(Ether()/ IP(dst=packet[IP].src)/ ICMP(type=TIME_EXCEEDED_TYPE, code=TTL_EXPIRED_CODE)/ packet, iface=packet.sniffed_on)


def destination_host_unreachable(packet):
    sendp(Ether()/ IP(dst= packet[IP].src)/ ICMP(type= DESTINATION_HOST_UNREACHABLE, code=  HOST_UNREACHABLE_CODE)/ packet, iface= packet.sniffed_on)


def route_packet_by_rules(packet, routing_table):
    for rule in routing_table:
        if packet[IP].dst == rule.dst_ip and packet.sniffed_on != rule.dst_iface:
            sendp(Ether()/ packet[IP], iface= rule.dst_iface)
            return
        elif rule.dst_ip.find('/') != NOT_FOUND and rule.dst_ip.startswith(packet[IP].dst[:packet[IP].dst.rfind(".")]) and packet.sniffed_on != rule.dst_iface:
            sendp(Ether()/ packet[IP], iface= rule.dst_iface)
            return
    destination_host_unreachable(packet)

def setup_rules(routing_table):
    parser = argparse.ArgumentParser()
    parser.add_argument('--rule', action='append', nargs=2, help='Enter a rule like that: dst_ip dst_iface -> every packet with this dst ip will be sent to this interface(can add more rules by doing the flag again)')
    args = parser.parse_args()
    for rule in args.rule:
        routing_table.append(RoutingRule(rule[DST_IP], rule[DST_IFACE]))


class RoutingRule:
    def __init__(self, dst_ip, dst_iface):
        self.dst_ip = dst_ip
        self.dst_iface = dst_iface

    def print_rule(self):
        print(self.dst_ip, " ", self.dst_iface)


if __name__ == "__main__":
    main()
