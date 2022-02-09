
from ipaddress import ip_address, ip_network
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6

pkts = [p for i, (p, m) in enumerate(RawPcapReader('comn_cw/comn22cw/traffic_analysis/202201031400p.pcap'))
        if i < 100000000]
collect = []
count = 0
num = 0
for pkt in pkts:
    ether = Ether(pkt)
    num+=1
    if ether.type == 0x86dd:
        ip = ether[IPv6]
        count += 1
        # print('num=',num,'count=',count)
        collect.append(pkt)
        if (TCP in ip) and (ip.nh != 6):
            print('found! The ip number is ',num-1)
