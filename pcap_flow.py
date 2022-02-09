from turtle import backward
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.inet6 import IPv6
from ipaddress import ip_address, IPv6Address
from socket import IPPROTO_TCP
import sys
import matplotlib.pyplot as plt

class Flow(object):
    def __init__(self, data):
        self.pkts = 0
        self.flows = 0
        self.ft = {}
        for pkt, metadata in RawPcapReader(data):
            self.pkts += 1
            ether = Ether(pkt)
            if ether.type == 0x86dd:#IPv6
                ip = ether[IPv6]
                if TCP not in ip or ip.nh != 6: 
                    continue
                # Payload length - TCP header length in Byte\
                tcp = ip[TCP]
                data_size = ip.plen - tcp.dataofs * 4
                
            elif ether.type == 0x0800: #IPv4
                ip = ether[IP]
                if TCP not in ip or ip.proto != 6:
                    continue
                # Whole Packet length - IP header length in Byte - TCP header length in Byte
                print(ip.ip_network)
                tcp = ip[TCP]
                data_size = ip.len - ip.ihl * 4 - tcp.dataofs * 4
            
            else:
                continue
            toward = (int(ip_address(ip.src)), int(ip_address(ip.dst)), tcp.sport, tcp.dport)
            backward = (int(ip_address(ip.dst)), int(ip_address(ip.src)), tcp.dport, tcp.sport)
            if toward in self.ft:
                self.ft[toward] += data_size
            elif backward in self.ft:
                self.ft[backward] += data_size
            else:
                self.ft[toward] = data_size
            
    def Plot(self):
        topn = 100
        data = [i/1000 for i in list(self.ft.values())]
        data.sort()
        data = data[-topn:]
        fig = plt.figure()
        ax = fig.add_subplot(1,1,1)
        ax.hist(data, bins=50, log=True)
        ax.set_ylabel('# of flows')
        ax.set_xlabel('Data sent [KB]')
        ax.set_title('Top {} TCP flow size distribution.'.format(topn))
        plt.savefig(sys.argv[1] + '.flow.pdf', bbox_inches='tight')
        plt.close()
    def _Dump(self):
        with open(sys.argv[1] + '.flow.data', 'w') as f:
            f.write('{}'.format(self.ft))

if __name__ == '__main__':
    d = Flow(sys.argv[1])
    d.Plot()
    d._Dump()
