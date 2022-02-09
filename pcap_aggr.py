from audioop import add
from logging import root
from turtle import left
from scapy.utils import RawPcapReader
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from ipaddress import ip_address, ip_network
import sys
import matplotlib.pyplot as plt

class Node(object):
    def __init__(self, ip, plen):
        self.bytes = plen
        self.left = None
        self.right = None
        self.ip = ip

    def add(self, ip, plen):
        if self.ip == ip:
            self.bytes += plen
        elif self.ip > ip:
            # self.left.ip < self.ip < self.right.ip
            if self.left:
                self.left.add(ip, plen)
            else:
                self.left = Node(ip, plen)
        else:
            if self.right:
                self.right.add(ip, plen)
            else:
                self.right = Node(ip, plen)

    def data(self, data):
        if self.left:
            self.left.data(data)
        if self.bytes > 0:
            data[ip_network(self.ip)] = self.bytes
        if self.right:
            self.right.data(data)
    @staticmethod 
    def supernet(ip1, ip2):
        # arguments are either IPv4Address or IPv4Network
        na1 = ip_network(ip1).network_address
        na2 = ip_network(ip2).network_address

        ip1_code = '{0:032b}'.format(int(na1))
        ip2_code = '{0:032b}'.format(int(na2))
        netmask = 0
        for i in range(32):
            if ip1_code[i] != ip2_code[i]:
                break
            netmask = i+1
        return ip_network('{}/{}'.format(na1, netmask), strict=False)

    def aggr(self, byte_thresh):
        if not self.left and not self.right:
            return
        if self.left:
            self.left.aggr(byte_thresh) # Transverse to the leaf
            if self.left.bytes < byte_thresh:  # 如果 左叶的流量过小
                self.bytes += self.left.bytes  # 将左叶纳为己有
                self.left.bytes = 0
                self.ip = self.supernet(self.ip, self.left.ip)
                if not self.left.left and not self.left.right:
                    self.left = None
            
        if self.right:
            self.right.aggr(byte_thresh)
            if self.right.bytes < byte_thresh:  
                self.bytes += self.right.bytes
                self.right.bytes = 0
                self.ip = self.supernet(self.ip, self.right.ip)
                if not self.right.left and not self.right.right:
                    self.right = None
            
        
class Data(object):
    def __init__(self, data):
        self.tot_bytes = 0
        self.data = {}
        self.aggr_ratio = 0.05
        root = None
        cnt = 0
        for pkt, metadata in RawPcapReader(data):
            ether = Ether(pkt)
            if not 'type' in ether.fields:
                continue
            if ether.type != 0x0800:
                continue
            ip = ether[IP]
            self.tot_bytes += ip.len
            if root is None:
                root = Node(ip_address(ip.src), ip.len)
            else:
                root.add(ip_address(ip.src), ip.len)
            cnt += 1
        root.aggr(self.tot_bytes * self.aggr_ratio)
        root.data(self.data)
    def Plot(self):
        data = {k: v/1000 for k, v in self.data.items()}
        plt.rcParams['font.size'] = 8
        fig = plt.figure()
        ax = fig.add_subplot(1, 1, 1)
        ax.grid(which='major', axis='y')
        ax.tick_params(axis='both', which='major')
        ax.set_xticks(range(len(data)))
        ax.set_xticklabels([str(l) for l in data.keys()], rotation=45,
            rotation_mode='default', horizontalalignment='right')
        ax.set_ylabel('Total bytes [KB]')
        ax.bar(ax.get_xticks(), data.values(), zorder=2)
        ax.set_title('IPv4 sources sending {} % ({}KB) or more traffic.'.format(
            self.aggr_ratio * 100, self.tot_bytes * self.aggr_ratio / 1000))
        plt.savefig(sys.argv[1] + '.aggr.pdf', bbox_inches='tight')
        plt.close()
    def _Dump(self):
        with open(sys.argv[1] + '.aggr.data', 'w') as f:
            f.write('{}'.format({str(k): v for k, v in self.data.items()}))

if __name__ == '__main__':
    d = Data(sys.argv[1])
    d.Plot()
    d._Dump()
