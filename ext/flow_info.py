

from functools import total_ordering
from collections import namedtuple

IPPort = namedtuple('IPPort', ['ip', 'port'])
TCP_NUM = 2 ** 32

def get_src(tcp_packet):
    ip_packet = tcp_packet.prev
    return IPPort(ip_packet.srcip, ip_packet.srcport)

def get_dst(tcp_packet):
    ip_packet = tcp_packet.prev
    return IPPort(ip_packet.dstip, ip_packet.dstport)

def get_flow(tcp_packet):
    a = get_src(tcp_packet)
    b = get_dst(tcp_packet)
    return FlowKey(a, b)

@total_ordering
class FlowKey(object):
    def __init__(self, a, b):
        self.a, self.b = sorted((IPPort(*a), IPPort(*b)))

    def __lt__(self, other):
        return (self.a, self.b) < (other.a, other.b)

    def __eq__(self, other):
        return (self.a, self.b) == (other.a, other.b)

    def __repr__(self):
        return f"FlowKey({self.a.ip}:{self.a.port},{self.b.ip}:{self.b.port})"

class FlowInfo:
    def __init__(self, tcp_packet):
        ip_packet = tcp_packet.prev
        packet = ip_packet.prev

        self.client = IPPort(ip_packet.srcip, tcp_packet.srcport)
        self.client_mac = packet.src,
        
        self.server = IPPort(ip_packet.dstip, tcp_packet.dstport)
        self.server_mac = packet.dst,

        # saved packeets for later use
        self.client_syn = tcp_packet
        self.client_ack = None

        # options
        self.client_tcp_options = tcp_packet.options
        self.client_tcp_window = tcp_packet.win
        ## server's tcp option is unknown but cannot be left empty
        self.server_tcp_options = tcp_packet.options
        self.server_tcp_window = tcp_packet.win

        self.policy = 0

        # state for policy 0
        self.proxy_seq = None
        self.server_seq = None

    def add_proxy_synack(self, tcp_packet):
        self.proxy_seq = tcp_packet.seq

    def add_client_ack(self, tcp_packet):
        self.client_ack = tcp_packet

    def add_server_synack(self, tcp_packet):
        self.server_seq = tcp_packet.seq
        self.server_tcp_options = tcp_packet.options
        self.server_tcp_window = tcp_packet.win

    def get_state(self):
        if self.proxy_seq is None:
            return 'Initial'
        if self.client_ack is None:
            return 'Spoofed SYNACK'
        if self.server_seq is None:
            return 'Spoofed SYN'
        return 'Established' # i.e. Spoofed ACK

    def translate(self, tcp_packet):
        src = get_src(tcp_packet)
        dst = get_dst(tcp_packet)
        if (src, dst) == (self.client, self.server):
            # rewrite ack, from clent's view to server's view
            ack = tcp_packet.ack - self.proxy_seq + self.server_seq
            tcp_packet.ack = ack % TCP_NUM
        elif (src, dst) == (self.server, self.client):
            # rewrite seq, from server's view to client's view
            seq = tcp_packet.seq - self.server_seq + self.proxy_seq
            tcp_packet.seq = seq % TCP_NUM
        else:
            packet_key = get_flow(tcp_packet)
            self_key = FlowKey(self.client, self.server)
            assert packet_key == self_key, f"Flow {self_key} and packet {packet_key} mismatch"
            raise ValueError("Unreachable")
