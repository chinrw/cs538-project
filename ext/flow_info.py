from functools import total_ordering
from collections import namedtuple
from enum import Enum
from random import randint
from collections import defaultdict
# for type hints
from pox.lib.packet import tcp, ipv4, ethernet
from typing import Tuple, Union

TCP_NUM = 2 ** 32
IPPort = namedtuple('IPPort', ['ip', 'port'])

@total_ordering
class FlowKey(object):
    def __init__(self, a: Tuple[any, any], b: Tuple[any, any]):
        self.a, self.b = sorted((IPPort(*a), IPPort(*b)))

    def __lt__(self, other):
        return (self.a, self.b) < (other.a, other.b)

    def __eq__(self, other):
        return (self.a, self.b) == (other.a, other.b)

    def __repr__(self):
        return f"FlowKey({self.a.ip}:{self.a.port},{self.b.ip}:{self.b.port})"

    def __hash__(self):
        return hash((self.a, self.b))

FlowState = Enum('FlowState', ['Initial', 'SpoofedSYNACK', 'SpoofedSYN', 'Established'])
Placeholder = Enum('Placeholder', [])


class FlowInfo:
    def __init__(self, tcp_packet: tcp, policy: int):
        ip_packet: ipv4
        ip_packet = tcp_packet.prev
        packet: ethernet
        packet = ip_packet.prev

        self.client = IPPort(ip_packet.srcip, tcp_packet.srcport)
        self.client_mac = packet.src

        self.server = IPPort(ip_packet.dstip, tcp_packet.dstport)
        self.server_mac = packet.dst

        # saved packeets for later use
        self.client_syn = tcp_packet
        self.client_ack = None

        # options
        self.client_tcp_options = tcp_packet.options
        self.client_tcp_window = tcp_packet.win
        ## server's tcp option is unknown but cannot be left empty
        self.server_tcp_options = tcp_packet.options
        self.server_tcp_window = tcp_packet.win

        self.policy = policy

        # state for policy 0
        self.proxy_seq = None
        self.server_seq = None

    def add_proxy_synack(self, tcp_packet: tcp):
        self.proxy_seq = tcp_packet.seq

    def add_client_ack(self, tcp_packet: tcp):
        self.client_ack = tcp_packet

    def add_server_synack(self, tcp_packet: tcp):
        self.server_seq = tcp_packet.seq
        self.server_tcp_options = tcp_packet.options
        self.server_tcp_window = tcp_packet.win

    # call this after sending out all spoofed packets
    def clear_packets(self):
        assert self.client_syn and self.client_ack
        self.client_syn = Placeholder
        self.client_ack = Placeholder

    def get_state(self):
        if self.proxy_seq is None:
            return FlowState.Initial
        if self.client_ack is None:
            return FlowState.SpoofedSYNACK
        if self.server_seq is None:
            return FlowState.SpoofedSYN
        return FlowState.Established # i.e. Spoofed ACK

class Host:
    def __init__(self) -> None:
        self.in_flight = 0
        self.threshold  = 100

    def set_threshold(self, num):
        self.threshold  = num

    def syn_received(self):
        self.in_flight += 1

    def tcp_established(self):
        self.in_flight -= 1
        assert self.in_flight >= 0

    def get_policy(self):
        if self.in_flight < self.threshold:
            return 0
        else:
            return 1

class HostCounter:
    def __init__(self):
        self.hosts = defaultdict(Host)

    def add_flow(self, client_ip):
        self.hosts[client_ip].syn_received()

    def flow_established(self, client_ip):
        assert client_ip in self.hosts
        self.hosts[client_ip].tcp_established()

    def get_host_policy(self, client_ip):
        return self.hosts[client_ip].get_policy()

# address helpers

def get_src(tcp_packet: tcp):
    ip_packet = tcp_packet.prev
    return IPPort(ip_packet.srcip, tcp_packet.srcport)

def get_dst(tcp_packet: tcp):
    ip_packet = tcp_packet.prev
    return IPPort(ip_packet.dstip, tcp_packet.dstport)

def get_flow(tcp_packet: tcp):
    a = get_src(tcp_packet)
    b = get_dst(tcp_packet)
    return FlowKey(a, b)

# packet helpers

def translate_packet(flow: FlowInfo, tcp_packet: tcp):
    src = get_src(tcp_packet)
    dst = get_dst(tcp_packet)
    if (src, dst) == (flow.client, flow.server):
        # rewrite ack, from clent's view to server's view
        ack = tcp_packet.ack - flow.proxy_seq + flow.server_seq
        tcp_packet.ack = ack % TCP_NUM
    elif (src, dst) == (flow.server, flow.client):
        # rewrite seq, from server's view to client's view
        seq = tcp_packet.seq - flow.server_seq + flow.proxy_seq
        tcp_packet.seq = seq % TCP_NUM
    else:
        key = FlowKey(flow.client, flow.server)
        packet_key = get_flow(tcp_packet)
        assert key == packet_key, f"Flow {key} and packet {packet_key} mismatch"
        raise ValueError("Unreachable")

def spoofed_synack(flow: FlowInfo):
    packet = ethernet(src=flow.server_mac,
                      dst=flow.client_mac,
                      type=ethernet.IP_TYPE)
    ip_packet = ipv4(srcip=flow.server.ip,
                        dstip=flow.client.ip,
                        protocol=ipv4.TCP_PROTOCOL)
    tcp_packet = tcp(srcport=flow.server.port,
                        dstport=flow.client.port,
                        seq=randint(0, TCP_NUM - 1),
                        ack=flow.client_syn.seq + 1,
                        off=5,
                        flags=tcp.SYN_flag | tcp.ACK_flag,
                        win=flow.server_tcp_window,
                        options=flow.server_tcp_options)
    packet.payload = ip_packet
    ip_packet.payload = tcp_packet
    return tcp_packet
