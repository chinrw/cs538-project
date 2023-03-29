from pox.core import core
from pox.lib.revent import EventMixin
from pox.lib.packet import ethernet, ipv4, tcp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import logging
import random

log = core.getLogger()
TCP_NUM = 2**32 - 1

def create_rst_packet(self, connection_info, seq_number):
    rst_packet = ethernet(src=connection_info['client_mac'],
                          dst=connection_info['server_mac'],
                          type=ethernet.IP_TYPE)
    rst_ip_packet = ipv4(srcip=connection_info['client_ip'],
                         dstip=connection_info['server_ip'],
                         protocol=ipv4.TCP_PROTOCOL)
    rst_tcp_packet = tcp(srcport=connection_info['client_port'],
                         dstport=connection_info['server_port'],
                         seq=seq_number,
                         off=5,
                         flags=tcp.RST_flag)
    rst_packet.payload = rst_ip_packet
    rst_ip_packet.payload = rst_tcp_packet
    return rst_packet.pack()

def wrap_around(num):
    min_val = 0
    range_size = TCP_NUM - min_val
    return (num - min_val) % range_size + min_val



