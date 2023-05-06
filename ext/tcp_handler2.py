from pox.core import core
from pox.lib.revent import EventMixin
from pox.lib.packet import ethernet, ipv4, tcp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import logging
import random

log = core.getLogger()
log_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_handler = logging.StreamHandler()
log_handler.setFormatter(log_format)
log.addHandler(log_handler)

def quadruple(tcp_packet):
    ip_packet = tcp_packet.prev
    return (
        ip_packet.srcip,
        tcp_packet.srcport,
        ip_packet.dstip,
        tcp_packet.dstport,
    )

class syn_proxy_conn_info:
    def __init__(self, tcp_packet):
        ip_packet = tcp_packet.prev
        packet = ip_packet.prev

        self.client_mac = packet.src
        self.client_ip = ip_packet.srcip
        self.client_port = tcp_packet.srcport

        self.server_mac = packet.dst
        self.server_ip = ip_packet.dstip
        self.server_port = tcp_packet.dstport

        self.original_seq = tcp_packet.seq
        self.proxy_seq = random.randint(1, 2**32 - 1)
    
    def spoofed_synack(self):
        packet = ethernet(src=self.server_mac,
                          dst=self.client_mac,
                          type=ethernet.IP_TYPE)
        ip_packet = ipv4(srcip=self.server_ip,
                         dstip=self.client_ip,
                         protocol=ipv4.TCP_PROTOCOL)
        tcp_packet = tcp(srcport=self.server_port,
                         dstport=self.client_port,
                         seq=self.proxy_seq,
                         ack=self.original_seq + 1,
                         off=5,
                         flags=tcp.SYN_flag | tcp.ACK_flag)
        packet.payload = ip_packet
        ip_packet.payload = tcp_packet
        return packet.pack()
    
    def spoofed_syn(self):
        # could just use the actual syn
        # handle non responding server
        packet = ethernet(src=self.client_mac,
                          dst=self.server_mac,
                          type=ethernet.IP_TYPE)
        ip_packet = ipv4(srcip=self.client_ip,
                         dstip=self.server_ip,
                         protocol=ipv4.TCP_PROTOCOL)
        tcp_packet = tcp(srcport=self.client_port,
                         dstport=self.server_port,
                         seq=self.original_seq,
                         off=5,
                         flags=tcp.SYN_flag)
        packet.payload = ip_packet
        ip_packet.payload = tcp_packet
        return packet.pack()

    # def spoofed_ack(self):
    #     # could just translate seq

def send_packet_out(connection, packet_data, in_port, output_port):
    msg = of.ofp_packet_out()
    msg.data = packet_data
    msg.in_port = in_port
    log.debug("Sending packet out on port %s and in_port %s" , output_port, msg.in_port)
    msg.actions.append(of.ofp_action_output(port=output_port))
    connection.send(msg)


class SYNProxy(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.pending_syn = {}

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                # self.mac_to_port[packet.src] = event.port
                tcp_packet = ip_packet.payload
                quad = quadruple(tcp_packet)
                if tcp_packet.SYN and not tcp_packet.ACK:
                    log.debug(f"SYN packet {quad} {event.connection}")
                    self.handle_syn(event, tcp_packet)
                elif tcp_packet.ACK and not tcp_packet.SYN:
                    log.debug(f"ACK packet {quad}")
                    self.handle_ack(event, tcp_packet)
                elif tcp_packet.SYN and tcp_packet.ACK:
                    log.debug(f"SYN-ACK packet {quad}")
                    self.handle_synack(event, tcp_packet)
                elif tcp_packet.RST:
                    log.debug(f"RST packet {quad}")
                else:
                    # malformed packet; should drop
                    log.debug(f"malformed packet?? {quad}")

    def handle_syn(self, event, tcp_packet):
        quad = quadruple(tcp_packet)
        info = syn_proxy_conn_info(tcp_packet)
        self.pending_syn[quad] = info
        synack = info.spoofed_synack()
        send_packet_out(event.connection, synack, of.OFPP_NONE, event.port)
        event.halt = True

    def handle_ack(self, event, tcp_packet):
        # no translate for now
        # is the ack part of handshake?
        quad = quadruple(tcp_packet)
        info = self.pending_syn.get(quad)
        if info is not None:
            log.debug("is handshake ack!?")
            del self.pending_syn[quad]
            syn = info.spoofed_syn()
            send_packet_out(event.connection, syn, event.port, of.OFPP_FLOOD)
            event.halt = True
        else:
            log.debug("is data ack!?")
        pass

    def handle_synack(self, event, tcp_packet):
        pass

def launch():
    core.registerNew(SYNProxy)
