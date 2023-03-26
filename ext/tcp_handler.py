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

class SYNProxy(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.syn_proxy_state = {}

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                tcp_packet = ip_packet.payload
                if tcp_packet.SYN and not tcp_packet.ACK:
                    # Handle incoming SYN packet
                    self.handle_syn(event, packet, ip_packet, tcp_packet)
                elif tcp_packet.ACK and not tcp_packet.SYN:
                    # Handle incoming ACK packet from client
                    self.handle_ack_from_client(event, packet, ip_packet, tcp_packet)
                elif tcp_packet.SYN and tcp_packet.ACK:
                    # Handle incoming SYN-ACK packet from server
                    self.handle_syn_ack_from_server(event, packet, ip_packet, tcp_packet)
                else:
                    self.forward_packet(event)

    def handle_syn(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling SYN packet")
        # Store the original sequence number and other relevant information
        connection_info = {
            'original_seq': tcp_packet.seq,
            'client_ip': ip_packet.srcip,
            'client_port': tcp_packet.srcport,
            'server_ip': ip_packet.dstip,
            'server_port': tcp_packet.dstport,
            'client_mac': packet.src,
            'server_mac': packet.dst
        }
        # Generate seq number for SYN-ACK packet
        proxy_seq = random.randint(1, 2**32 - 1)  
        self.syn_proxy_state[proxy_seq] = connection_info

        # Create and send a SYN-ACK packet with the modified sequence number
        syn_ack = self.create_syn_ack_packet(connection_info, proxy_seq)
        self.send_packet_out(event.connection, syn_ack, event.port)

    def handle_ack_from_client(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling ACK packet from client")
        proxy_seq = tcp_packet.ack - 1
        if proxy_seq in self.syn_proxy_state:
            connection_info = self.syn_proxy_state[proxy_seq]
            original_seq = connection_info['original_seq']
            
            # Send a SYN packet to the server with the original sequence number
            syn_packet = self.create_syn_packet(connection_info, original_seq)
            self.send_packet_out(event.connection, syn_packet, event.port)
        else:
            log.warning("Unexpected ACK packet, dropping")
            return

    def handle_syn_ack_from_server(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling SYN-ACK packet from server")
        # Look for a matching connection in the state table
        for proxy_seq, connection_info in self.syn_proxy_state.items():
            if (connection_info['server_ip'] == ip_packet.srcip and
                    connection_info['server_port'] == tcp_packet.srcport):
                # Send the ACK packet to the client with the original sequence number
                ack_packet = self.create_ack_packet(connection_info, tcp_packet.seq + 1, proxy_seq + 1)
                self.send_packet_out(event.connection, ack_packet, event.port)
                break
        else:
            log.warning("Unexpected SYN-ACK packet, dropping")
            return

    # Utility functions for creating and sending packets
    def create_syn_ack_packet(self, connection_info, proxy_seq):
        syn_ack_packet = ethernet(src=connection_info['server_mac'],
                                  dst=connection_info['client_mac'],
                                  type=ethernet.IP_TYPE)
        syn_ack_ip_packet = ipv4(srcip=connection_info['server_ip'],
                                 dstip=connection_info['client_ip'],
                                 protocol=ipv4.TCP_PROTOCOL)
        syn_ack_tcp_packet = tcp(srcport=connection_info['server_port'],
                                 dstport=connection_info['client_port'],
                                 seq=proxy_seq,
                                 ack=connection_info['original_seq'] + 1,
                                 off=5,
                                 flags=tcp.SYN_flag and tcp.ACK_flag)
        syn_ack_packet.payload = syn_ack_ip_packet
        syn_ack_ip_packet.payload = syn_ack_tcp_packet
        return syn_ack_packet.pack()

    def create_syn_packet(self, connection_info, original_seq):
        syn_packet = ethernet(src=connection_info['client_mac'],
                              dst=connection_info['server_mac'],
                              type=ethernet.IP_TYPE)
        syn_ip_packet = ipv4(srcip=connection_info['client_ip'],
                             dstip=connection_info['server_ip'],
                             protocol=ipv4.TCP_PROTOCOL)
        syn_tcp_packet = tcp(srcport=connection_info['client_port'],
                             dstport=connection_info['server_port'],
                             seq=original_seq,
                             off=5,
                             flags=tcp.SYN)
        syn_packet.payload = syn_ip_packet
        syn_ip_packet.payload = syn_tcp_packet
        return syn_packet.pack()

    def create_ack_packet(self, connection_info, server_seq, original_ack):
        ack_packet = ethernet(src=connection_info['client_mac'],
                              dst=connection_info['server_mac'],
                              type=ethernet.IP_TYPE)
        ack_ip_packet = ipv4(srcip=connection_info['client_ip'],
                             dstip=connection_info['server_ip'],
                             protocol=ipv4.TCP_PROTOCOL)
        ack_tcp_packet = tcp(srcport=connection_info['client_port'],
                             dstport=connection_info['server_port'],
                             seq=original_ack - 1,
                             ack=server_seq,
                             off=5,
                             flags=tcp.ACK)
        ack_packet.payload = ack_ip_packet
        ack_ip_packet.payload = ack_tcp_packet
        return ack_packet.pack()

    def forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)
    
    def send_packet_out(self, connection, packet_data, in_port):
        msg = of.ofp_packet_out()
        msg.data = packet_data
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        msg.in_port = in_port
        connection.send(msg)


def launch():
    core.registerNew(SYNProxy)
