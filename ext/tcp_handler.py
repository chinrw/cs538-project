from pox.core import core
from pox.lib.revent import EventMixin
from pox.lib.packet import ethernet, ipv4, tcp
from pox.lib.addresses import IPAddr, EthAddr
import pox.openflow.libopenflow_01 as of
import logging
import random
from helper import *

# log_format = logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# log_handler = logging.StreamHandler()
# log_handler.setFormatter(log_format)
# log.addHandler(log_handler)


class SYNProxy(EventMixin):
    def __init__(self):
        self.listenTo(core.openflow)
        self.syn_proxy_state = {}
        self.mac_to_port = {}

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return

        if packet.type == ethernet.IP_TYPE:
            ip_packet = packet.payload
            if ip_packet.protocol == ipv4.TCP_PROTOCOL:
                # Update the mac_to_port dictionary
                event.halt = True
                self.mac_to_port[packet.src] = event.port
                tcp_packet = ip_packet.payload
                if tcp_packet.SYN and not tcp_packet.ACK:
                    # log.debug("Handle incoming SYN packet")
                    self.handle_syn(event, packet, ip_packet, tcp_packet)
                elif tcp_packet.ACK and not tcp_packet.SYN:
                    # log.debug("Handle incoming ACK packet from client")
                    connection_info = self.finding_connection_info(ip_packet, tcp_packet)
                    if connection_info is not None and connection_info['finished_handshake']:
                        log.debug("Translating and forwarding non-SYN packet")
                        self.translate_and_forward_packet(
                            event, packet, ip_packet, tcp_packet)
                    elif (not self.handle_ack_from_client(
                            event, packet, ip_packet, tcp_packet)):
                        log.debug("Translating and forwarding non-SYN packet")
                        self.translate_and_forward_packet(
                            event, packet, ip_packet, tcp_packet)

                elif tcp_packet.SYN and tcp_packet.ACK:
                    # log.debug("Handle incoming SYN-ACK packet from server")
                    self.handle_syn_ack_from_server(
                        event, packet, ip_packet, tcp_packet)
                else:
                    log.debug("Translating and forwarding non-SYN packet")
                    self.translate_and_forward_packet(
                        event, packet, ip_packet, tcp_packet)
                    # event.halt = False

    def handle_syn(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling SYN packet")
        log.debug(f"TCP {tcp_packet} ")
        # Store the original sequence number and other relevant information
        connection_info = {
            'original_seq': tcp_packet.seq,
            'server_seq': None,
            'client_ip': ip_packet.srcip,
            'client_port': tcp_packet.srcport,
            'server_ip': ip_packet.dstip,
            'server_port': tcp_packet.dstport,
            'client_mac': packet.src,
            'server_mac': packet.dst,
            'tcp_options': tcp_packet.options,
            'client_tcp_window': tcp_packet.win,
            'server_tcp_window': None,
            'original_syn': tcp_packet,
            'client_ack': None,
            'finished_handshake': False
        }
        log.debug(connection_info)
        # Generate seq number for SYN-ACK packet
        proxy_seq = random.randint(1, TCP_NUM)
        self.syn_proxy_state[proxy_seq] = connection_info

        # Create and send a SYN-ACK packet with the modified sequence number
        log.debug("Sending SYN-ACK packet to client")
        syn_ack = self.create_syn_ack_packet(connection_info, proxy_seq)
        output_port = self.mac_to_port.get(
            connection_info['client_mac'], of.OFPP_FLOOD)
        self.send_packet_out(event.connection, syn_ack,
                             event.port, output_port)

    def handle_ack_from_client(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling ACK packet from client, will send SYN to server")
        proxy_seq = tcp_packet.ack - 1
        if proxy_seq in self.syn_proxy_state:
            connection_info = self.syn_proxy_state[proxy_seq]
            if connection_info['finished_handshake']:
                log.debug(
                    "handshake already established, translate and forward")
                return False
            original_seq = connection_info['original_seq']
            connection_info['client_ack'] = tcp_packet

            # Send a SYN packet to the server with the original sequence number
            syn_packet = self.create_syn_packet(connection_info, original_seq)
            output_port = self.mac_to_port.get(
                connection_info['server_mac'], of.OFPP_FLOOD)
            self.send_packet_out(
                event.connection, syn_packet, event.port, output_port)
            return True
        else:
            log.warning("Unexpected ACK packet, ignore")
            event.halt = False
            return True

    def finding_connection_info(self, ip_packet, tcp_packet):
        for proxy_seq, connection_info in self.syn_proxy_state.items():
            is_src_server = (
                connection_info['server_ip'] == ip_packet.srcip
                and connection_info['server_port'] == tcp_packet.srcport
            )
            is_dst_server = (
                connection_info['server_ip'] == ip_packet.dstip
                and connection_info['server_port'] == tcp_packet.dstport
            )
            is_dst_client = (
                connection_info['client_ip'] == ip_packet.dstip
                and connection_info['client_port'] == tcp_packet.dstport
            )
            is_src_client = (
                connection_info['client_ip'] == ip_packet.srcip
                and connection_info['client_port'] == tcp_packet.srcport
            )

            if (is_src_server or is_dst_server) and (is_src_client or is_dst_client):
                return connection_info
        else:
            log.warning("Unexpected SYN-ACK packet, dropping")
            return None

    def handle_syn_ack_from_server(self, event, packet, ip_packet, tcp_packet):
        log.debug("Handling SYN-ACK packet from server")
        # Look for a matching connection in the state table
        for proxy_seq, connection_info in self.syn_proxy_state.items():
            if (connection_info['server_ip'] == ip_packet.srcip and
                    connection_info['server_port'] == tcp_packet.srcport):
                # Send the ACK packet to the client with the original sequence number
                connection_info['server_seq'] = tcp_packet.seq
                log.debug(
                    "Found matching connection, sending ACK packet to server")
                ack_packet = self.create_ack_packet(
                    connection_info, tcp_packet.ack, connection_info['server_seq'] + 1)
                connection_info['server_tcp_window'] = tcp_packet.win
                # output_port = self.mac_to_port.get(
                #     connection_info['client_mac'], of.OFPP_FLOOD)
                output_port = 2
                self.send_packet_out(
                    event.connection, ack_packet, event.port, output_port)

                connection_info['finished_handshake'] = True
                log.debug("Finished handshake, connection established")
                break
        else:
            log.warning("Unexpected SYN-ACK packet, ignore")
            event.halt = False
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
                                 flags=tcp.SYN_flag | tcp.ACK_flag,
                                 win=connection_info['client_tcp_window'],
                                 options=connection_info['tcp_options'])
        syn_ack_packet.payload = syn_ack_ip_packet
        syn_ack_ip_packet.payload = syn_ack_tcp_packet
        log.debug(syn_ack_tcp_packet)
        return syn_ack_packet.pack()

    def create_syn_packet(self, connection_info, original_seq):
        syn_packet = ethernet(src=connection_info['client_mac'],
                              dst=connection_info['server_mac'],
                              type=ethernet.IP_TYPE)
        syn_ip_packet = ipv4(srcip=connection_info['client_ip'],
                             dstip=connection_info['server_ip'],
                             protocol=ipv4.TCP_PROTOCOL)

        syn_packet.payload = syn_ip_packet
        syn_ip_packet.payload = connection_info['original_syn']
        return syn_packet.pack()

    def create_ack_packet(self, connection_info, server_seq, original_ack):
        # Create an ACK packet from the server to the client
        log.debug("Creating ACK packet from server to client, with seq %d and ack %d",
                  server_seq, original_ack)
        ack_packet = ethernet(src=connection_info['client_mac'],
                              dst=connection_info['server_mac'],
                              type=ethernet.IP_TYPE)
        ack_ip_packet = ipv4(srcip=connection_info['client_ip'],
                             dstip=connection_info['server_ip'],
                             protocol=ipv4.TCP_PROTOCOL)
        ack_tcp_packet = connection_info['client_ack']
        ack_tcp_packet.seq = server_seq
        ack_tcp_packet.ack = original_ack
        ack_packet.payload = ack_ip_packet
        ack_ip_packet.payload = ack_tcp_packet
        return ack_packet.pack()

    def translate_and_forward_packet(self, event, packet, ip_packet, tcp_packet):
        direction = None
        connection_info = None
        # packet = event.parsed
        # ip_packet = packet.payload
        # tcp_packet = ip_packet.payload
        for proxy_seq, conn_info in self.syn_proxy_state.items():
            if (conn_info['client_ip'] == ip_packet.srcip and
                    conn_info['client_port'] == tcp_packet.srcport):
                direction = 'client_to_server'
                # conn_info['client_tcp_window'] = tcp_packet.win
                # tcp_packet.win = conn_info['server_tcp_window']
                connection_info = conn_info
                break
            elif (conn_info['server_ip'] == ip_packet.srcip and
                    conn_info['server_port'] == tcp_packet.srcport):
                direction = 'server_to_client'
                # conn_info['server_tcp_window'] = tcp_packet.win
                # tcp_packet.win = conn_info['client_tcp_window']
                connection_info = conn_info
                break

        if direction is None or connection_info is None:
            log.warning("Unknown connection, dropping packet")
            return

        original_seq = connection_info['original_seq']
        server_seq = connection_info['server_seq']
        proxy_seq = list(self.syn_proxy_state.keys())[list(
            self.syn_proxy_state.values()).index(connection_info)]

        log.debug(f"Original seq {original_seq}, proxy seq {proxy_seq}")
        log.debug(
            f"Original packet, seq {tcp_packet.seq}, ack {tcp_packet.ack}")
        if direction == 'client_to_server':
            diff = server_seq - proxy_seq
            output_port = self.mac_to_port.get(
                connection_info['server_mac'], of.OFPP_FLOOD)
            tcp_packet.ack = wrap_around(tcp_packet.ack + diff)
        else:  # 'server_to_client'
            diff = tcp_packet.seq - proxy_seq - 1
            output_port = self.mac_to_port.get(
                connection_info['client_mac'], of.OFPP_FLOOD)
            tcp_packet.seq = wrap_around(tcp_packet.seq - diff)

        log.debug(tcp_packet)
        ip_packet.payload = tcp_packet
        packet.payload = ip_packet

        # Send the translated packet
        msg = of.ofp_packet_out()
        msg.data = packet.pack()
        log.debug(
            f"Sending packet out on port {output_port}, in_port {event.port}")
        msg.actions.append(of.ofp_action_output(port=output_port))
        msg.in_port = event.port
        event.connection.send(msg)

    def forward_packet(self, event):
        msg = of.ofp_packet_out()
        msg.data = event.ofp
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        event.connection.send(msg)

    def send_packet_out(self, connection, packet_data, in_port, output_port):
        msg = of.ofp_packet_out()
        msg.data = packet_data
        log.debug("Sending packet out on port %s and in_port %s",
                  output_port, in_port)
        msg.actions.append(of.ofp_action_output(port=output_port))
        if in_port != output_port:
            msg.in_port = in_port
        connection.send(msg)


def launch():
    core.registerNew(SYNProxy)
