from pox.core import core
from pox.lib.revent import EventMixin
from pox.lib.packet import ethernet, ipv4, tcp
from pox.messenger import Connection
import pox.openflow.libopenflow_01 as of
from flow_info import *
# for type hints
from typing import Dict

# log_format = logging.Formatter(
#     '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# log_handler = logging.StreamHandler()
# log_handler.setFormatter(log_format)
# log.addHandler(log_handler)

log = core.getLogger()

def send_packet_out(connection: Connection, tcp_packet: tcp, in_port, output_port):
    msg = of.ofp_packet_out()
    msg.data = tcp_packet.prev.prev
    msg.in_port = in_port
    log.debug("Sending packet out on port %s and in_port %s" , output_port, msg.in_port)
    msg.actions.append(of.ofp_action_output(port=output_port))
    connection.send(msg)

class SYNProxy(EventMixin):
    flow_table: Dict[FlowKey, FlowInfo]
    def __init__(self):
        self.listenTo(core.openflow)
        self.flow_table = {}
        self.mac_table = {}

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed:
            log.warning("Ignoring incomplete packet")
            return
        if packet.type != ethernet.IP_TYPE:
            log.warning("Handling ip packet only")
            return

        self.mac_table[packet.src] = event.port
        # TODO: send RST instead of discarding invalid tcp

        ip_packet = packet.payload
        if ip_packet.protocol != ipv4.TCP_PROTOCOL:
            log.warning("Handling ipv4 packet only")
            return

        event.halt = True
        tcp_packet = ip_packet.payload
        if tcp_packet.RST:
            # RST can replace SYNACK, when proxy_seq is not set
            log.debug("Handle RST packet")
            self.handle_rst(event, tcp_packet)
        elif tcp_packet.FIN:
            # seem to be the same as RST
            log.debug("Handle FIN packet")
            self.handle_fin(event, tcp_packet)
        elif tcp_packet.SYN and not tcp_packet.ACK:
            # log.debug("Handle incoming SYN packet")
            self.handle_syn(event, tcp_packet)
        elif tcp_packet.ACK and not tcp_packet.SYN:
            # log.debug("Handle ACK packet")
            flow = self.flow_table.get(get_flow(tcp_packet))
            state = flow and flow.get_state()
            if state == FlowState.SpoofedSYNACK:
                self.handle_handshake_ack(event, tcp_packet)
            elif state == FlowState.Established:
                self.handle_data_ack(event, tcp_packet)
            else:
                log.warning(f'Illegal ACK state {flow and flow.get_state()}')
        elif tcp_packet.SYN and tcp_packet.ACK:
            # log.debug("Handle incoming SYN-ACK packet from server")
            self.handle_synack(event, tcp_packet)
        else:
            # what else?
            log.warning(f'Unknown flag combination {tcp_packet.flags}, dropping')

    def handle_syn(self, event, tcp_packet: tcp):
        flow = FlowInfo(tcp_packet)
        self.flow_table[get_flow(tcp_packet)] = flow
        # Create and send a SYN-ACK packet with the modified sequence number
        synack = spoofed_synack(flow)
        log.debug('Sending SYNACK to client')
        send_packet_out(event.connection, synack, of.OFPP_NONE, event.port)
        flow.add_proxy_synack(synack)

    def handle_handshake_ack(self, event, tcp_packet: tcp):
        # flow exists
        flow = self.flow_table.get(get_flow(tcp_packet))
        log.debug('Sending SYN to server')
        send_packet_out(event.connection, flow.client_syn, event.port, self.dst_port(tcp_packet))
        flow.add_client_ack(tcp_packet)

    def handle_synack(self, event, tcp_packet: tcp):
        # flow may not exist
        flow = self.flow_table.get(get_flow(tcp_packet))
        if not flow:
            log.warning('Unexpected SYNACK packet, dropping')
            return
        flow.add_server_synack(tcp_packet)
        log.debug('Sending ACK to server')
        translate_packet(flow, flow.client_ack)
        send_packet_out(event.connection, flow.client_ack, of.OFPP_NONE, event.port)
        flow.clear_packets()

    def handle_data_ack(self, event, tcp_packet: tcp):
        log.debug('Forwarding ACK')
        self.translate_and_forward(event, tcp_packet)

    def handle_rst(self, event, tcp_packet: tcp):
        # ignore if flow does not exist
        # if seq incomplete and rst comes from server
        flow = self.flow_table.get(get_flow(tcp_packet))
        state = flow and flow.get_state()
        if state == FlowState.SpoofedSYN and get_src(tcp_packet) == flow.server:
            flow.server_seq = (tcp_packet.seq - 1) % TCP_NUM
        self.translate_and_forward(event, tcp_packet)

    def handle_fin(self, event, tcp_packet: tcp):
        # same as handle_data_ack, but ignore if flow is not established
        self.translate_and_forward(event, tcp_packet)

    def translate_and_forward(self, event, tcp_packet: tcp):
        flow = self.flow_table.get(get_flow(tcp_packet))
        state = flow and flow.get_state()
        if state != FlowState.Established:
            log.warning('Flow not established, cannot translate')
            return
        log.debug('Translate and forward')
        translate_packet(flow, tcp_packet)
        send_packet_out(event.connection, tcp_packet, event.port, self.dst_port(tcp_packet))

    def dst_port(self, tcp_packet: tcp):
        return self.mac_table.get(tcp_packet.prev.prev.dst, of.OFPP_FLOOD)

    # def forward_packet(self, event):
    #     msg = of.ofp_packet_out()
    #     msg.data = event.ofp
    #     msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
    #     event.connection.send(msg)

def launch():
    core.registerNew(SYNProxy)
