import sys
from scapy.all import *

def analyze_pcap(pcap_file):
    packets = rdpcap(pcap_file)
    packet_stats = {}

    for packet in packets:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            packet_size = len(packet)

            if src_ip not in packet_stats:
                packet_stats[src_ip] = {'sent_packets': 0, 'received_packets': 0, 'sent_bytes': 0, 'received_bytes': 0}
            packet_stats[src_ip]['sent_packets'] += 1
            packet_stats[src_ip]['sent_bytes'] += packet_size
            
            if dst_ip not in packet_stats:
                packet_stats[dst_ip] = {'sent_packets': 0, 'received_packets': 0, 'sent_bytes': 0, 'received_bytes': 0}
            packet_stats[dst_ip]['received_packets'] += 1
            packet_stats[dst_ip]['received_bytes'] += packet_size

    # Print statistics
    print("IP Address\tSent Packets\tReceived Packets\tSent Bytes\tReceived Bytes")
    print("---------------------------------------------------------------------")
    for ip, stats in packet_stats.items():
        print(f"{ip}\t{stats['sent_packets']}\t\t{stats['received_packets']}\t\t{stats['sent_bytes']}\t\t{stats['received_bytes']}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Syntax: packet-stat <pcap file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    analyze_pcap(pcap_file)
