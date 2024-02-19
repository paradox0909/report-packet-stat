#include <iostream>
#include <unordered_map>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void process_packet(const u_char* packet, int size, std::unordered_map<std::string, int>& sent_packets,
                    std::unordered_map<std::string, int>& received_packets,
                    std::unordered_map<std::string, int>& sent_bytes,
                    std::unordered_map<std::string, int>& received_bytes,
                    std::unordered_map<std::string, int>& eth_endpoints,
                    std::unordered_map<std::string, int>& tcp_endpoints,
                    std::unordered_map<std::string, int>& udp_endpoints) {
    struct iphdr* ip_header = (struct iphdr*)(packet + sizeof(struct ether_header));

    // Extract source and destination IP addresses
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(ip_header->saddr), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->daddr), dst_ip, INET_ADDRSTRLEN);

    // Count sent packets and bytes
    std::string src_ip_str(src_ip);
    sent_packets[src_ip_str]++;
    sent_bytes[src_ip_str] += size;

    // Count received packets and bytes
    std::string dst_ip_str(dst_ip);
    received_packets[dst_ip_str]++;
    received_bytes[dst_ip_str] += size;

    // Count Ethernet, TCP, UDP endpoints
    struct ether_header* eth_header = (struct ether_header*)packet;
    eth_endpoints[ether_ntoa((struct ether_addr*)eth_header->ether_shost)]++;
    eth_endpoints[ether_ntoa((struct ether_addr*)eth_header->ether_dhost)]++;
    if (ip_header->protocol == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        std::string src_port = std::to_string(ntohs(tcp_header->source));
        std::string dst_port = std::to_string(ntohs(tcp_header->dest));
        tcp_endpoints[src_ip_str + ":" + src_port]++;
        tcp_endpoints[dst_ip_str + ":" + dst_port]++;
    } else if (ip_header->protocol == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
        std::string src_port = std::to_string(ntohs(udp_header->source));
        std::string dst_port = std::to_string(ntohs(udp_header->dest));
        udp_endpoints[src_ip_str + ":" + src_port]++;
        udp_endpoints[dst_ip_str + ":" + dst_port]++;
    }
}

void print_stats(const std::unordered_map<std::string, int>& packets,
                 const std::unordered_map<std::string, int>& bytes,
                 const std::string& label) {
    std::cout << label << " IP\tPackets\tBytes" << std::endl;
    for (const auto& entry : packets) {
        std::cout << entry.first << "\t" << entry.second << "\t" << bytes.at(entry.first) << std::endl;
    }
    std::cout << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Syntax: " << argv[0] << " <pcap file>" << std::endl;
        return 1;
    }

    const char* pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap = pcap_open_offline(pcap_file, errbuf);
    if (pcap == nullptr) {
        std::cerr << "Error opening pcap file: " << errbuf << std::endl;
        return 1;
    }

    std::unordered_map<std::string, int> sent_packets;
    std::unordered_map<std::string, int> received_packets;
    std::unordered_map<std::string, int> sent_bytes;
    std::unordered_map<std::string, int> received_bytes;
    std::unordered_map<std::string, int> eth_endpoints;
    std::unordered_map<std::string, int> tcp_endpoints;
    std::unordered_map<std::string, int> udp_endpoints;

    struct pcap_pkthdr header;
    const u_char* packet;
    while ((packet = pcap_next(pcap, &header)) != nullptr) {
        process_packet(packet, header.len, sent_packets, received_packets, sent_bytes, received_bytes, eth_endpoints, tcp_endpoints, udp_endpoints);
    }

    print_stats(sent_packets, sent_bytes, "Sent");
    print_stats(received_packets, received_bytes, "Received");
    print_stats(eth_endpoints, eth_endpoints, "Ethernet Endpoints");
    print_stats(tcp_endpoints, tcp_endpoints, "TCP Endpoints");
    print_stats(udp_endpoints, udp_endpoints, "UDP Endpoints");

    pcap_close(pcap);
    return 0;
}