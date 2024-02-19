#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>

// Structure to hold packet statistics
typedef struct {
    int sent_packets;
    int received_packets;
    long sent_bytes;
    long received_bytes;
} PacketStats;

// Function to analyze pcap file
void analyze_pcap(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    PacketStats stats[100]; // Assuming a maximum of 100 unique IP addresses
    int i;

    // Initialize stats array
    for (i = 0; i < 100; i++) {
        stats[i].sent_packets = 0;
        stats[i].received_packets = 0;
        stats[i].sent_bytes = 0;
        stats[i].received_bytes = 0;
    }

    // Open the pcap file
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        exit(1);
    }

    // Loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct ip*)(packet + 14); // Skip Ethernet header
        
        // Update statistics based on source IP address
        stats[ntohl(ip_header->ip_src.s_addr)].sent_packets++;
        stats[ntohl(ip_header->ip_src.s_addr)].sent_bytes += ntohs(ip_header->ip_len);

        // Update statistics based on destination IP address
        stats[ntohl(ip_header->ip_dst.s_addr)].received_packets++;
        stats[ntohl(ip_header->ip_dst.s_addr)].received_bytes += ntohs(ip_header->ip_len);
    }

    // Close the pcap file
    pcap_close(handle);

    // Print statistics
    printf("IP Address\tSent Packets\tReceived Packets\tSent Bytes\tReceived Bytes\n");
    printf("---------------------------------------------------------------------\n");
    for (i = 0; i < 100; i++) {
        if (stats[i].sent_packets > 0 || stats[i].received_packets > 0) {
            printf("%d.%d.%d.%d\t%d\t\t%d\t\t%ld\t\t%ld\n", (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF, 
                    stats[i].sent_packets, stats[i].received_packets, stats[i].sent_bytes, stats[i].received_bytes);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Syntax: %s <pcap file>\n", argv[0]);
        return 1;
    }

    analyze_pcap(argv[1]);

    return 0;
}
