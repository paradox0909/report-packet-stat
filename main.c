#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/in.h>

typedef struct {
    int sent_packets;
    int received_packets;
    long sent_bytes;
    long received_bytes;
} PacketStats;

void analyze_pcap(const char* filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const u_char *packet;
    struct pcap_pkthdr header;
    struct ip *ip_header;
    PacketStats *stats = malloc(sizeof(PacketStats) * 100); // Dynamic allocation for statistics
    if (!stats) {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    for (int i = 0; i < 100; i++) {
        stats[i].sent_packets = 0;
        stats[i].received_packets = 0;
        stats[i].sent_bytes = 0;
        stats[i].received_bytes = 0;
    }

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        free(stats);
        exit(1);
    }

    while ((packet = pcap_next(handle, &header)) != NULL) {
        ip_header = (struct ip*)(packet + 14);

        int src_index = ntohl(ip_header->ip_src.s_addr) % 100;
        
        stats[src_index].sent_packets++;
        stats[src_index].sent_bytes += ntohs(ip_header->ip_len);

        int dst_index = ntohl(ip_header->ip_dst.s_addr) % 100;

        stats[dst_index].received_packets++;
        stats[dst_index].received_bytes += ntohs(ip_header->ip_len);
    }

    pcap_close(handle);

    // 결과창
    printf("IP Address\tSent Packets\tReceived Packets\tSent Bytes\tReceived Bytes\n");
    printf("-----------------------------------------------------------------------------------------------\n");
    for (int i = 0; i < 100; i++) {
        if (stats[i].sent_packets > 0 || stats[i].received_packets > 0) {
            printf("%d.%d.%d.%d\t%d\t\t%d\t\t%ld\t\t%ld\n", (i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF,
                stats[i].sent_packets, stats[i].received_packets, stats[i].sent_bytes, stats[i].received_bytes);
        }
    }

    free(stats);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Syntax: %s <pcap file>\n", argv[0]);
        return 1;
    }

    analyze_pcap(argv[1]);

    return 0;
}
