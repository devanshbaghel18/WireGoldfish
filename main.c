#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <time.h>

// Port scan detection
#define MAX_IPS 256
#define SCAN_THRESHOLD 15
#define TIME_WINDOW 10

typedef struct {
    char ip[16];
    int ports[1024];
    int port_count;
    time_t first_seen;
    int alerted;
} IPTracker;

IPTracker trackers[MAX_IPS];
int tracker_count = 0;

// SYN Flood detection
typedef struct {
    char ip[16];
    int syn_count;
    int ack_count;
    time_t first_seen;
    int alerted;
} SYNTracker;

SYNTracker syn_trackers[MAX_IPS];
int syn_tracker_count = 0;

void check_port_scan(char *src_ip, int dst_port) {
    time_t now = time(NULL);

    // Find existing tracker for this IP
    IPTracker *tracker = NULL;
    for (int i = 0; i < tracker_count; i++) {
        if (strcmp(trackers[i].ip, src_ip) == 0) {
            tracker = &trackers[i];
            break;
        }
    }

    // New IP — create tracker
    if (tracker == NULL && tracker_count < MAX_IPS) {
        tracker = &trackers[tracker_count++];
        strcpy(tracker->ip, src_ip);
        tracker->port_count = 0;
        tracker->first_seen = now;
        tracker->alerted = 0;
    }

    if (tracker == NULL) return;

    // Reset if time window expired
    if (now - tracker->first_seen > TIME_WINDOW) {
        tracker->port_count = 0;
        tracker->first_seen = now;
        tracker->alerted = 0;
    }

    // Check if port already seen
    for (int i = 0; i < tracker->port_count; i++) {
        if (tracker->ports[i] == dst_port) return;
    }

    // Add new port
    if (tracker->port_count < 1024) {
        tracker->ports[tracker->port_count++] = dst_port;
    }

    // ALERT if threshold exceeded
    if (!tracker->alerted && tracker->port_count > SCAN_THRESHOLD) {
        tracker->alerted = 1;
        printf("\n⚠️  PORT SCAN DETECTED!\n");
        printf("    Source IP: %s\n", src_ip);
        printf("    Ports hit: %d in %d seconds\n\n",
               tracker->port_count, TIME_WINDOW);
    }
}

void check_syn_flood(char *src_ip, int syn, int ack) {
    time_t now = time(NULL);

    // Find existing tracker
    SYNTracker *tracker = NULL;
    for (int i = 0; i < syn_tracker_count; i++) {
        if (strcmp(syn_trackers[i].ip, src_ip) == 0) {
            tracker = &syn_trackers[i];
            break;
        }
    }

    // New IP — create tracker
    if (tracker == NULL && syn_tracker_count < MAX_IPS) {
        tracker = &syn_trackers[syn_tracker_count++];
        strcpy(tracker->ip, src_ip);
        tracker->syn_count = 0;
        tracker->ack_count = 0;
        tracker->first_seen = now;
        tracker->alerted = 0;
    }

    if (tracker == NULL) return;

    // Reset if time window expired
    if (now - tracker->first_seen > TIME_WINDOW) {
        tracker->syn_count = 0;
        tracker->ack_count = 0;
        tracker->first_seen = now;
        tracker->alerted = 0;
    }

    // Count SYNs and ACKs
    if (syn && !ack) tracker->syn_count++;
    if (ack)         tracker->ack_count++;

    // ALERT if SYNs >> ACKs
    if (!tracker->alerted &&
        tracker->syn_count > 10 &&
        tracker->syn_count > tracker->ack_count * 3) {
        tracker->alerted = 1;
        printf("\n⚠️  SYN FLOOD DETECTED!\n");
        printf("    Source IP: %s\n", src_ip);
        printf("    SYNs: %d  ACKs: %d\n\n",
            tracker->syn_count, tracker->ack_count);
    }
}

int main()
{
    // Create raw socket
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    unsigned char buffer[65536];

    while (1)
    {
        ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (len < 0)
        {
            perror("recvfrom");
            break;
        }

        // Parse Ethernet header
        struct ethhdr *eth = (struct ethhdr *)buffer;
        printf("Ethernet Frame:\n");
        printf("  Src: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_source[0], eth->h_source[1], eth->h_source[2],
               eth->h_source[3], eth->h_source[4], eth->h_source[5]);
        printf("  Dst: %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
               eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
        printf("  Protocol: %d\n\n", ntohs(eth->h_proto));

        if (ntohs(eth->h_proto) == 0x0800)
        { // IPv4
            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
            inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

            printf("  IPv4:\n");
            printf("    Src IP: %s\n", src_ip);
            printf("    Dst IP: %s\n", dst_ip);
            printf("    Protocol: %d\n", ip->protocol);
            printf("    TTL: %d\n\n", ip->ttl);

            // TCP
            if (ip->protocol == 6)
            {
                struct tcphdr *tcp = (struct tcphdr *)(buffer +
                                                       sizeof(struct ethhdr) + ip->ihl * 4);
                printf("    TCP:\n");
                printf("      Src Port: %d\n", ntohs(tcp->source));
                printf("      Dst Port: %d\n", ntohs(tcp->dest));
                printf("      SYN: %d ACK: %d FIN: %d\n",
                       tcp->syn, tcp->ack, tcp->fin);

                check_port_scan(src_ip, ntohs(tcp->dest));
                check_syn_flood(src_ip, tcp->syn, tcp->ack);
            }

            // UDP
            if (ip->protocol == 17)
            {
                struct udphdr *udp = (struct udphdr *)(buffer +
                                                       sizeof(struct ethhdr) + ip->ihl * 4);
                printf("    UDP:\n");
                printf("      Src Port: %d\n", ntohs(udp->source));
                printf("      Dst Port: %d\n", ntohs(udp->dest));
            }
        }
    }

    close(sock);
    return 0;
}