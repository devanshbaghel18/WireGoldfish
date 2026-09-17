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
        int len = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
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

            struct in_addr src, dst;
            src.s_addr = ip->saddr;
            dst.s_addr = ip->daddr;

            printf("  IPv4:\n");
            printf("    Src IP: %s\n", inet_ntoa(src));
            printf("    Dst IP: %s\n", inet_ntoa(dst));
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
