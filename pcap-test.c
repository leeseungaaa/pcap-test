#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>

typedef struct EthernetHeader{
    char src_mac[6];
    char dst_mac[6];
    char type[2];
}Ether_h;

typedef struct IPHeader{
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int ihl:4;
        unsigned int version:4;
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
        unsigned int version:4;
        unsigned int ihl:4;
    #endif
    unsigned int dscp: 6;
    unsigned int ecn: 2;
    unsigned short total_length;
    unsigned short identification;
    unsigned int flags: 3;
    unsigned int fragment_offset: 13;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short header_checksum;
    unsigned char src_ip[4];
    unsigned char dst_ip[4];
} IP_h;

typedef struct TCPHeader{
    uint16_t src_port;
    uint16_t dst_port;
    char seq[4];
    char ack[4];
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        unsigned int reserved: 4;
        unsigned int offset: 4;
    #endif
    #if __BYTE_ORDER == __BIG_ENDIAN
        unsigned int offset: 4;
        unsigned int reserved: 4;
    #endif
} TCP_h;

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param  = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    while (true) {
        struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}

        Ether_h* ether_h = (Ether_h*)packet;

        printf("===================================\n");
        printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x \n", ether_h->src_mac[0] &0xff, ether_h->src_mac[1] &0xff
                ,ether_h->src_mac[2] &0xff, ether_h->src_mac[3] &0xff
                ,ether_h->src_mac[4] &0xff, ether_h->src_mac[5] &0xff);

        printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x \n", ether_h->dst_mac[0] &0xff, ether_h->dst_mac[1] &0xff
                ,ether_h->dst_mac[2] &0xff, ether_h->dst_mac[3] &0xff
                ,ether_h->dst_mac[4] &0xff, ether_h->dst_mac[5] &0xff);

        packet += 14;

        IP_h* ip_h = (IP_h*)packet;

        printf("===================================\n");
        printf("src ip: %d.%d.%d.%d \n", ip_h -> src_ip[0], ip_h -> src_ip[1], ip_h -> src_ip[2],ip_h -> src_ip[3]);
        printf("dst ip: %d.%d.%d.%d \n", ip_h -> dst_ip[0], ip_h -> dst_ip[1], ip_h -> dst_ip[2],ip_h -> dst_ip[3]);

        unsigned int ip_datagram_length = ntohs(ip_h -> total_length);
        unsigned int ip_header_length = (ip_h -> ihl)*4;

        packet += (ip_h -> ihl)*4;

        TCP_h* tcp_h = (TCP_h*)packet;

        printf("===================================\n");
        printf("src port: %d \n", ntohs(tcp_h -> src_port));
        printf("dst port: %d \n", ntohs(tcp_h -> dst_port));

        unsigned int tcp_header_length = (tcp_h -> offset)*4;

        int payload_size = (ip_datagram_length - ip_header_length - tcp_header_length);
        printf("===================================\n");
        if (payload_size > 0){
            packet += tcp_header_length;
            printf("payload: ");
            for(int i =0; i<8; i++) {
               printf("%02x ",packet[i]);
           }
        } else printf("payload: 00 00 00 00 00 00 00 00");
        printf("\n===================================\n");

        break;
    }
	pcap_close(pcap);
}
