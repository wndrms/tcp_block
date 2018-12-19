#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>

void dump(u_char* p, int len){
	for(int i=0; i<len; i++){
		printf("%02x ", *p);
		p++;
		if(i%16==15) printf("\n");
	}
	printf("\n");
}
u_short checksum(u_short *base, int len){
  int nleft = len;
  int sum = 0;
  u_short *w = base;
  u_short answer = 0; 
 
  while(nleft>1){
    sum += *w;
    w++;
    nleft -= 2;
  }
 
  if(nleft == 1){
    *(u_short *)(&answer) = *(u_char *)w;
    sum += answer;
  }
  sum = (sum>>16) + (sum & 0xFFFF);
  sum += (sum >>16);
  answer = ~sum;
  return (answer);
}
struct tmp_tcp_header{
    unsigned int ip_src;
    unsigned int ip_dst;
    unsigned char zero;
    unsigned char protocol;
    unsigned short tcp_len;
    struct tcphdr tcp_hdr;
    unsigned char tcp_data[100];
};
int analysis(const u_char *p){
	struct ether_header *e_header;
	int ether_type;
	
	e_header = (struct ether_header *)p;
	p += sizeof(struct ether_header);
	ether_type = ntohs(e_header->ether_type);
	
	if(ether_type == ETHERTYPE_IP){
		struct ip *ip_header = (struct ip *)p;
        if(ip_header -> ip_p == IPPROTO_TCP){
        	struct tcphdr *tcp_header = (struct tcphdr *)(p + ip_header->ip_hl * 4);
        	if(ntohs(tcp_header->th_dport) == 80) return 2;
        	else return 1;
		}
	}
	return -1;
}
void send_rst(pcap_t *handle, u_char *p, uint32_t len, u_char *eth_dhost, u_char *eth_shost, u_char *ip_src_adr, u_char *ip_dst_adr, uint16_t tcp_src_port, uint16_t tcp_dst_port, uint32_t tcp_seq, uint32_t tcp_ack, int syn, int ack){
    memset(p, 0, len);

    struct ether_header *e_header = (struct ether_header *)p;
    memcpy(e_header->ether_dhost, eth_dhost, 6);
    memcpy(e_header->ether_shost, eth_shost, 6);
    e_header->ether_type = htons(ETHERTYPE_IP);

    struct ip *ip_header = (struct ip *)(p + sizeof(struct ether_header));
    memcpy(&(ip_header->ip_src), ip_src_adr, sizeof(struct in_addr));
    memcpy(&(ip_header->ip_dst), ip_dst_adr, sizeof(struct in_addr));
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_sum = checksum((unsigned short *)ip_header, sizeof(struct ip));
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 144;
    ip_header->ip_p = IPPROTO_TCP;

	struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
    memset(tcp_header, 0, sizeof(struct tcphdr));
    tcp_header->th_sport = htons(tcp_src_port);
    tcp_header->th_dport = htons(tcp_dst_port);
    tcp_header->th_seq = htonl(tcp_seq);
    tcp_header->th_ack = htonl(tcp_ack);
    tcp_header->th_off = 5;
    tcp_header->th_flags |= TH_RST;    
	tcp_header->th_flags |= TH_SYN * syn;
	tcp_header->th_flags |= TH_ACK * ack;
    
    struct tmp_tcp_header tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(struct tmp_tcp_header));
    tmp_hdr.ip_src = *(uint32_t *)ip_src_adr;
    tmp_hdr.ip_dst = *(uint32_t *)ip_dst_adr;
    tmp_hdr.protocol = 6;
    tmp_hdr.tcp_len = htons(20);
    tmp_hdr.tcp_hdr = *(tcp_header);

    tcp_header->th_sum = checksum((unsigned short *)&tmp_hdr, sizeof(tmp_tcp_header));
    pcap_sendpacket(handle, p, (u_char *)tcp_header - p + tcp_header->th_off * 4);
}
void send_fin(pcap_t *handle, u_char *p, uint32_t len, u_char *eth_dhost, u_char *eth_shost, u_char *ip_src_adr, u_char *ip_dst_adr, uint16_t tcp_src_port, uint16_t tcp_dst_port, uint32_t tcp_seq, uint32_t tcp_ack, int syn, int ack){
    memset(p, 0, len);

    struct ether_header *e_header = (struct ether_header *)p;
    memcpy(e_header->ether_dhost, eth_dhost, 6);
    memcpy(e_header->ether_shost, eth_shost, 6);
    e_header->ether_type = htons(ETHERTYPE_IP);

    struct ip *ip_header = (struct ip *)(p + sizeof(struct ether_header));
    memcpy(&(ip_header->ip_src), ip_src_adr, sizeof(struct in_addr));
    memcpy(&(ip_header->ip_dst), ip_dst_adr, sizeof(struct in_addr));
    ip_header->ip_len = htons(sizeof(struct ip) + sizeof(struct tcphdr));
    ip_header->ip_sum = checksum((unsigned short *)ip_header, sizeof(struct ip));
    ip_header->ip_hl = 5;
    ip_header->ip_v = 4;
    ip_header->ip_tos = 0;
    ip_header->ip_id = 0;
    ip_header->ip_off = 0;
    ip_header->ip_ttl = 144;
    ip_header->ip_p = IPPROTO_TCP;

	struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
    memset(tcp_header, 0, sizeof(struct tcphdr));
    tcp_header->th_sport = htons(tcp_src_port);
    tcp_header->th_dport = htons(tcp_dst_port);
    tcp_header->th_seq = htonl(tcp_seq);
    tcp_header->th_ack = htonl(tcp_ack);
    tcp_header->th_off = 5;
    tcp_header->th_flags |= TH_FIN;   
	tcp_header->th_flags |= TH_PUSH;    
	tcp_header->th_flags |= TH_SYN * syn;   
	tcp_header->th_flags |= TH_ACK * ack;
	u_char tcp_redirect_data[61] = {
	    0x48, 0x54, 0x54, 0x50, 0x2f, 
	    0x31, 0x2e, 0x31, 0x20, 0x33,
	    0x30, 0x32, 0x20, 0x52, 0x65,
	    0x64, 0x69, 0x72, 0x65, 0x63,
	    0x74, 0x0d, 0x0a, 0x4c, 0x6f,
	    0x63, 0x61, 0x74, 0x69, 0x6f,
	    0x6e, 0x3a, 0x20, 0x68, 0x74,
	    0x74, 0x70, 0x3a, 0x2f, 0x2f,
	    0x77, 0x77, 0x77, 0x2e, 0x77,
	    0x61, 0x72, 0x6e, 0x69, 0x6e,
	    0x67, 0x2e, 0x6f, 0x72, 0x2e,
	    0x6b, 0x72, 0x0d, 0x0a, 0x0d,
	    0x0a
	};
    memcpy(tcp_header + 1, tcp_redirect_data, sizeof(tcp_redirect_data));

	struct tmp_tcp_header tmp_hdr;
    memset(&tmp_hdr, 0, sizeof(struct tmp_tcp_header));
    tmp_hdr.ip_src = *(uint32_t *)ip_src_adr;
    tmp_hdr.ip_dst = *(uint32_t *)ip_dst_adr;
    tmp_hdr.protocol = 6;
    tmp_hdr.tcp_len = htons(20 + sizeof(tcp_redirect_data));
    tmp_hdr.tcp_hdr = *(tcp_header);
    memcpy(tmp_hdr.tcp_data, tcp_redirect_data, sizeof(tcp_redirect_data));
    tcp_header->th_sum = checksum((unsigned short *)&tmp_hdr, sizeof(tmp_tcp_header));

    pcap_sendpacket(handle, p, (u_char *)tcp_header - p + tcp_header->th_off * 4 + sizeof(tcp_redirect_data));
}

int main(int argc, char* argv[]) {
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
	
	while (true) {
		printf("\n");
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);
		dump((u_char*)packet, header->caplen);
		
		int check = analysis((u_char*)packet);
		if(check == -1) continue;
		struct ether_header *e_header = (struct ether_header *)packet;
        u_char *eth_dhost = e_header->ether_dhost;
        u_char *eth_shost = e_header->ether_shost;
        
        struct ip *ip_header = (struct ip *)(packet + sizeof(struct ether_header));
        u_char *ip_src_adr = (u_char *)(&(ip_header->ip_src));
        u_char *ip_dst_adr = (u_char *)(&(ip_header->ip_dst));
        
        
		struct tcphdr *tcp_header = (struct tcphdr *)((u_char *)ip_header + ip_header->ip_hl * 4);
        uint16_t tcp_src_port = ntohs(tcp_header->th_sport);
        uint16_t tcp_dst_port = ntohs(tcp_header->th_dport);
        
        uint32_t tcp_seq = ntohl(tcp_header->th_seq);
        uint32_t tcp_ack = ntohl(tcp_header->th_ack);
        
        uint32_t tcp_len = ntohs(ip_header->ip_len) - (ip_header->ip_hl) * 4 - (tcp_header->th_off) * 4;
        u_char *p = (u_char *)malloc(200);
		
		if(check == 1){
			send_rst(handle, p, 200, eth_dhost, eth_shost, ip_src_adr, ip_dst_adr, tcp_src_port, tcp_dst_port, tcp_seq + tcp_len, tcp_ack, 1, 0);
            send_rst(handle, p, 200, eth_shost, eth_dhost, ip_dst_adr, ip_src_adr, tcp_dst_port, tcp_src_port, tcp_ack, tcp_seq + tcp_len, 0, 1);
		}
		else if(check == 2){
			send_rst(handle, p, 200, eth_dhost, eth_shost, ip_src_adr, ip_dst_adr, tcp_src_port, tcp_dst_port, tcp_seq + tcp_len, tcp_ack, 1, 0); 
            send_fin(handle, p, 200, eth_shost, eth_dhost, ip_dst_adr, ip_src_adr, tcp_dst_port, tcp_src_port, tcp_ack, tcp_seq + tcp_len, 0, 1);
		}
		printf("\n");
	}
	
	pcap_close(handle);
	return 0;
}
