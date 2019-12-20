#ifndef _PACKET_H_
#define _PACKET_H_

#define DATAGRAM_LEN 4096
#define OPT_SIZE 20

#define URG_PACKET 0
#define ACK_PACKET 1
#define PSH_PACKET 2
#define RST_PACKET 3
#define SYN_PACKET 4
#define FIN_PACKET 5

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

/*
 * Pseudo header needed for TCP-header-checksum-calculation.
 * See: http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-2.htm
 */
struct pseudohdr {
	u_int32_t source_addr;
	u_int32_t dest_addr;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

uint16_t in_cksum(char *buf, uint32_t sz);
uint16_t in_cksum_tcp(struct tcphdr *tcp_hdr, struct sockaddr_in *src, 
		struct sockaddr_in *dst, int len);
void read_seq_and_ack(char *pck, uint32_t *seq, uint32_t *ack);
void update_seq_and_ack(char* pck, uint32_t *seq, uint32_t *ack);
void gather_packet_data(char *databuf, int *datalen, int seqnum, 
	int acknum, char *pld, int pldlen);

void setup_tcp_hdr(struct tcphdr *tcp_hdr, int iSrcPort, int iDestPort);
uint32_t strip_tcp_hdr(struct tcphdr *tcp_hdr, char *buf, int len);
uint32_t setup_ip_hdr(struct iphdr *ip_hdr, struct sockaddr_in *src, 
		struct sockaddr_in *dst, int len);
uint32_t strip_ip_hdr(struct iphdr *ip_hdr, char *buf, int len);

void create_raw_datagram(char *pck, int *pcklen, int type,
		struct sockaddr_in *src, struct sockaddr_in *dst, 
		char* databuf, int len);
void strip_raw_packet(char *pck, int pcklen,
		struct iphdr *ip_hdr, struct tcphdr* tcp_hdr, char* pld, int* pldlen);

#endif
