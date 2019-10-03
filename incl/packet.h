#ifndef _PACKET_H_
#define _PACKET_H_

// ==== DEFINES ====
#define DATAGRAM_LEN 4096																			// The size of a single Datagra in bytes
#define OPT_SIZE 20																					// The size of the options in the IP-header

// ==== DEFINE STRUCTS ====
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
};  // pseudohdr

// === Define PROTOTYPES ===
unsigned short in_cksum(char*, unsigned);
unsigned short in_cksum_tcp(struct tcphdr*, struct sockaddr_in*, struct sockaddr_in*, int);
unsigned int setup_ip_hdr(struct iphdr*, struct sockaddr_in*, struct sockaddr_in*, int);
unsigned int strip_ip_hdr(struct iphdr*, char*, int);
void setup_tcp_hdr(struct tcphdr*, int, int);
void strip_tcp_hdr(struct tcphdr*, char*, int, char*, int*);

#endif
