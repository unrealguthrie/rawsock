#ifndef _PACKET_H_
#define _PACKET_H_

// ==== DEFINES ====
#define DATAGRAM_LEN 4096																			// The size of a single Datagram
#define OPT_SIZE 20																					// The size of options in IP-header

// Set packet-types.
#define URG_PACKET 0
#define ACK_PACKET 1
#define PSH_PACKET 2
#define RST_PACKET 3
#define SYN_PACKET 4
#define FIN_PACKET 5

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

// === DEFINE PROTOTYPES ===
// Functions needed for building packets.
unsigned long crc(int n, unsigned char c[]);
unsigned short in_cksum(char*, unsigned);
unsigned short in_cksum_tcp(struct tcphdr*, struct sockaddr_in*, struct sockaddr_in*, int);
void read_seq_and_ack(char*, uint32_t*, uint32_t*);
void update_seq_and_ack(char*, uint32_t*, uint32_t*);
void gather_packet_data(char*, int*, int, int, char*, int);

// Build and deconstruct headers.
void setup_tcp_hdr(struct tcphdr*, int, int);
unsigned int strip_tcp_hdr(struct tcphdr*, char*, int);
unsigned int setup_ip_hdr(struct iphdr*, struct sockaddr_in*, struct sockaddr_in*, int);
unsigned int strip_ip_hdr(struct iphdr*, char*, int);

// Build and deconstruct packets.
void create_raw_datagram(char*, int*, int,
		struct sockaddr_in*, struct sockaddr_in*, char*, int);
void strip_raw_packet(char*, int, struct iphdr*, struct tcphdr*, char*, int*);

#endif
