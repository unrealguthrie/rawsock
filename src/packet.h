#ifndef _PACKET_H
#define _PACKET_H

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


/*
 * Calculate the checksum for an IP-header or pseudoheader. The code here
 * is recoded using https://tools.ietf.org/html/rfc1071#section-4 as
 * a direct reference.
 *
 * @buf: A buffer to calculate the checksum with
 * @sz: The size of the buffer in bytes
 *
 * Returns: The calculated checksum
 */
uint16_t in_cksum(char *buf, uint32_t sz);


/*
 * Calculate the checksum for the TCP-header.
 * See for more information:
 * http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-3.htm
 *
 * @tcp_hdr: A pointer to memory containing TCP-header and data
 * @src: A pointer to the source-IP-address
 * @dst: A pointer to the destination-IP-address
 * @len: The length of the data without headers
 *
 * Returns: The calculated checksum
 */
uint16_t in_cksum_tcp(struct tcphdr *tcp_hdr, struct sockaddr_in *src, 
		struct sockaddr_in *dst, int len);


/*
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram. The function also converts the numbers to
 * the little-edian-byteorder.
 *
 * @pck: A buffer containing the datagram with the numbers
 * @seq: An address to write the seqeunce-number to
 * @ack: An address to write the acknowledgement-number to
 */
void read_seq_and_ack(char *pck, uint32_t *seq, uint32_t *ack);


/*
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram and then returned the updated numbers.
 *
 * @pck: A buffer containing the datagram with the numbers
 * @seq: An address to write the updated seqeunce-number to
 * @ack: An address to write the updated acknowledgement-number to
 */
void update_seq_and_ack(char* pck, uint32_t *seq, uint32_t *ack);


/*
 * Write the necessary data to create a packet into the data-buffer. This
 * function will write the seq- and ack-number, and if given the pld
 * to the buffer.
 *
 * @databuf: The buffer to write the data to
 * @datalen: The final length of the buffer
 * @seqnum: The sequence-number
 * @acknum: The acknowledgement-number
 * @pld: The pld-buffer
 * @pldlen: The length of the pld-buffer
 */
void gather_packet_data(char *databuf, int *datalen, int seqnum, 
	int acknum, char *pld, int pldlen);


/*
 * Setup a default TCP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * header right, you have to set flags afterwards, depending on the purpose of
 * the datagram. For example: To create a SYN-packet, you would have to activate 
 * the syn-flag.
 *
 * @tcp_hdr: A pointer to the TCP-header-structure
 * @srcport: The source-port
 * @dstport: The destination-port
 */
void setup_tcp_hdr(struct tcphdr *tcp_hdr, int iSrcPort, int iDestPort);


/*
 * Extract the TCP-header from the datagram. Note, all previous headers, have to
 * be removed already, as the function marks the beginning of the passed
 * datagram as the beginning of the TCP-header. It then parses the raw bytes
 * into the header-struct and returns the length of the TCP-header as it is.
 * To get the start-position of the pld, just add the length of the header
 * to the start of the TCP-header.
 *
 * @tcp_hdr: A pointer to the strut, used to parse the header into
 * @buf: The buffer to extract the header from
 * @len: The length of the datagram-buffer
 *
 * Returns: The length of the TCP-header in bytes
 */
uint32_t strip_tcp_hdr(struct tcphdr *tcp_hdr, char *buf, int len);


/*
 * Setup a default IP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * header right, you have to adjust further settings depending on the purpose of the
 * datagram afterwards. By default the following settings are used: IPv4,
 * Header-Length of 5 words and TCP as the transmission-protocol.
 *
 * @ip_hdr: A pointer to the IP-header-structure
 * @src: The source-IP-address
 * @dst: The destination-IP-address
 * @len: The length of the text
 *
 * Returns: The length of the IP-datagram
 */
uint32_t setup_ip_hdr(struct iphdr *ip_hdr, struct sockaddr_in *src, 
		struct sockaddr_in *dst, int len);


/*
 * Remove the IP-header and parse data into a given IP-header-struct. Then 
 * return the rest of the datgram. To actually read the content contained in this
 * datagram, you also have to remove the TCP-header, by calling strip_tcp_hdr().
 *
 * @iphdr: A pointer to an IP-header-struct
 * @buf: A buffer containing the receieved datagram
 * @len: The length of the buffer
 *
 * Returns: The length of the entire package in bytes
 */
uint32_t strip_ip_hdr(struct iphdr *ip_hdr, char *buf, int len);


/*
 * Define a raw datagram used to transfer data to a server. The passed
 * buffer has to containg at least the seq- and ack-numbers of the 
 * datagram. To pass the pld, just attach it to the end of the 
 * data-buffer and adjust the size-parameter to the new buffer-size.
 *
 * @pck: A pointer to memory to store packet
 * @pcklen: Length of the datagram in bytes
 * @type: The type of packet
 * @src: The source-IP-address
 * @dst: The destination-IP-address
 * @databuf: A buffer containing data to create datagram
 * @len: The length of the buffer
 */
void create_raw_datagram(char *pck, int *pcklen, int type,
		struct sockaddr_in *src, struct sockaddr_in *dst, 
		char* databuf, int len);

/*
 * 
 */
void strip_raw_packet(char *pck, int pcklen,
		struct iphdr *ip_hdr, struct tcphdr* tcp_hdr, char* pld, int* pldlen);

#endif /* _PACKET_H */
