#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>

#include "packet.h"

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
uint16_t in_cksum(char *buf, uint32_t sz)
{
	uint32_t sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < (sz - 1); i += 2) {
		sum += *(unsigned short*)&buf[i];
	}

	/* Handle odd-sized case and add left-over byte */
	if (sz & 1) {
		sum += (unsigned char)buf[i];
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	/* Invert to get the negative in ones-complement arithmetic */
	return (~sum);
}

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
		struct sockaddr_in *dst, int len)
{
	/* The pseudoheader used to calculate the checksum */
	struct pseudohdr psh;
	char *psd;
	int psd_sz;

	/* Configure the TCP-Pseudo-Header for checksum calculation */
	psh.source_addr = src->sin_addr.s_addr;
	psh.dest_addr = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + len);

	/* Paste everything into the pseudogram */
	psd_sz = sizeof(struct pseudohdr) + sizeof(struct tcphdr) + OPT_SIZE + len;
	psd = malloc(psd_sz);
	/* Copy the pseudo-header into the pseudogram */
	memcpy(psd, (char *)&psh, sizeof(struct pseudohdr));
	/* Attach the TCP-header and -content after the pseudo-header */
	memcpy(psd + sizeof(struct pseudohdr), tcp_hdr, 
			sizeof(struct tcphdr) + OPT_SIZE + len);

	/* Return the checksum of the TCP-header */
	return(in_cksum((char*)psd, psd_sz));
}

/*
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram. The function also converts the numbers to
 * the little-edian-byteorder.
 *
 * @pck: A buffer containing the datagram with the numbers
 * @seq: An address to write the seqeunce-number to
 * @ack: An address to write the acknowledgement-number to
 */
void read_seq_and_ack(char *pck, uint32_t *seq, uint32_t *ack)
{
	uint32_t seqnum, acknum;
	/* Read sequence number */
	memcpy(&seqnum, (pck + 24), 4);
	/* Read acknowledgement number */
	memcpy(&acknum, (pck + 28), 4);
	/* Convert network to host byte order */
	*seq = ntohl(seqnum);
	*ack = ntohl(acknum);
}

/*
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram and then returned the updated numbers.
 *
 * @pck: A buffer containing the datagram with the numbers
 * @seq: An address to write the updated seqeunce-number to
 * @ack: An address to write the updated acknowledgement-number to
 */
void update_seq_and_ack(char *pck, uint32_t *seq, uint32_t *ack)
{
	uint32_t seqnum, acknum;
	/* Read sequence number */
	memcpy(&seqnum, (pck + 24), 4);
	/* Read acknowledgement number */
	memcpy(&acknum, (pck + 28), 4);
	/* Convert network to host byte order */
	*seq = ntohl(acknum);
	*ack = ntohl(seqnum);
	*ack = *ack + 1;
}

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
	int acknum, char *pld, int pldlen) 
{
	/* Copy the seq- and ack-numbers into the buffer */
	memcpy(databuf, &seqnum, 4);
	memcpy(databuf + 4, &acknum, 4);
	*datalen = 8;

	if(pld != NULL) {
		/* Copy the pld into the data-buffer */
		memcpy(databuf + 8, pld, pldlen);
		/* Adjust the buffer-length */
		*datalen += pldlen;
	}
}

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
void setup_tcp_hdr(struct tcphdr *tcp_hdr, int iSrcPort, int iDestPort) 
{
	/* Configure the TCP-header */
	tcp_hdr->source = iSrcPort;
	tcp_hdr->dest = iDestPort;
	tcp_hdr->seq = htonl(rand() % 0xffffffff);
	tcp_hdr->ack_seq = htonl(0);
	tcp_hdr->doff = 10;
	/* Set the TCP-Header-Flags */
	tcp_hdr->urg = 0;
	tcp_hdr->ack = 0;
	tcp_hdr->psh = 0;
	tcp_hdr->rst = 0;
	tcp_hdr->syn = 0;
	tcp_hdr->fin = 0;
	/* Fill other values */
	tcp_hdr->window = htons(5840);
	tcp_hdr->check = 0;
	tcp_hdr->urg_ptr = 0;
}

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
uint32_t strip_tcp_hdr(struct tcphdr *tcp_hdr, char *buf, int len)
{
	if(len){/* Prevent warning for not using len*/}
	
	/* Convert the first part of the buffer into a TCP-header */
	memcpy(tcp_hdr, buf, sizeof(struct tcphdr));
	/* Return the length of the TCP-header */
	return (tcp_hdr->doff * 4);
}

/*
 * Setup a default IP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * header right, you have to adjust further settings depending on the purpose of the
 * datagram afterwards. By default the following settings are used: IPv4,
 * Header-Length of 5 words and TCP as the transmission-protocol.
 *
 * @pIPHdr: A pointer to the IP-header-structure
 * @src: The source-IP-address
 * @dst: The destination-IP-address
 *
 * Returns: The length of the IP-datagram
 */
uint32_t setup_ip_hdr(struct iphdr *ip_hdr, struct sockaddr_in *src, 
		struct sockaddr_in *dst, int len)
{
	/* Configure the IP-header */
	ip_hdr->version = 0x4;
	ip_hdr->ihl = 0x5;
	ip_hdr->tos = 0;
	ip_hdr->tot_len = sizeof(struct iphdr) + OPT_SIZE + sizeof(struct tcphdr) + len;
	printf("  Length of IP-Hdr: %d\n", ip_hdr->tot_len);
	ip_hdr->id = htonl(rand() % 65535);
	ip_hdr->frag_off = 0;
	ip_hdr->ttl = 0xff;
	ip_hdr->protocol = IPPROTO_TCP;
	ip_hdr->check = 0;
	/* Set IP-addresses for source and destination */
	ip_hdr->saddr = src->sin_addr.s_addr;
	ip_hdr->daddr = dst->sin_addr.s_addr;
	/* Return the length of the IP-header */
	return(ip_hdr->tot_len);
}

/*
 * Remove the IP-header and parse data into a given IP-header-struct. Then 
 * return the rest of the datgram. To actually read the content contained in this
 * datagram, you also have to remove the TCP-header, by calling strip_tcp_hdr().
 *
 * @iphdr: A pointer to an IP-header-struct
 * @buf: A buffer containing the receieved datagram
 * @len: The length of the buffer
 *
 * Returns: The length of the IP-header in bytes
*/
uint32_t strip_ip_hdr(struct iphdr *ip_hdr, char *buf, int len)
{
	if(len){/* Prevent warning for not using len*/}

	/* Parse the buffer into the IP-header-struct */
	memcpy(ip_hdr, buf, sizeof(struct iphdr));
	/* Return the length of the IP-header in bytes */
	return (ip_hdr->ihl * 4);
}

/**
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
		char *databuf, int len)
{
	uint32_t seq, ack;
	int poff, pldlen = 0;
	int16_t mss;

	/* Reserve empty space for storing the datagram. (memory already filled with zeros) */
	char *pld, *dgrm = calloc(DATAGRAM_LEN, sizeof(char));

	/* Required structs for the IP- and TCP-header */
	struct iphdr* iph = (struct iphdr *)(dgrm);
	struct tcphdr* tcph = (struct tcphdr *)(dgrm + sizeof(struct iphdr));

	/* If the passes data-buffer contains more than the seq- and ack-numbers */
	if(len > 8) {
		/* The length of the pld is the length of the whole buffer */
		/* without the seq- and ack-numbers. */
		pldlen = len - 8;
	}

	/* Configure the IP-header */
	setup_ip_hdr(iph, src, dst, pldlen);

	/* Configure the TCP-header */
	setup_tcp_hdr(tcph, src->sin_port, dst->sin_port);

	/* Configure the datagram, depending on the type */
	switch(type) {
		case(URG_PACKET):
			break;
		
		case(ACK_PACKET):
			/* Set packet-flags */
			tcph->ack = 1;

			/* Set seq- and ack-numbers */
			memcpy(&seq, databuf, 4);
			memcpy(&ack, databuf + 4, 4);
			tcph->seq = htonl(seq);
			tcph->ack_seq = htonl(ack);
			break;
		
		case(PSH_PACKET):
			/* Set datagram-flags */
			tcph->psh = 1;
			tcph->ack = 1;

			/* Set pld according to the preset message */
			pld = dgrm + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
			memcpy(pld, databuf + 8, len - 8);

			/* Set seq- and ack-numbers */
			memcpy(&seq, databuf, 4);
			memcpy(&ack, databuf + 4, 4);
			tcph->seq = htonl(seq);
			tcph->ack_seq = htonl(ack);
			break;
		
		case(RST_PACKET):
			break;
				
		case(SYN_PACKET):
			/* Set datagram-flags */
			tcph->syn = 1;

			poff = sizeof(struct ethhdr);

			/* TCP options are only set in the SYN packet */
			/* Set the Maximum Segment Size(MMS) */
			dgrm[poff + 40] = 0x02;
			dgrm[poff + 41] = 0x04;
			mss = htons(48);
			memcpy(dgrm + poff + 42, &mss, sizeof(int16_t));
			/* Enable SACK */
			dgrm[poff + 44] = 0x04;
			dgrm[poff + 45] = 0x02;
			break;

		case(FIN_PACKET):
			/* Set the datagram-flags */
			tcph->ack = 1;
			tcph->fin = 1;

			/* Set seq- and ack-numbers */
			memcpy(&seq, databuf, 4);
			memcpy(&ack, databuf + 4, 4);
			tcph->seq = htonl(seq);
			tcph->ack_seq = htonl(ack);
			break;
	}

	/* Calculate the checksum for both the IP- and TCP-header */
	tcph->check = in_cksum_tcp(tcph, src, dst, pldlen);
	iph->check = in_cksum((char*)dgrm, iph->tot_len);

	/* Convert the length of IP-header to big endian. */
	/* iph->tot_len = htons(iph->tot_len); */

	/* Return the created datagram */
	memcpy(pck, dgrm, DATAGRAM_LEN);
	*pcklen = iph->tot_len;
}

/**
 * 
 */
void strip_raw_packet(char *pck, int pcklen,
		struct iphdr *ip_hdr, struct tcphdr *tcp_hdr, char *pld, int *pldlen)
{
	short ip_hdr_len;
	int tcp_hdr_len;

	/* Remove the IP-header, and write it to the header-struct */
	ip_hdr_len = strip_ip_hdr(ip_hdr, (pck), (pcklen));

	if(tcp_hdr != NULL) {
		/* Remove the TCP-header, and write it to the header-struct */
		tcp_hdr_len = strip_tcp_hdr(tcp_hdr, (pck + ip_hdr_len), 
				(pcklen - ip_hdr_len));
		
		if(pld != NULL) {
			/* Get the length of the pld contained in the datagram */
			*pldlen = (pcklen - ip_hdr_len - tcp_hdr_len);
	
			/* Copy the pld into the according buffer */
			memcpy(pld, pck + ip_hdr_len + tcp_hdr_len, *pldlen);
		}
	}	
}
