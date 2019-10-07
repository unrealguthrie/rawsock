// ==== INCLUDES ====
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "packet.h"

/**
 * Calculate the checksum for an IP-header and pseudoheader. The code here
 * is recoded using https://tools.ietf.org/html/rfc1071#section-4 as
 * a direct reference.
 *
 * @returns {unsigned short} The calculated checksum
 *
 * @param {const char*} pBuf_ - The buffer to calculate the checksum with
 * @param {unsigned} uSize_ - The size of the buffer
 */
unsigned short in_cksum(char* pBuf_, unsigned uSize_) {
	unsigned iSum = 0, iIt;

	// Accumulate checksum.
	for (iIt = 0; iIt < (uSize_ - 1); iIt += 2) {
		iSum += *(unsigned short*)&pBuf_[iIt];
	}

	// Handle odd-sized case and add left-over byte.
	if (uSize_ & 1) {
		iSum += (unsigned char)pBuf_[iIt];
	}

	// Fold to get the ones-complement result.
	while (iSum >> 16) {
		iSum = (iSum & 0xffff) + (iSum >> 16);
	}

	// Invert to get the negative in ones-complement arithmetic.
	return (~iSum);
} // in_cksum

/**
 * Calculate the checksum for the TCP-header.
 *
 * @returns {unsigned short} The calculated checksum
 *
 * @param {struct tcphdr*} pTCPHdr_ - A pointer to the TCP-header
 * @param {struct sockaddr_in*} pSrc_ - A pointer to the source-IP-address
 * @param {struct sockaddr_in*} pDst_ - A pointer to the destination-IP-address
 * @param {int} iDataLen_ - The length of the data without headers
 */
unsigned short in_cksum_tcp(struct tcphdr* pTCPHdr_, struct sockaddr_in* pSrc_, 
		struct sockaddr_in* pDst_, int iDataLen_) {
	// The pseudoheader used to calculate the checksum.
	struct pseudohdr oPsh;
	char* pPseudogram;
	int iSize;

	// Configure the TCP-Pseudo-Header for checksum calculation.
	oPsh.source_addr = pSrc_->sin_addr.s_addr;                        								// Set the Source-Address
	oPsh.dest_addr = pDst_->sin_addr.s_addr;                          								// Set the Destination-Address
	oPsh.placeholder = 0;																			// Use 0 as a placeholder
	oPsh.protocol = IPPROTO_TCP;                                         							// Specific the used protocol
	oPsh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + iDataLen_);							// The length of the TCP-header

	// Paste everything into the pseudogram.
	iSize = sizeof(struct pseudohdr) + sizeof(struct tcphdr) + OPT_SIZE + iDataLen_;
	pPseudogram = malloc(iSize);
	// Copy the pseudo-header into the pseudogram.
	memcpy(pPseudogram, (char*)&oPsh, sizeof(struct pseudohdr));
	// Attach the TCP-header and -content after the pseudo-header.
	memcpy(pPseudogram + sizeof(struct pseudohdr), pTCPHdr_, 
			sizeof(struct tcphdr) + OPT_SIZE + iDataLen_);

	// Return the checksum of the TCP-header.
	return (in_cksum((char*)pPseudogram, iSize));
} // in_cksum_tcp

/**
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram. These numbers are already converted to little-edian
 * when returned by the function.
 *
 * @param {char*} pPacket_ - A buffer containing the datagram
 * @param {int*} pSeq_ - An address to write the seq-number to
 * @param {int*} pAck_ - An address to write the ack-number to
 */
void read_seq_and_ack(char* pPacket_, uint32_t* pSeq_, uint32_t* pAck_) {
	uint32_t iSeqNum, iAckNum;
	// Read sequence number.
	memcpy(&iSeqNum, (pPacket_ + 24), 4);
	// Read acknowledgement number.
	memcpy(&iAckNum, (pPacket_ + 28), 4);
	// Convert network to host byte order.
	*pSeq_ = ntohl(iSeqNum);
	*pAck_ = ntohl(iAckNum);
}  // read_seq_and_ack

/**
 * Setup a default IP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * packet right, you have to adjust further settings depending on the purpose of the
 * packet afterwards.
 *
 * @returns {unsigned int} The length of the IP-datagram
 *
 * @param {struct iphdr*} pIPHdr_ - A pointer to the IP-header-structure
 * @param {struct sockaddr_in*} pSrc_ - The source-IP-address
 * @param {struct sockaddr_in*} pDst_ - The destination-IP-address
 */
unsigned int setup_ip_hdr(struct iphdr* pIPHdr_, struct sockaddr_in* pSrc_, 
		struct sockaddr_in* pDst_, int iDataLen_) {
	// Configure the IP-header.
	pIPHdr_->version = 0x4;                                                 						// Set the IP-version (IPv4)
	pIPHdr_->ihl = 0x5;                                                     						// Internet-Header-Length
	pIPHdr_->tos = 0;                                                       						// Type-Of-Service
	pIPHdr_->tot_len = sizeof(struct iphdr) + OPT_SIZE + sizeof(struct tcphdr) + iDataLen_;    		// Total-Length of the IP-datagram
	pIPHdr_->id = htonl(rand() % 65535);                                    						// Identification of datagram (set random)
	pIPHdr_->frag_off = 0;                                                  						// Fragment-Offset
	pIPHdr_->ttl = 0xff;                                                      						// Time-To-Live
	pIPHdr_->protocol = IPPROTO_TCP;                                        						// Protocol used in Transport-Layer
	pIPHdr_->check = 0;                                                     						// The IP-Header-Checksum (calculated later)
	// Set IP-addresses for source and destination.
	pIPHdr_->saddr = pSrc_->sin_addr.s_addr;                                						// The Source-IP-Address
	pIPHdr_->daddr = pDst_->sin_addr.s_addr;                                						// The Destination-IP-Address
	// Return the length of the IP-header.
	return(pIPHdr_->tot_len);
} // setup_ip_hdr

/**
 * Remove the IP-header and parse data into a given IP-header-struct. Then 
 * return the rest of the datgram. To actually read the content contained in this
 * datagram, you also have to remove the TCP-header, by calling strip_tcp_hdr().
 *
 * @param {struct iphdr*} pIPHdr_ - A pointer to an IP-header-struct
 * @param {char*} pDatagramBuf_ - A buffer containing the receieved datagram
 * @param {int} pDatagramLen_- The length of the buffer
*/
unsigned int strip_ip_hdr(struct iphdr* pIPHdr_, char* pDatagramBuf_, int pDatagramLen_) {
	// Parse the buffer into the IP-header-struct.
	memcpy(pIPHdr_, pDatagramBuf_, sizeof(struct iphdr));
	// Return the length of the IP-header in bytes.
	return (pIPHdr_->ihl * 4);
} // strip_ip_hdr

/**
 * Setup a default TCP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * packet right, you have to set flags afterwards, depending on the purpose of
 * the packet. For example: To create a SYN-packet, you would have to activate 
 * the syn-flag.
 *
 * @param {struct tcphdr*} pTCPHdr_ - A pointer to the TCP-header-structure
 * @param {int} iSrcPort_ - The source-port
 * @param {int} iDestPort_ - The destination-port
 */
void setup_tcp_hdr(struct tcphdr* pTCPHdr_, int iSrcPort, int iDestPort) {
	// Configure the TCP-header.
	pTCPHdr_->source = iSrcPort;                                     								// The Source-Port
	pTCPHdr_->dest = iDestPort;                                       								// The Destination-Port
	pTCPHdr_->seq = htonl(rand() % 4294967295);														// The Sequence-Number 	
	pTCPHdr_->ack_seq = htonl(0);																	// Acknowledgement-Number
	pTCPHdr_->doff = 10;  																			// The TCP-Header-Size in words
	// Set the TCP-Header-Flags.
	pTCPHdr_->urg = 0;																				// Urgent-Pointer-Valid flag
	pTCPHdr_->ack = 0;																				// Acknowledgment-Number-Valid flag
	pTCPHdr_->psh = 0;																				// Push flag
	pTCPHdr_->rst = 0;																				// Reset-Connection flag
	pTCPHdr_->syn = 0;																				// Synchronize-Sequence-Numbers flag
	pTCPHdr_->fin = 0;																				// End-Of-Data flag
	// Configure the TCP-header further.
	pTCPHdr_->window = htons(5840);                                        							// The Window-Size
	pTCPHdr_->check = 0;																			// The TCP-Header-Checksum (calculated later)
	pTCPHdr_->urg_ptr = 0;																			// The pointer to the urgent data
} // setup_tcp_hdr

/**
 * Extract the TCP-header from the datagram. Note, all previous headers, have to
 * be removed already, as the function marks the beginning of the passed
 * datagram as the beginning of the TCP-header. It then parses the raw bytes
 * into the header-struct and return the data contained in this datagram,
 * if there is any.
 *
 * @returns {unsigned int} The length of the TCP-header
 *
 * @param {struct tcphdr*} pTCPHdr_ - A pointer to the strut, used to parsethe header into
 * @param {char*} pDatagramBuf_ - The buffer to extract the header from
 * @param {int} pDatagramLen_ - The length of the datagram-buffer
*/ 
unsigned int strip_tcp_hdr(struct tcphdr* pTCPHdr_, char* pDatagramBuf_, 
		int pDatagramLen_) {
	// Convert the first part of the buffer into a TCP-header.
	memcpy(pTCPHdr_, pDatagramBuf_, sizeof(struct tcphdr));
	// Return the length of the TCP-header.
	return (pTCPHdr_->doff * 4);
} // strip_tcp_hdr

/**
 * Define a raw packet used to transfer data to a server.
 *
 * @param {char**} pOutPacket_ - A pointer to memory to store packet
 * @param {int*} pOutPacketLen_ - Length of the packet in bytes
 * @param {int} iType_ - The type of packet
 * @param {struct sockaddr_in*} pSrc_ - The source-IP-address
 * @param {struct sockaddr_in*} pDst_ - The destination-IP-address
*/
void create_raw_packet(char** pOutPacket_, int* pOutPacketLen_, int iType_,
		struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_, 
		char* pData_, int iDataLen_) {
	uint32_t iSeq, iAck;
	int iPayloadLen = 0;
	
	if(iDataLen_ > 8) {
		iPayloadLen = iDataLen_ - 8;
	}

	// Reserve empty space for storing the datagram (memory already filled with zeros)
	char* datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Required structs for IP and TCP header.
	struct iphdr* iph = (struct iphdr*)datagram;
	struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));

	// Configure the IP-header.
	setup_ip_hdr(iph, pSrc_, pDst_, iPayloadLen);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);

	switch(iType_) {
		case(URG_PACKET):
			break;
		
		
		case(ACK_PACKET):
			// Set packet-flags.
			tcph->ack = 1;

			memcpy(&iSeq, pData_, 4);
			memcpy(&iAck, pData_ + 4, 4);

			// Set seq- and ack-numbers.
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
		
		
		case(PSH_PACKET):
			// Set packet-flags.
			tcph->psh = 1;
			tcph->ack = 1;

			// Set payload according to the preset message.
			char* payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
			memcpy(payload, pData_ + 8, iDataLen_ - 8);

			memcpy(&iSeq, pData_, 4);
			memcpy(&iAck, pData_ + 4, 4);

			// Set seq- and ack-numbers.
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
		
		
		case(RST_PACKET):
			break;
		
		
		case(SYN_PACKET):
			// Set packet-flags.
			tcph->syn = 1;

			// TCP options are only set in the SYN packet.
			// Set the Maximum Segment Size(MMS).
			datagram[40] = 0x02;
			datagram[41] = 0x04;
			int16_t mss = htons(48);
			memcpy(datagram + 42, &mss, sizeof(int16_t));
			// Enable SACK.
			datagram[44] = 0x04;
			datagram[45] = 0x02;
			break;


		case(FIN_PACKET):
			// Set the packet-flags.
			tcph->ack = 1;
			tcph->fin = 1;

			memcpy(&iSeq, pData_, 4);
			memcpy(&iAck, pData_ + 4, 4);

			// Set seq- and ack-numbers.
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
	}

	// Calculate the checksum for both the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, iPayloadLen);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;
}  // create_raw_packet

