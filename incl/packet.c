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
#include <linux/if_ether.h>

#include "packet.h"

/**
 * Calculate the checksum for an IP-header or pseudoheader. The code here
 * is recoded using https://tools.ietf.org/html/rfc1071#section-4 as
 * a direct reference.
 *
 * @returns {unsigned short} The calculated checksum
 *
 * @param {const char*} pBuf_ - A buffer to calculate the checksum with
 * @param {unsigned} uSize_ - The size of the buffer in bytes
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
 * See for more information:
 * http://www.tcpipguide.com/free/t_TCPChecksumCalculationandtheTCPPseudoHeader-3.htm
 *
 * @returns {unsigned short} The calculated checksum
 *
 * @param {struct tcphdr*} pTCPHdr_ - A pointer to memory containing TCP-header and data
 * @param {struct sockaddr_in*} pSrc_ - A pointer to the source-IP-address
 * @param {struct sockaddr_in*} pDst_ - A pointer to the destination-IP-address
 * @param {int} iDataLen_ - The length of the data without headers
 */
unsigned short in_cksum_tcp(struct tcphdr* pTCPHdr_, struct sockaddr_in* pSrc_, 
		struct sockaddr_in* pDst_, int iDataLen_) {
	// The pseudoheader used to calculate the checksum.
	struct pseudohdr oPsh;																			// A buffer used to contain pseudoheader
	char* pPseudogram;																				// A buffer to store the pseudogram
	int iPseudoSize;																				// The size of the pseudogram-buffer

	// Configure the TCP-Pseudo-Header for checksum calculation.
	oPsh.source_addr = pSrc_->sin_addr.s_addr;                        								// Set the Source-Address
	oPsh.dest_addr = pDst_->sin_addr.s_addr;                          								// Set the Destination-Address
	oPsh.placeholder = 0;																			// Use 0 as a placeholder
	oPsh.protocol = IPPROTO_TCP;                                         							// Specific the used protocol
	oPsh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + iDataLen_);							// The length of the TCP-header

	// Paste everything into the pseudogram.
	iPseudoSize = sizeof(struct pseudohdr) + sizeof(struct tcphdr) + OPT_SIZE + iDataLen_;
	pPseudogram = malloc(iPseudoSize);
	// Copy the pseudo-header into the pseudogram.
	memcpy(pPseudogram, (char*)&oPsh, sizeof(struct pseudohdr));
	// Attach the TCP-header and -content after the pseudo-header.
	memcpy(pPseudogram + sizeof(struct pseudohdr), pTCPHdr_, 
			sizeof(struct tcphdr) + OPT_SIZE + iDataLen_);

	// Return the checksum of the TCP-header.
	return (in_cksum((char*)pPseudogram, iPseudoSize));
} // in_cksum_tcp

/**
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram. The function also converts the numbers to
 * the little-edian-byteorder.
 *
 * @param {char*} pPacket_ - A buffer containing the datagram with the numbers
 * @param {int*} pSeq_ - An address to write the seqeunce-number to
 * @param {int*} pAck_ - An address to write the acknowledgement-number to
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
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram and then returned the updated numbers.
 *
 * @param {char*} pPacket_ - A buffer containing the datagram with the numbers
 * @param {int*} pSeq_ - An address to write the updated seqeunce-number to
 * @param {int*} pAck_ - An address to write the updated acknowledgement-number to
 */
void update_seq_and_ack(char* pPacket_, uint32_t* pSeq_, uint32_t* pAck_) {
	uint32_t iSeqNum, iAckNum;
	// Read sequence number.
	memcpy(&iSeqNum, (pPacket_ + 24), 4);
	// Read acknowledgement number.
	memcpy(&iAckNum, (pPacket_ + 28), 4);
	// Convert network to host byte order.
	*pSeq_ = ntohl(iAckNum);
	*pAck_ = ntohl(iSeqNum);
	*pAck_ = *pAck_ + 1;
}  // update_seq_and_ack

/*
 * Write the necessary data to create a packet into the data-buffer. This
 * function will write the seq- and ack-number, and if given the payload
 * to the buffer.
 *
 * @param {char*} pDataBuf_ - The buffer to write the data to
 * @param {int*} pDataLen_ - The final length of the buffer
 * @param {int} iSeqNum_ - The sequence-number
 * @param {int} iAckNum_ - The acknowledgement-number
 * @param {char*} pPayload_ - The payload-buffer
 * @param {int} iPayloadLen_ - The length of the payload-buffer
*/
void gather_packet_data(char* pDataBuf_, int* pDataLen_, int iSeqNum_, int iAckNum_,
		char* pPayload_, int iPayloadLen_) {
	// Copy the seq- and ack-numbers into the buffer.
	memcpy(pDataBuf_, &iSeqNum_, 4);
	memcpy(pDataBuf_ + 4, &iAckNum_, 4);
	*pDataLen_ = 8;

	if(pPayload_ != NULL) {
		// Copy the payload into the data-buffer.
		memcpy(pDataBuf_ + 8, pPayload_, iPayloadLen_);
		// Adjust the buffer-length.
		*pDataLen_ += iPayloadLen_;
	}
} // gather_packet_data

/**
 * Setup a default TCP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * header right, you have to set flags afterwards, depending on the purpose of
 * the datagram. For example: To create a SYN-packet, you would have to activate 
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
	// Fill other values.
	pTCPHdr_->window = htons(5840);                                        							// The Window-Size
	pTCPHdr_->check = 0;																			// The TCP-Header-Checksum (calculated later)
	pTCPHdr_->urg_ptr = 0;																			// The pointer to the urgent data
} // setup_tcp_hdr

/**
 * Extract the TCP-header from the datagram. Note, all previous headers, have to
 * be removed already, as the function marks the beginning of the passed
 * datagram as the beginning of the TCP-header. It then parses the raw bytes
 * into the header-struct and returns the length of the TCP-header as it is.
 * To get the start-position of the payload, just add the length of the header
 * to the start of the TCP-header.
 *
 * @returns {unsigned int} The length of the TCP-header in bytes
 *
 * @param {struct tcphdr*} pTCPHdr_ - A pointer to the strut, used to parse the header into
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
 * Setup a default IP-header, with the standart settings. This function just
 * fills up the header with the default settings. To actually configure the
 * header right, you have to adjust further settings depending on the purpose of the
 * datagram afterwards. By default the following settings are used: IPv4,
 * Header-Length of 5 words and TCP as the transmission-protocol.
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
 * @returns {unsigned int} The length of the IP-header in bytes
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
 * Setup the ethernet-header and fill the necessary fields, with the given 
 * information.
 *
 * 
*/
void setup_eth_hdr(struct ethhdr* pEthHdr_, struct mac_addr* pSrcMac_, struct mac_addr* pDstMac_) {
	pEthHdr_->h_source[0] = pSrcMac_->addr[0];
	pEthHdr_->h_source[1] = pSrcMac_->addr[1];
	pEthHdr_->h_source[2] = pSrcMac_->addr[2];
	pEthHdr_->h_source[3] = pSrcMac_->addr[3];
	pEthHdr_->h_source[4] = pSrcMac_->addr[4];
	pEthHdr_->h_source[5] = pSrcMac_->addr[5];
	
	pEthHdr_->h_dest[0] = pDstMac_->addr[0];
	pEthHdr_->h_dest[1] = pDstMac_->addr[1];
	pEthHdr_->h_dest[2] = pDstMac_->addr[2];
	pEthHdr_->h_dest[3] = pDstMac_->addr[3];
	pEthHdr_->h_dest[4] = pDstMac_->addr[4];
	pEthHdr_->h_dest[5] = pDstMac_->addr[5];

	// Set IP as the next header.
	pEthHdr_->h_proto = htons(ETH_P_IP);
} // setup_eth_hdr

/**
 * Define a raw datagram used to transfer data to a server. The passed
 * buffer has to containg at least the seq- and ack-numbers of the 
 * datagram. To pass the payload, just attach it to the end of the 
 * data-buffer and adjust the size-parameter to the new buffer-size.
 *
 * @param {char*} pOutPacket_ - A pointer to memory to store packet
 * @param {int*} pOutPacketLen_ - Length of the datagram in bytes
 * @param {int} iType_ - The type of packet
 * @param {struct mac_addr*} pSrcMac_ - Source-MAC-address of packet
 * @param {struct mac_addr*} pDstMac_ - Destination-MAC-address of packet
 * @param {struct sockaddr_in*} pSrc_ - The source-IP-address
 * @param {struct sockaddr_in*} pDst_ - The destination-IP-address
 * @param {char*} pDataBuf_ - A buffer containing data to create datagram
 * @param {int} iDataLen_ - The length of the buffer
*/
void create_raw_datagram(char* pOutPacket_, int* pOutPacketLen_, int iType_,
		struct mac_addr* pSrcMac_, struct mac_addr* pDstMac_,
		struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_, 
		char* pDataBuf_, int iDataLen_) {
	uint32_t iSeq, iAck;																			// Both the seq- and ack-numbers
	int iPayloadLen = 0;																			// The length of the payload, or 0
	
	// If the passes data-buffer contains more than the seq- and ack-numbers.
	if(iDataLen_ > 8) {
		// The length of the payload is the length of the whole buffer
		// without the seq- and ack-numbers.
		iPayloadLen = iDataLen_ - 8;
	}

	// Reserve empty space for storing the datagram. (memory already filled with zeros)
	char* pDatagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Required structs for the IP- and TCP-header.
	struct ethhdr* ethh = (struct ethhdr*)pDatagram;
	struct iphdr* iph = (struct iphdr*)pDatagram + sizeof(struct ethhdr);
	struct tcphdr* tcph = (struct tcphdr*)(pDatagram + sizeof(struct ethhdr) + sizeof(struct iphdr));

	// Configure the Ethernet-header.
	setup_eth_hdr(ethh, pSrcMac_, pDstMac_);	

	// Configure the IP-header.
	setup_ip_hdr(iph, pSrc_, pDst_, iPayloadLen);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);

	// Configure the datagram, depending on the type.
	switch(iType_) {
		case(URG_PACKET):
			break;
		
		case(ACK_PACKET):
			// Set packet-flags.
			tcph->ack = 1;

			// Set seq- and ack-numbers.
			memcpy(&iSeq, pDataBuf_, 4);
			memcpy(&iAck, pDataBuf_ + 4, 4);
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
		
		case(PSH_PACKET):
			// Set datagram-flags.
			tcph->psh = 1;
			tcph->ack = 1;

			// Set payload according to the preset message.
			char* payload = pDatagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
			memcpy(payload, pDataBuf_ + 8, iDataLen_ - 8);

			// Set seq- and ack-numbers.
			memcpy(&iSeq, pDataBuf_, 4);
			memcpy(&iAck, pDataBuf_ + 4, 4);
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
		
		case(RST_PACKET):
			break;
				
		case(SYN_PACKET):
			// Set datagram-flags.
			tcph->syn = 1;

			// TCP options are only set in the SYN packet.
			// Set the Maximum Segment Size(MMS).
			pDatagram[40] = 0x02;
			pDatagram[41] = 0x04;
			int16_t mss = htons(48);
			memcpy(pDatagram + 42, &mss, sizeof(int16_t));
			// Enable SACK.
			pDatagram[44] = 0x04;
			pDatagram[45] = 0x02;
			break;

		case(FIN_PACKET):
			// Set the datagram-flags.
			tcph->ack = 1;
			tcph->fin = 1;

			// Set seq- and ack-numbers.
			memcpy(&iSeq, pDataBuf_, 4);
			memcpy(&iAck, pDataBuf_ + 4, 4);
			tcph->seq = htonl(iSeq);
			tcph->ack_seq = htonl(iAck);
			break;
	}

	// Calculate the checksum for both the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, iPayloadLen);
	iph->check = in_cksum((char*)pDatagram, iph->tot_len);

	// Return the created datagram.
	memset(pOutPacket_, 0, DATAGRAM_LEN);
	memcpy(pOutPacket_, pDatagram, DATAGRAM_LEN);
	*pOutPacketLen_ = iph->tot_len;
}  // create_raw_datagram

/**
 * 
 */
void strip_raw_packet(char* pPckBuf_, int iPckLen_, struct iphdr* pIPHdr_,  
		struct tcphdr* pTCPHdr_, char* pPayload_, int* iPayloadLen_) {

	short iIPHdrLen;
	int iTCPHdrLen;

	// Remove the IP-header, and write it to the header-struct.
	iIPHdrLen = strip_ip_hdr(pIPHdr_, pPckBuf_, iPckLen_);

	if(pTCPHdr_ != NULL) {
		// Remove the TCP-header, and write it to the header-struct.
		iTCPHdrLen = strip_tcp_hdr(pTCPHdr_, (pPckBuf_ + iIPHdrLen), (iPckLen_ - iIPHdrLen));
		
		if(pPayload_ != NULL) {
			// Get the length of the payload contained in the datagram.
			*iPayloadLen_ = (iPckLen_ - iIPHdrLen - iTCPHdrLen);
	
			// Copy the payload into the according buffer.
			memcpy(pPayload_, pPckBuf_ + iIPHdrLen + iTCPHdrLen, *iPayloadLen_);
		}
	}	
} // strip_raw_packet
