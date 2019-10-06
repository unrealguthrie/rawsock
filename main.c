/**
 * FILE: main.c
 * SEND A MESSAGE VIA TCP/IP USING RAW SOCKETS
 * Julian Kennerknecht [Julian.kennerknecht@gmx.de]
 *
 * usage: sudo ./rawsock 192.168.2.109 $(perl -e 'print int(rand(4444) + 1111)') 192.168.2.100 4242
 */

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

#include "./incl/bsc_ext.h"
#include "./incl/packet.h"

// Set packet-types.
#define URG_PACKET 0
#define ACK_PACKET 1
#define PSH_PACKET 2
#define RST_PACKET 3
#define SYN_PACKET 4
#define FIN_PACKET 5

// ==== PROTOTYPES ====
void create_raw_packet(char**, int*, int, struct sockaddr_in*, struct sockaddr_in*, 
		char*, int);
void create_psh_packet(struct sockaddr_in*, struct sockaddr_in*, int32_t, int32_t, 
		char*, int, char**, int*);
void read_seq_and_ack(const char*, uint32_t*, uint32_t*);
int receive_packet(int, char*, size_t, struct sockaddr_in*);

// ==== MAIN FUNCTION ====
int main(int argc, char** argv) {
	// Check if all necessary parameters have been specified by the user.
	if (argc < 5) {
		// printf("invalid parameters.\n");
		printf("usage: %s <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
		exit (1);
	}

	int iSockHdl, iPckLen, iSent, one  = 1;
	struct sockaddr_in daddr, saddr;
	char* pPck;
	int iRecvLen;
	char recvbuf[DATAGRAM_LEN];
	uint32_t iSeqNum, iAckNum, iNewSeqNum, iNewAckNum;
	char request[] = "TEST TEST.";
	char* pDataBuf;
	int iTCPoff = 0;
	struct iphdr sIPHdr;
	struct tcphdr sTCPHdr;
	char* pDataOff;
	int iDataLen = 0;
	short sSendPacket = 0;

	// Reset seed used for generating random numbers.
	srand(time(NULL));

	printf("SETUP:\n");

	// Create a raw socket for communication.
	printf(" Create raw socket...");
	iSockHdl = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (iSockHdl < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	// Configure the destination-IP-address.
	printf(" Configure destination-ip...");
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[4]));
	if (inet_pton(AF_INET, argv[3], &daddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Dest-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Configure the source-IP-address.
	printf(" Configure source-ip...");
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Src-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Tell the kernel that headers are included in the packet.
	printf(" Finalize socket configuration...");
	if (setsockopt(iSockHdl, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");
	printf("\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// THE TCP-HANDSHAKE

	printf("TCP-HANDSHAKE:\n");

	// Step 1: Send the SYN-packet.
	printf(" Send SYN-pck...");
	// create_syn_packet(&saddr, &daddr, &pPck, &iPckLen);
	create_raw_packet(&pPck, &iPckLen, SYN_PACKET, &saddr, &daddr, NULL, 0);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}
	printf("ok. (%d bytes)\n", iSent);

	// Step 2: Wait for the SYN-ACK-packet.
	printf(" Waiting for SYN-ACK-pck...");
	iRecvLen = receive_packet(iSockHdl, recvbuf, sizeof(recvbuf), &saddr);
	if (iRecvLen <= 0) {
		printf("failed.\n");
		exit(1);
	}
	printf("ok. (%d bytes)\n", iRecvLen);

	// Read sequence number to acknowledge in next packet.
	read_seq_and_ack(recvbuf, &iSeqNum, &iAckNum);
	iNewSeqNum = iAckNum;
	iNewAckNum = iSeqNum + 1;
	
	// Step 3: Send the ACK-packet.
	// The previous seq-number is used as ack number and vica vera.
	printf(" Send ACK-pck...");
	pDataBuf = malloc(8);
	memcpy(pDataBuf, &iNewSeqNum, 4);
	memcpy(pDataBuf + 4, &iNewAckNum, 4);
	create_raw_packet(&pPck, &iPckLen, ACK_PACKET, &saddr, &daddr, pDataBuf, 8);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		exit(1);
	}
	free(pDataBuf);
	printf("ok. (%d bytes)\n", iSent);
	printf("\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SEND DATA USING TCP-SOCKET

	// Send data using the established connection.	
	printf("Send data to server...");

	int iPayloadLen = ((sizeof(request) - 1) / sizeof(char));
	pDataBuf = malloc(8 + iPayloadLen);
	memcpy(pDataBuf, &iNewSeqNum, 4);
	memcpy(pDataBuf + 4, &iNewAckNum, 4);
	memcpy(pDataBuf + 8, request, iPayloadLen);
	create_raw_packet(&pPck, &iPckLen, PSH_PACKET, &saddr, &daddr, pDataBuf, 8 + iPayloadLen);	

	//create_psh_packet(&saddr, &daddr, iNewSeqNum, iNewAckNum, request, 
	//		sizeof(request) - 1 / sizeof(char), &pPck, &iPckLen);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}
	printf("done. (%d byte)\n", iSent);

	// Wait for the response from the server.
	while ((iRecvLen = receive_packet(iSockHdl, recvbuf, sizeof(recvbuf), &saddr)) > 0) {
		//hexDump(recvbuf, received);
		// Extract the IP-header and remove the header-length. 
		iTCPoff = strip_ip_hdr(&sIPHdr, recvbuf, iRecvLen);
		pDataOff = recvbuf;
		strip_tcp_hdr(&sTCPHdr, recvbuf + iTCPoff, iRecvLen - iTCPoff, pDataOff, &iDataLen);

	 	// hexDump(recvbuf, received);	
		// hexDump(&sIPHdr, sizeof(struct iphdr));
		//hexDump(&sTCPHdr, sizeof(struct tcphdr));

		printf("[IN]  %s:%d --> %s:%d ", "192.168.2.100", ntohs(sTCPHdr.source), "192.168.2.109", ntohs(sTCPHdr.dest));

		printf("| Flags: (");
		if(sTCPHdr.urg) printf(" urg: %x", sTCPHdr.urg);
		if(sTCPHdr.ack) printf(" ack: %x", sTCPHdr.ack);
		if(sTCPHdr.psh) printf(" psh: %x", sTCPHdr.psh);
		if(sTCPHdr.rst) printf(" rst: %x", sTCPHdr.rst);
		if(sTCPHdr.syn) printf(" syn: %x", sTCPHdr.syn);
		if(sTCPHdr.fin) printf(" fin: %x", sTCPHdr.fin);
		printf(" )\n");

		if(iDataLen > 0 && 0) {
			char* pContentBuf = malloc(iDataLen + 1);
			memcpy(pContentBuf, recvbuf + iTCPoff + 20, iDataLen);
			//*(pContentBuf + iDataLen) = '\0';
			hexDump(pContentBuf, iDataLen);
			printf("Dumped %d bytes.\n", iDataLen);
		}

		// Read ack- and seq-packet
		read_seq_and_ack(recvbuf, &iSeqNum, &iAckNum);

		iNewSeqNum = (iSeqNum + 1);

		if(sTCPHdr.fin == 1) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iNewSeqNum, 4);
			memcpy(pDataBuf + 4, &iAckNum, 4);
			create_raw_packet(&pPck, &iPckLen, FIN_PACKET, &saddr, &daddr, pDataBuf, 8);
			free(pDataBuf);
			sSendPacket = 1;
		}
		else if(sTCPHdr.psh == 1) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iNewSeqNum, 4);
			memcpy(pDataBuf + 4, &iAckNum, 4);
			create_raw_packet(&pPck, &iPckLen, ACK_PACKET, &saddr, &daddr, pDataBuf, 8);
			free(pDataBuf);
				
			sSendPacket = 1;
		}
		if(sSendPacket) {
			if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
						sizeof(struct sockaddr))) < 0) {
				printf("send failed\n");
			} 
			else {
				printf("[OUT] 192.168.2.109:4242 --> 192.168.2.100:4242 | FLAGS: ( ack: 1 )\n");
				sSendPacket = 0;
				if(sTCPHdr.fin == 1) {
					break;
				}
			}
		}
	}

	// Close the socket.
	printf("Close socket...");
	close(iSockHdl);
	printf("done.\n");
	return (0);
}  // main

// ==== DEFINE FUNCTIONS ====
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
			tcph->ack = htonl(iAck);
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
			tcph->ack = htonl(iAck);

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
			tcph->ack = htonl(iAck);
			break;
	}

	// Calculate the checksum for both the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, iPayloadLen);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;
}  // create_raw_packet

/**
 * Extract both the sequence-number and the acknowledgement-number from 
 * the received datagram. These numbers are already converted to little-edian
 * when returned by the function.
 *
 * @param {char*} pPacket_ - A buffer containing the datagram
 * @param {int*} pSeq_ - An address to write the seq-number to
 * @param {int*} pAck_ - An address to write the ack-number to
 */
void read_seq_and_ack(const char* pPacket_, uint32_t* pSeq_, uint32_t* pAck_) {
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
 * Recieve a short packet using a given socket and write the data to a buffer.
 *
 * @param {int} iSockHdl_ - The sockets to receive packets with
 * @param {char*} pBuf_ - A buffer to write to
 * @param {size_t} sBufLen_ - The length of the buffer
 *
 */
int receive_packet(int iSockHdl_, char* pBuf_, size_t sBufLen_, struct sockaddr_in* pDst_) {
	unsigned short dst_port;
	int iRecvLen;

	do {
		iRecvLen = recvfrom(iSockHdl_, pBuf_, sBufLen_, 0, NULL, NULL);
		if (iRecvLen <= 0) {
			break;
		}
		memcpy(&dst_port, pBuf_ + 22, sizeof(dst_port));
	} while (dst_port != pDst_->sin_port);

	// Return the amount of recieved bytes.
	return (iRecvLen);
} // receive_packet
