/**
 * FILE: main.c
 * SEND A MESSAGE VIA TCP/IP USING RAW SOCKETS
 * Julian Kennerknecht [Julian.kennerknecht@gmx.de]
 *
 * usage: sudo ./rawsock <Src-IP> <Src-Port> <Dst-IP> <Dst-Port>
 * example: sudo ./rawsock 192.168.2.109 4243 192.168.2.100 4242
 *
 * To generate random ports for testing: $(perl -e 'print int(rand(4444) + 1111)')
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

// ==== PROTOTYPES ====
int receive_packet(int, char*, size_t, struct sockaddr_in*);

// ==== MAIN FUNCTION ====
int main(int argc, char** argv) {
	// Check if all necessary parameters have been specified by the user.
	if (argc < 5) {
		printf("usage: %s <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
		exit (1);
	}

	int iSockHdl, iSent, one  = 1;
	struct sockaddr_in sDstAddr, sSrcAddr;															// The source- and destination-addresses
	char* pPck;																						// The buffer containing the raw datagram
	int iPckLen;																					// The length of the datagram-buffer
	char pRecvBuf[DATAGRAM_LEN];																	// A buffer containing the received datagram
	int iRecvLen;
	uint32_t iSeqNum, iAckNum;																		// The seq- and ack-numbers
   	uint32_t iNewSeqNum, iNewAckNum;																// Placeholder for new seq- and ack-numbers
	char request[] = "TEST TEST.";
	char* pDataBuf;
	int iIPHdrLen = 0, iTCPHdrLen = 0, iDataLen = 0;
	struct iphdr sIPHdr;																			// A buffer used to create the IP-header
	struct tcphdr sTCPHdr;																			// A buffer used to create the TCP-header
	short sSendPacket = 0;
	int iPayloadLen;
	char* pContentBuf;

	// Reset seed used for generating random numbers.
	srand(time(NULL));

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SETUP SCRIPT

	printf("SETUP:\n");

	// Create a raw socket for communication and store socket-handler.
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
	sDstAddr.sin_family = AF_INET;
	sDstAddr.sin_port = htons(atoi(argv[4]));
	if (inet_pton(AF_INET, argv[3], &sDstAddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Dest-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Configure the source-IP-address.
	printf(" Configure source-ip...");
	sSrcAddr.sin_family = AF_INET;
	sSrcAddr.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &sSrcAddr.sin_addr) != 1) {
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
	create_raw_packet(&pPck, &iPckLen, SYN_PACKET, &sSrcAddr, &sDstAddr, NULL, 0);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}
	printf("ok. (%d bytes)\n", iSent);

	// Step 2: Wait for the SYN-ACK-packet.
	printf(" Waiting for SYN-ACK-pck...");
	iRecvLen = receive_packet(iSockHdl, pRecvBuf, sizeof(pRecvBuf), &sSrcAddr);
	if (iRecvLen <= 0) {
		printf("failed.\n");
		exit(1);
	}
	printf("ok. (%d bytes)\n", iRecvLen);

	// Update seq-number and ack-number.
	read_seq_and_ack(pRecvBuf, &iSeqNum, &iAckNum);
	iNewSeqNum = iAckNum;
	iNewAckNum = iSeqNum + 1;
	
	// Step 3: Send the ACK-packet.
	printf(" Send ACK-pck...");
	pDataBuf = malloc(8);
	memcpy(pDataBuf, &iNewSeqNum, 4);
	memcpy(pDataBuf + 4, &iNewAckNum, 4);
	create_raw_packet(&pPck, &iPckLen, ACK_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
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

	iPayloadLen = ((sizeof(request) - 1) / sizeof(char));
	pDataBuf = malloc(8 + iPayloadLen);
	memcpy(pDataBuf, &iNewSeqNum, 4);
	memcpy(pDataBuf + 4, &iNewAckNum, 4);
	// Additionally to the seq- and ack-number, add the playload.
	memcpy(pDataBuf + 8, request, iPayloadLen);
	create_raw_packet(&pPck, &iPckLen, PSH_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8 + iPayloadLen);	
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}
	printf("done. (%d byte)\n", iSent);

	// Wait for the response from the server.
	while ((iRecvLen = receive_packet(iSockHdl, pRecvBuf, sizeof(pRecvBuf), &sSrcAddr)) > 0) {
		// Extract the IP-header and get the header-length. 
		iIPHdrLen = strip_ip_hdr(&sIPHdr, pRecvBuf, iRecvLen);
		// Extract the TCP-header and get a pointer to the payload-data.
		iTCPHdrLen = strip_tcp_hdr(&sTCPHdr, (pRecvBuf + iIPHdrLen), (iRecvLen - iTCPHdrLen));
		// Get the length of the payload contained in the datagram.
		iDataLen = (iRecvLen - iIPHdrLen - iIPHdrLen);

		printf("[IN]  %s:%d -> %s:%d ", "192.168.2.100", ntohs(sTCPHdr.source), "192.168.2.109", ntohs(sTCPHdr.dest));

		printf("| (");
		if(sTCPHdr.urg) printf(" urg: %x", sTCPHdr.urg);
		if(sTCPHdr.ack) printf(" ack: %x", sTCPHdr.ack);
		if(sTCPHdr.psh) printf(" psh: %x", sTCPHdr.psh);
		if(sTCPHdr.rst) printf(" rst: %x", sTCPHdr.rst);
		if(sTCPHdr.syn) printf(" syn: %x", sTCPHdr.syn);
		if(sTCPHdr.fin) printf(" fin: %x", sTCPHdr.fin);
		printf(" )\n");

		// Dump payload in the terminal, if there is any.
		if(iDataLen > 0) {
			pContentBuf = malloc(iDataLen + 1);
			memcpy(pContentBuf, (pRecvBuf + iIPHdrLen + iTCPHdrLen), iDataLen);
			hexDump(pContentBuf, iDataLen);
			printf("Dumped %d bytes.\n", iDataLen);
		}

		// Update ack-number and seq-number.
		read_seq_and_ack(pRecvBuf, &iSeqNum, &iAckNum);
		iNewSeqNum = iAckNum;
		iNewAckNum = iSeqNum + 1;

		if(sTCPHdr.fin == 1) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iNewSeqNum, 4);
			memcpy(pDataBuf + 4, &iNewAckNum, 4);
			create_raw_packet(&pPck, &iPckLen, FIN_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
			free(pDataBuf);
			sSendPacket = 1;
		}
		else if(sTCPHdr.psh == 1) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iNewSeqNum, 4);
			memcpy(pDataBuf + 4, &iNewAckNum, 4);
			create_raw_packet(&pPck, &iPckLen, ACK_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
			free(pDataBuf);
				
			sSendPacket = 1;
		}
		if(sSendPacket) {
			if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
						sizeof(struct sockaddr))) < 0) {
				printf("send failed\n");
			} 
			else {
				printf("[OUT] 192.168.2.109:4242 -> 192.168.2.100:4242 | ( ack: 1 )\n");
				sSendPacket = 0;
				if(sTCPHdr.fin == 1) {
					break;
				}
			}
		}
	}

	printf("\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// CLEAN-UP THE SCRIPT
	
	printf("CLEAN-UP:\n");

	// Close the socket.
	printf(" Close socket...");
	close(iSockHdl);
	printf("done.\n");
	return (0);
}  // main

// ==== DEFINE FUNCTIONS ====
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
