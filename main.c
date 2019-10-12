/**
 * FILE: main.c
 * SEND DATA VIA TCP/IP USING RAW SOCKETS IN C
 * Julian Kennerknecht [Julian.kennerknecht@gmx.de]
 *
 * usage: sudo ./rawsock <Src-IP> <Src-Port> <Dst-IP> <Dst-Port>
 * example: sudo ./rawsock 192.168.2.109 4243 192.168.2.100 4242
 *
 * Replace Src-Port with the following code to generate random ports for testing: 
 * $(perl -e 'print int(rand(4444) + 1111)')
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
	// Check if all necessary parameters have been set by the user.
	if (argc < 5) {
		printf("usage: %s <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
		exit (1);
	}

	int iSockHdl;
	int iSent;
    int	one  = 1;
	
	// The IP-addresses of both maschines in the connections.
	struct sockaddr_in sSrcAddr;																	// The source-IP-address
	struct sockaddr_in sDstAddr;																	// The destination-IP-address
	
	// The buffer containing the raw datagram, both when it is
	// received and send.
	char* pPckBuf;																					// The buffer containing the raw datagram
	int iPckLen;																					// Length of the datagram-buffer in bytes

	// The buffer filled with the information to create the packet.
	// The buffer will be filled like that: Seq + Ack [ + Payload ]
	// So by default without the payload, it is 8 bytes long.
	char* pDataBuf;																					// Data needed to create packet
	int iDataLen = 0;																				// The length of the data-buffer in bytes

	// Both numbers used to identify the send packets.
	uint32_t iSeqNum; 																				// The sequence-number
	uint32_t iAckNum;																				// The acknowledgement-number

	// The payload contained in the packet.
	char pPayload[] = "Data send.";																	// A buffer containing the payload
	int iPayloadLen = iPayloadLen = ((sizeof(pPayload) - 1) / sizeof(char));						// The length of the payloadin bytes

	// Buffers used when taking apart the received datagrams.
	int iIPHdrLen = 0; 																				// Length of the IP-header in bytes
	struct iphdr sIPHdr;																			// Buffer containing the IP-header
	int iTCPHdrLen = 0;																				// Length of the TCP-header in bytes
	struct tcphdr sTCPHdr;																			// Buffer containing the TCP-header
		
	short sSendPacket = 0;
	char* pContentBuf;

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SETUP SCRIPT

	printf("SETUP:\n");

	// Reserve memory for the datagram.
	pPckBuf = calloc(DATAGRAM_LEN, sizeof(char));

	// Set the payload being send to the other maschine.
	

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
	printf(" Configure socket...");
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
	memset(pPckBuf, 0, DATAGRAM_LEN);
	create_raw_datagram(pPckBuf, &iPckLen, SYN_PACKET, &sSrcAddr, &sDstAddr, NULL, 0);
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}
	printf("ok. (%d bytes)\n", iSent);

	// Step 2: Wait for the SYN-ACK-packet.
	printf(" Waiting for SYN-ACK-pck...");
	iPckLen = receive_packet(iSockHdl, pPckBuf, DATAGRAM_LEN, &sSrcAddr);
	if (iPckLen <= 0) {
		printf("failed.\n");
		exit(1);
	}
	printf("ok. (%d bytes)\n", iPckLen);

	// Update seq-number and ack-number.
	update_seq_and_ack(pPckBuf, &iSeqNum, &iAckNum);
	
	// Step 3: Send the ACK-packet, with updatet numbers.
	printf(" Send ACK-pck...");
	memset(pPckBuf, 0, DATAGRAM_LEN);
	pDataBuf = malloc(8);
	memcpy(pDataBuf, &iSeqNum, 4);
	memcpy(pDataBuf + 4, &iAckNum, 4);
	create_raw_datagram(pPckBuf, &iPckLen, ACK_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		exit(1);
	}
	free(pDataBuf);
	printf("ok. (%d bytes)\n", iSent);

	printf("\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SEND DATA USING TCP-SOCKET

	printf("TRANSMISSIONS:\n");

	// Send data using the established connection.	
	printf("Send data to server...");

	pDataBuf = malloc(8 + iPayloadLen);
	memcpy(pDataBuf, &iSeqNum, 4);
	memcpy(pDataBuf + 4, &iAckNum, 4);
	// Additionally to the seq- and ack-number, add the playload.
	memcpy(pDataBuf + 8, pPayload, iPayloadLen);
	create_raw_datagram(pPckBuf, &iPckLen, PSH_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8 + iPayloadLen);	
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}
	printf("done. (%d byte)\n", iSent);


	// Wait for the response from the server.
	while ((iPckLen = receive_packet(iSockHdl, pPckBuf, DATAGRAM_LEN, &sSrcAddr)) > 0) {
		// Extract the IP-header and get the header-length. 
		iIPHdrLen = strip_ip_hdr(&sIPHdr, pPckBuf, iPckLen);
		// Extract the TCP-header and get a pointer to the payload-data.
		iTCPHdrLen = strip_tcp_hdr(&sTCPHdr, (pPckBuf + iIPHdrLen), (iPckLen - iTCPHdrLen));
		// Get the length of the payload contained in the datagram.
		iDataLen = (iPckLen - iIPHdrLen - iIPHdrLen);

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
			memcpy(pContentBuf, (pPckBuf + iIPHdrLen + iTCPHdrLen), iDataLen);
			hexDump(pContentBuf, iDataLen);
			printf("Dumped %d bytes.\n", iDataLen);
		}

		// Update ack-number and seq-numbers.
		update_seq_and_ack(pPckBuf, &iSeqNum, &iAckNum);

		if(sTCPHdr.fin == 1) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iSeqNum, 4);
			memcpy(pDataBuf + 4, &iAckNum, 4);
			create_raw_datagram(pPckBuf, &iPckLen, FIN_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
			free(pDataBuf);
			sSendPacket = 1;
		}
		else if(sTCPHdr.psh == 1 || (sTCPHdr.ack == 1 && iDataLen > 0)) {
			pDataBuf = malloc(8);
			memcpy(pDataBuf, &iSeqNum, 4);
			memcpy(pDataBuf + 4, &iAckNum, 4);
			create_raw_datagram(pPckBuf, &iPckLen, ACK_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, 8);
			free(pDataBuf);
				
			sSendPacket = 1;
		}
		if(sSendPacket) {
			if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
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

	// Clear the memory used to store the datagram.
	memset(pBuf_, 0, sBufLen_);

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
