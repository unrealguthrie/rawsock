/**
 * FILE: main.c
 * SEND DATA VIA TCP/IP USING RAW SOCKETS IN C
 * Julian Kennerknecht [Julian.kennerknecht@gmx.de]
 *
 * Prevent the kernel from sending RST-packets:
 * $ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 * 
 * Drop the rule:
 * $ sudo iptables -F
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
	short sSendPacket = 0;																			// The type of packet used to responde
	
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
	char* pPayload;																					// A buffer containing the payload
	int iPayloadLen;																				// The length of the payloadin bytes

	// Buffers used when taking apart the received datagrams.
	struct iphdr sIPHdr;																			// Buffer containing the IP-header
	struct tcphdr sTCPHdr;																			// Buffer containing the TCP-header


	// Reserve memory for the datagram.
	pPckBuf = calloc(DATAGRAM_LEN, sizeof(char));

	// Initialize the data-buffer.
	pDataBuf = malloc(520);

	// Set the payload intended to be send using the connection.
	pPayload = malloc(512);
	strcpy(pPayload, "Data send.");
	iPayloadLen = (strlen(pPayload) / sizeof(char));


	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SETUP SOCKET

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
	printf(" Configure socket...");
	if (setsockopt(iSockHdl, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	printf("\n");
	printf("COMMUNICATION:\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// THE TCP-HANDSHAKE

	// Step 1: Send the SYN-packet.
	memset(pPckBuf, 0, DATAGRAM_LEN);
	create_raw_datagram(pPckBuf, &iPckLen, SYN_PACKET, &sSrcAddr, &sDstAddr, NULL, 0);
	dump_packet(pPckBuf, iPckLen);
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}

	// Step 2: Wait for the SYN-ACK-packet.
	iPckLen = receive_packet(iSockHdl, pPckBuf, DATAGRAM_LEN, &sSrcAddr);
	dump_packet(pPckBuf, iPckLen);
	if (iPckLen <= 0) {
		printf("failed.\n");
		exit(1);
	}

	// Update seq-number and ack-number.
	update_seq_and_ack(pPckBuf, &iSeqNum, &iAckNum);
	
	// Step 3: Send the ACK-packet, with updated numbers.
	memset(pPckBuf, 0, DATAGRAM_LEN);
	gather_packet_data(pDataBuf, &iDataLen, iSeqNum, iAckNum, NULL, 0);
	create_raw_datagram(pPckBuf, &iPckLen, ACK_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, iDataLen);
	dump_packet(pPckBuf, iPckLen);
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		exit(1);
	}
	free(pDataBuf);

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SEND DATA USING TCP-SOCKET

	// Send data using the established connection.	
	gather_packet_data(pDataBuf, &iDataLen, iSeqNum, iAckNum, pPayload, iPayloadLen);
	create_raw_datagram(pPckBuf, &iPckLen, PSH_PACKET, &sSrcAddr, &sDstAddr, pDataBuf, iDataLen);	
	dump_packet(pPckBuf, iPckLen);
	if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}


	// Wait for the response from the server.
	while ((iPckLen = receive_packet(iSockHdl, pPckBuf, DATAGRAM_LEN, &sSrcAddr)) > 0) {
		// Display packet-info in the terminal.
		dump_packet(pPckBuf, iPckLen);

		// Deconstruct the packet and extract payload.
		strip_raw_packet(pPckBuf, iPckLen, &sIPHdr, &sTCPHdr, pPayload, &iPayloadLen);

		// Dump payload in the terminal, if there is any.
		if(iPayloadLen > 0) {
			hexDump(pPayload, iPayloadLen);
			printf("Dumped %d bytes.\n", iPayloadLen);
		}

		// Update ack-number and seq-numbers.
		update_seq_and_ack(pPckBuf, &iSeqNum, &iAckNum);

		sSendPacket = 0;
		if(sTCPHdr.fin == 1) {
			sSendPacket = FIN_PACKET;
		}
		else if(sTCPHdr.psh == 1 || (sTCPHdr.ack == 1 && iDataLen > 0)) {
			sSendPacket = ACK_PACKET;
		}
		if(sSendPacket != 0) {
			// Create the response-packet.
			gather_packet_data(pDataBuf, &iDataLen, iSeqNum, iAckNum, NULL, 0);
			create_raw_datagram(pPckBuf, &iPckLen, sSendPacket, &sSrcAddr, &sDstAddr, pDataBuf, 8);
			dump_packet(pPckBuf, iPckLen);
			free(pDataBuf);

			if ((iSent = sendto(iSockHdl, pPckBuf, iPckLen, 0, (struct sockaddr*)&sDstAddr, 
						sizeof(struct sockaddr))) < 0) {
				printf("send failed\n");
			} 
			else {
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
