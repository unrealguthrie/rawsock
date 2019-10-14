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
#include <netpacket/packet.h>
//#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */
#include <sys/ioctl.h>
#include <net/if.h>

#include "./incl/bsc_ext.h"
#include "./incl/packet.h"

// ==== PROTOTYPES ====
void dump_packet(char*, int);
int receive_packet(int, char*, size_t, struct sockaddr_in*);

// ==== MAIN FUNCTION ====
int main(int argc, char** argv) {
	// Check if all necessary parameters have been set by the user.
	if (argc < 5) {
		printf("usage: %s <itf> <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
		exit (1);
	}


	int iSockHdl;
	int iSent;
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
	iSockHdl = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (iSockHdl < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	struct ifreq ifreq_i;
	struct ifreq ifreq_c;
	struct ifreq ifreq_ip;	

	// Get the index of the interface to send a packet.
	printf(" Get index of interface...");
	memset(&ifreq_i, 0, sizeof(ifreq_i));
	strncpy(ifreq_i.ifr_name, argv[1], IFNAMSIZ - 1);
	if((ioctl(iSockHdl, SIOCGIFINDEX, &ifreq_i)) < 0) {
		printf("failed.\n");
		printf("ERROR: Index ioctl reading.\n");
		exit(1);
	}
	printf("done. (%s/%d)\n", argv[1], ifreq_i.ifr_ifindex);

	// Get the MAC-address of the interface.
	printf(" Get MAC-address of interface...");
	memset(&ifreq_c, 0, sizeof(ifreq_c));
	strncpy(ifreq_c.ifr_name, argv[1], IFNAMSIZ - 1);
	if((ioctl(iSockHdl, SIOCGIFHWADDR, &ifreq_c)) < 0) {
		printf("failed.\n");
		printf("ERROR: SIOCGIFHWADDR ioctl reading.\n");
		exit(1);	
	}
	printf("done.\n");

	// Get the IP-address of the interface.
	printf(" Get IP-address of interface...");
	memset(&ifreq_ip, 0, sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name, argv[1], IFNAMSIZ - 1);
	if(ioctl(iSockHdl, SIOCGIFADDR, &ifreq_ip) < 0) {
		printf("failed.\n");
		printf("ERROR: In SIOCGIFADDR.\n");
		exit(1);
	}
	printf("done.\n");

	// Configure the destination-IP-address.
	printf(" Configure destination-ip...");
	sDstAddr.sin_family = AF_INET;
	sDstAddr.sin_port = htons(atoi(argv[5]));
	if (inet_pton(AF_INET, argv[4], &sDstAddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Dest-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Configure the source-IP-address.
	printf(" Configure source-ip...");
	sSrcAddr.sin_family = AF_INET;
	sSrcAddr.sin_port = htons(atoi(argv[3]));
	if (inet_pton(AF_INET, argv[2], &sSrcAddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Src-IP invalid:");
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
		exit(1);
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
	while (1) {
		// Receive a packet from the other maschine.
		iPckLen = receive_packet(iSockHdl, pPckBuf, DATAGRAM_LEN, &sSrcAddr);
		if(iPckLen < 1)
			break;

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
		} else if(sTCPHdr.psh == 1 || (sTCPHdr.ack == 1 && iDataLen > 0)) {
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
 * 
*/
void setup_eth_header() {
} // setup_eth_header

/**
 * A simple function to useful informations about a datagram,
 * into the terminal.
 *
 * @param {char*} pPckBuf_ - The raw datagram
 * @param {int} iPckLen_ - The length of the packet-buffer in bytes
*/
void dump_packet(char* pPckBuf_, int iPckLen_) {
	char cPos = 0;
	struct iphdr sIPHdr;
	short iIPHdrLen;
	struct tcphdr sTCPHdr;
	// int iTCPHdrLen;
	unsigned char* pOff;
	uint32_t iSrcAddr, iDstAddr;
	unsigned short sSrcPort, sDstPort;

	// Unwrap both headers.
	iIPHdrLen = strip_ip_hdr(&sIPHdr, pPckBuf_, iPckLen_);
	strip_tcp_hdr(&sTCPHdr, (pPckBuf_ + iIPHdrLen), (iPckLen_ - iIPHdrLen));

	// Get the IP-addresses.
	iSrcAddr = sIPHdr.saddr;
	iDstAddr = sIPHdr.daddr;

	printf("[*] ");

	// Ouput the source-IP-address.
	pOff = (unsigned char*)&iSrcAddr;
	for(cPos = 0; cPos < 4; cPos++) {
		printf("%d", *((unsigned char*)pOff + cPos));
		if(cPos < 3) {
			printf(".");
		}
	}
	// Print the source-port.
	sSrcPort = sTCPHdr.source;	
	printf(":%d", ntohs(sSrcPort));

	printf(" -> ");

	// Output the destination-IP-address.
	pOff = (unsigned char*)&iDstAddr;
	for(cPos = 0; cPos < 4; cPos++) {
		printf("%d", *((unsigned char*)pOff + cPos));
		if(cPos < 3) {
			printf(".");
		}
	}

	// Print the destination-port.
	sDstPort = sTCPHdr.dest;	
	printf(":%d", ntohs(sDstPort));

	// Display the packet-flags.
	printf(" | (");
	if(sTCPHdr.urg) printf(" urg: %x", sTCPHdr.urg);
	if(sTCPHdr.ack) printf(" ack: %x", sTCPHdr.ack);
	if(sTCPHdr.psh) printf(" psh: %x", sTCPHdr.psh);
	if(sTCPHdr.rst) printf(" rst: %x", sTCPHdr.rst);
	if(sTCPHdr.syn) printf(" syn: %x", sTCPHdr.syn);
	if(sTCPHdr.fin) printf(" fin: %x", sTCPHdr.fin);
	printf(" )");

	printf("\n");
} // dump_packet

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
