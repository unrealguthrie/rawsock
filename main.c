/**
 * FILE: rawtcp_v1.c
 * SEND A MESSAGE VIA TCP/IP USING RAW SOCKETS
 * Julian Kennerknecht [Julian.kennerknecht@gmx.de]
 * 
 * The kernal automatically sends RST-packets to the other maschine,
 * and therefore interrupts the TCP-handshake. To prevtn that, you have
 * to run the following command, to stop the kernal from sending 
 * RST-apckets on it's own:
 * sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
 *
 * usage: ./rawtcp <Src-IP> <Src-Port> <Dest-IP> <Dest-Port>
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
void create_syn_packet(struct sockaddr_in*, struct sockaddr_in*, char**, int*);
void create_ack_packet(struct sockaddr_in*, struct sockaddr_in*, int32_t, int32_t, 
		char**, int*);
void create_psh_packet(struct sockaddr_in*, struct sockaddr_in*, int32_t, int32_t, 
		char*, int, char**, int*);
void create_fin_packet(struct sockaddr_in*, struct sockaddr_in*, int32_t, int32_t, 
		char**, int*);
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
	char recvbuf[DATAGRAM_LEN];
	uint32_t iSeqNum, iAckNum, iNewSeqNum;
	char request[] = "GET / HTTP/1.0\r\n\r\n";

	// Reset seed used for generating random numbers.
	srand(time(NULL));

	// Create a raw socket for communication.
	printf("Create raw socket...");
	iSockHdl = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (iSockHdl < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	// Configure the destination-IP-address.
	printf("Configure destination-ip...");
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(atoi(argv[4]));
	if (inet_pton(AF_INET, argv[3], &daddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Dest-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Configure the source-IP-address.
	printf("Configure source-ip...");
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &saddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Src-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	// Tell the kernel that headers are included in the packet.
	printf("Finalize socket configuration...");
	if (setsockopt(iSockHdl, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");
	printf("\n");

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// THE TCP-HANDSHAKE

	// Step 1: Send the SYN-packet.
	printf("Send SYN-pck...");
	create_syn_packet(&saddr, &daddr, &pPck, &iPckLen);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}
	printf("ok. (%d bytes)\n", iSent);

	// Step 2: Wait for the SYN-ACK-packet.
	printf("Waiting for SYN-ACK-pck...");
	int received = receive_packet(iSockHdl, recvbuf, sizeof(recvbuf), &saddr);
	if (received <= 0) {
		printf("failed.\n");
		exit(1);
	}
	printf("ok. (%d bytes)\n", received);

	// Read sequence number to acknowledge in next packet.
	read_seq_and_ack(recvbuf, &iSeqNum, &iAckNum);
	iNewSeqNum = iSeqNum + 1;

	// Step 3: Send the ACK-packet.
	// The previous seq-number is used as ack number and vica vera.
	printf("Send ACK-pck...");
	create_ack_packet(&saddr, &daddr, iAckNum, iNewSeqNum, &pPck, &iPckLen);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		exit(1);
	}
	printf("ok. (%d bytes)\n", iSent);

	// =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
	// SEND DATA USING TCP-SOCKET

	// Send data using the established connection.	
	printf("Send data to server...");
	create_psh_packet(&saddr, &daddr, iAckNum, iNewSeqNum, request, 
			sizeof(request) - 1 / sizeof(char), &pPck, &iPckLen);
	if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}
	printf("done. (%d byte)\n", iSent);
	printf("\n");

	int iTCPoff = 0;
	struct iphdr sIPHdr;
	struct tcphdr sTCPHdr;
	char* pDataOff;
	int iDataLen = 0;
	// struct sockaddr_in sSrcAddr, sDstAddr;
	short sSendPacket = 0;

	// Wait for the response from the server.
	while ((received = receive_packet(iSockHdl, recvbuf, sizeof(recvbuf), &saddr)) > 0) {
		printf("[RECV]: %d bytes:\n", received);
		//hexDump(recvbuf, received);
		// Extract the IP-header and remove the header-length. 
		iTCPoff = strip_ip_hdr(&sIPHdr, recvbuf, received);
		strip_tcp_hdr(&sTCPHdr, recvbuf + iTCPoff, received - iTCPoff, pDataOff, &iDataLen);

	 	hexDump(recvbuf, received);	
		hexDump(&sIPHdr, sizeof(struct iphdr));
		hexDump(&sTCPHdr, sizeof(struct tcphdr));

		printf("Source: %d - Destination: %d\n", ntohs(sTCPHdr.source), ntohs(sTCPHdr.dest));
		printf("Flags: [");
		if(sTCPHdr.urg) printf(" urg: %x", sTCPHdr.urg);
		if(sTCPHdr.ack) printf(" ack: %x", sTCPHdr.ack);
		if(sTCPHdr.psh) printf(" psh: %x", sTCPHdr.psh);
		if(sTCPHdr.rst) printf(" rst: %x", sTCPHdr.rst);
		if(sTCPHdr.syn) printf(" syn: %x", sTCPHdr.syn);
		if(sTCPHdr.fin) printf(" fin: %x", sTCPHdr.fin);
		printf(" ]\n");

		if(iDataLen > 0) {
			printf("Data-length: %d\n", iDataLen);
			char* pContentBuf = malloc(iDataLen + 1);
			memcpy(pContentBuf, recvbuf + iTCPoff + 20, iDataLen);
			//*(pContentBuf + iDataLen) = '\0';
			hexDump(pContentBuf, iDataLen);
			printf("\n");
		}

		read_seq_and_ack(recvbuf, &iSeqNum, &iAckNum);

		iNewSeqNum = (iSeqNum + 1);

		if(sTCPHdr.fin == 1) {
			create_fin_packet(&saddr, &daddr, iAckNum, iNewSeqNum, &pPck, &iPckLen);
			sSendPacket = 1;
		}
		else if(sTCPHdr.psh == 1) {
			create_ack_packet(&saddr, &daddr, iAckNum, iNewSeqNum, &pPck, &iPckLen);
			sSendPacket = 1;
		}
		if(sSendPacket) {
			if ((iSent = sendto(iSockHdl, pPck, iPckLen, 0, (struct sockaddr*)&daddr, 
						sizeof(struct sockaddr))) < 0) {
				printf("send failed\n");
			} 
			else {
				printf("successfully sent %d bytes ACK!\n", iSent);
				sSendPacket = 0;
				if(sTCPHdr.fin == 1) {
					break;
				}
			}
		}
	}

	// Close the socket.
	close(iSockHdl);
	return (0);
}  // main

// ==== DEFINE FUNCTIONS ====
/** 
 *
*/
void setup_base_packet() {

} // setup_base_packet

/**
 * Setup a valid SYN-packet, used to start the TCP-handshake with the server.
 * Because the client is using raw sockets, both the TCP- and IP-header have
 * to be generated manually.
 *
 * @param {struct sockaddr_in*} pSrc_ - A pointer to the source-ip-address
 * @param {struct sockaddr_in*} pDst_ - A poinzer to the destination-ip-address
 * @param {char**} pOutPacker_ - A address to the packet-memory
 */
void create_syn_packet(struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_,
		char** pOutPacket_, int* pOutPacketLen_) {
	// Reserve empty space to store the datagram(memory already filled with zeros).
	char* datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Required structs for IP and TCP header.
	struct iphdr* iph = (struct iphdr*)datagram;
	struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));

	// Configure the IP-header.
	setup_ip_hdr(iph, pSrc_, pDst_, 0);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);
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

	// Calculate the checksum for the IP- and TCP-header.
	// tcph->check = in_cksum((const char*)pseudogram, psize);
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, 0);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;
}  // create_syn_packet

/**
 * Create the ACK-packet to complete the TCP-handshake.
 */
void create_ack_packet(struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_,
		int32_t iSeq_, int32_t iAckSeq_, char** pOutPacket_,
		int* pOutPacketLen_) {
	// Datagram to represent the packet.
	char* datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Required structs for IP and TCP header.
	struct iphdr* iph = (struct iphdr*)datagram;
	struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));

	// Configure the IP-header.    
	setup_ip_hdr(iph, pSrc_, pDst_, 0);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);
	tcph->seq = htonl(iSeq_);
	tcph->ack_seq = htonl(iAckSeq_);
	tcph->ack = 1;

	// Calculate the checksum for the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, 0);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	// Set packet-content.
	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;
}  // create_ack_packet

/**
 * Create the PSH-packet and send data to the other maschine.
 */
void create_psh_packet(struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_,
		int32_t iSeq_, int32_t iAckSeq_, char* pData_,
		int iDataLen_, char** pOutPacket_,
		int* pOutPacketLen_) {
	// Create a datagram to represent the packet.
	char* datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Create the required structs for IP- and TCP-header.
	struct iphdr* iph = (struct iphdr*)datagram;
	struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));

	// Set payload.
	char* payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	memcpy(payload, pData_, iDataLen_);

	// Configure the IP-header.
	setup_ip_hdr(iph, pSrc_, pDst_, iDataLen_);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);
	tcph->seq = htonl(iSeq_);
	tcph->ack_seq = htonl(iAckSeq_);
	tcph->psh = 1;
	tcph->ack = 1;

	// Calculate the checksum for the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, iDataLen_);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	// Set packet-content.
	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;
}  // create_psh_packet

/**
 *   
*/
void create_fin_packet(struct sockaddr_in* pSrc_, struct sockaddr_in* pDst_,
		int32_t iSeq_, int32_t iAckSeq_, char** pOutPacket_,
		int* pOutPacketLen_) {
	// Create a datagram to represent the packet.
	char* datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// Create the required structs for IP- and TCP-header.
	struct iphdr* iph = (struct iphdr*)datagram;
	struct tcphdr* tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));

	// Configure the IP-header.
	setup_ip_hdr(iph, pSrc_, pDst_, 0);

	// Configure the TCP-header.
	setup_tcp_hdr(tcph, pSrc_->sin_port, pDst_->sin_port);
	tcph->seq = htonl(iSeq_);
	tcph->ack_seq = htonl(iAckSeq_);
	tcph->ack = 1;
	tcph->fin = 1;
	// Calculate the checksum for the IP- and TCP-header.
	tcph->check = in_cksum_tcp(tcph, pSrc_, pDst_, 0);
	iph->check = in_cksum((char*)datagram, iph->tot_len);

	// Set packet-content.
	*pOutPacket_ = datagram;
	*pOutPacketLen_ = iph->tot_len;

} // create_fin_packet

/**
 *
 */
void read_seq_and_ack(const char* pPacket_, uint32_t* pSeq_, uint32_t* pAck_) {
	uint32_t iSeqNum, iAckNum;
	// Read sequence number.
	memcpy(&iSeqNum, pPacket_ + 24, 4);
	// Read acknowledgement number.
	memcpy(&iAckNum, pPacket_ + 28, 4);
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
