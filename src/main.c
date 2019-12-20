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
#include <sys/ioctl.h>
#include <net/if.h>

#include "bsc_ext.h"
#include "packet.h"

/* Recevive data and write to buffer */
int receive_packet(int sockfd, char *buf, size_t len, struct sockaddr_in *dst);

int main(int argc, char **argv) 
{
	int sockfd;
	int sent;
    int	one  = 1;
	short sSendPacket = 0;
	
	/* The IP-addresses of both maschines in the connections */
	struct sockaddr_in srcaddr;
	struct sockaddr_in dstaddr;
	
	/* The buffer containing the raw datagram, both when it is */
	/* received and send. */
	char* pckbuf;
	int pckbuflen;

	/* The buffer filled with the information to create the packet. */
	/* The buffer will be filled like that: Seq + Ack [ + Payload ] */
	/* So by default without the payload, it is 8 bytes long. */
	char* databuf;
	int databuflen = 0;

	/* Both numbers used to identify the send packets */
	uint32_t seqnum;
	uint32_t acknum;

	/* The payload contained in the packet */
	char* pld;
	int pldlen;

	/* Buffers used when taking apart the received datagrams */
	struct iphdr ip_hdr;
	struct tcphdr tcp_hdr;

	/* Check if all necessary parameters have been set by the user */
	if (argc < 5) {
		printf("usage: %s <src-ip> <src-port> <dest-ip> <dest-port>\n", argv[0]);
		exit (1);
	}

	/* Reserve memory for the datagram */
	pckbuf = calloc(DATAGRAM_LEN, sizeof(char));

	/* Initialize the data-buffer */
	databuf = malloc(520);

	/* Set the payload intended to be send using the connection */
	pld = malloc(512);
	strcpy(pld, "Data send.");
	pldlen = (strlen(pld) / sizeof(char));


	/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
	/* SETUP SOCKET                                                  */

	printf("SETUP:\n");

	/* Create a raw socket for communication and store socket-handler */
	printf(" Create raw socket...");
	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	/* Configure the destination-IP-address */
	printf(" Configure destination-ip...");
	dstaddr.sin_family = AF_INET;
	dstaddr.sin_port = htons(atoi(argv[4]));
	if (inet_pton(AF_INET, argv[3], &dstaddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Dest-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	/* Configure the source-IP-address */
	printf(" Configure source-ip...");
	srcaddr.sin_family = AF_INET;
	srcaddr.sin_port = htons(atoi(argv[2]));
	if (inet_pton(AF_INET, argv[1], &srcaddr.sin_addr) != 1) {
		printf("failed.\n");
		perror("Src-IP invalid:");
		exit (1);
	}
	printf("done.\n");

	/* Tell the kernel that headers are included in the packet */
	printf(" Configure socket...");
	if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		printf("failed.\n");
		perror("ERROR:");
		exit (1);
	}
	printf("done.\n");

	printf("\n");
	printf("COMMUNICATION:\n");

	/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
 	/* THE TCP-HANDSHAKE                                             */

	/* Step 1: Send the SYN-packet */
	memset(pckbuf, 0, DATAGRAM_LEN);
	create_raw_datagram(pckbuf, &pckbuflen, SYN_PACKET, &srcaddr, &dstaddr, NULL, 0);
	dump_packet(pckbuf, pckbuflen);
	if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
	}

	/* Step 2: Wait for the SYN-ACK-packet */
	pckbuflen = receive_packet(sockfd, pckbuf, DATAGRAM_LEN, &srcaddr);
	dump_packet(pckbuf, pckbuflen);
	if (pckbuflen <= 0) {
		printf("failed.\n");
		exit(1);
	}

	/* Update seq-number and ack-number */
	update_seq_and_ack(pckbuf, &seqnum, &acknum);
	
	/* Step 3: Send the ACK-packet, with updated numbers */
	memset(pckbuf, 0, DATAGRAM_LEN);
	gather_packet_data(databuf, &databuflen, seqnum, acknum, NULL, 0);
	create_raw_datagram(pckbuf, &pckbuflen, ACK_PACKET, &srcaddr, &dstaddr, databuf, databuflen);
	dump_packet(pckbuf, pckbuflen);
	if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("failed.\n");
		exit(1);
	}
	free(databuf);

	/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
	/* SEND DATA USING TCP-SOCKET                                    */

	/* Send data using the established connection */
	gather_packet_data(databuf, &databuflen, seqnum, acknum, pld, pldlen);
	create_raw_datagram(pckbuf, &pckbuflen, PSH_PACKET, &srcaddr, &dstaddr, databuf, databuflen);	
	dump_packet(pckbuf, pckbuflen);
	if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr, 
					sizeof(struct sockaddr))) < 0) {
		printf("send failed\n");
		return(1);
	}


	/* Wait for the response from the server */
	while ((pckbuflen = receive_packet(sockfd, pckbuf, DATAGRAM_LEN, &srcaddr)) > 0) {
		/* Display packet-info in the terminal */
		dump_packet(pckbuf, pckbuflen);

		/* Deconstruct the packet and extract payload */
		strip_raw_packet(pckbuf, pckbuflen, &ip_hdr, &tcp_hdr, pld, &pldlen);

		/* Dump payload in the terminal, if there is any */
		if(pldlen > 0) {
			hexDump(pld, pldlen);
			printf("Dumped %d bytes.\n", pldlen);
		}

		/* Update ack-number and seq-numbers */
		update_seq_and_ack(pckbuf, &seqnum, &acknum);

		sSendPacket = 0;
		if(tcp_hdr.fin == 1) {
			sSendPacket = FIN_PACKET;
		}
		else if(tcp_hdr.psh == 1 || (tcp_hdr.ack == 1 && databuflen > 0)) {
			sSendPacket = ACK_PACKET;
		}
		if(sSendPacket != 0) {
			/* Create the response-packet */
			gather_packet_data(databuf, &databuflen, seqnum, acknum, NULL, 0);
			create_raw_datagram(pckbuf, &pckbuflen, sSendPacket, &srcaddr, &dstaddr, databuf, 8);
			dump_packet(pckbuf, pckbuflen);
			free(databuf);

			if ((sent = sendto(sockfd, pckbuf, pckbuflen, 0, (struct sockaddr*)&dstaddr, 
						sizeof(struct sockaddr))) < 0) {
				printf("send failed\n");
			} 
			else {
				sSendPacket = 0;
				if(tcp_hdr.fin == 1) {
					break;
				}
			}
		}
	}

	printf("\n");

	/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */
	/* CLEAN-UP THE SCRIPT                                           */
	
	printf("CLEAN-UP:\n");

	/* Close the socket */
	printf(" Close socket...");
	close(sockfd);
	printf("done.\n");

	return (0);
}

/*
 * Recieve a short packet using a given socket and write the data to a buffer.
 *
 * @sockfd: The sockets to receive packets with
 * @buf: A buffer to write to
 * @len: The length of the buffer
 *
 * Returns: The amount of bytes received
 */
int receive_packet(int sockfd, char *buf, size_t len, struct sockaddr_in *dst) 
{
	unsigned short dst_port;
	int recvlen;

	/* Clear the memory used to store the datagram */
	memset(buf, 0, len);

	do {
		recvlen = recvfrom(sockfd, buf, len, 0, NULL, NULL);
		if (recvlen <= 0) {
			break;
		}
		memcpy(&dst_port, buf + 22, sizeof(dst_port));
	} while (dst_port != dst->sin_port);

	/* Return the amount of recieved bytes */
	return (recvlen);
}
