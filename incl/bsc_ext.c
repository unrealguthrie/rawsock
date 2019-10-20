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
#include <sys/ioctl.h>
#include <net/if.h>

#include "bsc_ext.h"

/**
 * Dump a chunk of data into the terminal. Each character is display
 * as a hex-number and as a readable ASCII-character. Invalid characters
 * are replaced by dots.
 *
 * @param {void*} pAddr_ - The adress of the buffer to display
 * @param {int} iLen_ - The amount of bytes to display starting from the specified address
 */
void hexDump(void *pAddr_, int iLen_) {
    int i;
    unsigned char sBuf[17];
    unsigned char *pPtr = (unsigned char *)pAddr_;
	struct winsize w;
	int iConsCol;

	// Get the width of the terminal.
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	iConsCol = (w.ws_col < 80) ? (14) : (DUMP_LEN);	

    // Process every byte in the data.
    for (i = 0; i < iLen_; i++) {
        // Multiple of DUMP_LEN means new line (with line offset).
        if ((i % iConsCol) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                printf(" | %s\n", sBuf);
            }

            // Output the offset.
            printf("> %03x: ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pPtr[i]);

        // And store a printable ASCII character for later.
        // Replace invalid ACII characters with dots.
        if ((pPtr[i] < 0x20) || (pPtr[i] > 0x7e)) {
            sBuf[i % iConsCol] = '.';
        } else {
            sBuf[i % iConsCol] = pPtr[i];
        }

        // Add the null-byte at the end of the buffer.
        sBuf[(i % iConsCol) + 1] = '\0';
    }

    // Pad out last line if not exactly DUMP_LEN characters.
    while ((i % iConsCol) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf(" | %s\n", sBuf);
}  // hexDump

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
	iIPHdrLen = strip_ip_hdr(&sIPHdr, (pPckBuf_), (iPckLen_));
	strip_tcp_hdr(&sTCPHdr, (pPckBuf_ + iIPHdrLen), (iPckLen_ - iIPHdrLen));

	// Get the IP-addresses.
	iSrcAddr = sIPHdr.saddr;
	iDstAddr = sIPHdr.daddr;

	printf("[*]");

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
