#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/tcp.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "bsc_ext.h"
#include "packet.h"

/*
 * Dump a chunk of data into the terminal. Each character is display
 * as a hex-number and as a readable ASCII-character. Invalid characters
 * are replaced by dots.
 *
 * @buf: The adress of the buffer to display
 * @len: The amount of bytes to display starting from the specified address
 */
void hexDump(void *buf, int len)
{
    int i;
    unsigned char secbuf[17];
    unsigned char *ptr = (unsigned char *)buf;
	struct winsize w;
	int colnum;

	/* Get the width of the terminal */
	ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
	colnum = (w.ws_col < 80) ? (14) : (DUMP_LEN);	

    /* Process every byte in the data */
    for (i = 0; i < len; i++) {
        /* Multiple of DUMP_LEN means new line (with line offset) */
        if ((i % colnum) == 0) {
            /* Just don't print ASCII for the zeroth line */
            if (i != 0) {
                printf(" | %s\n", secbuf);
            }

            /* Output the offset */
            printf("> %03x: ", i);
        }

        /* Now the hex code for the specific character */
        printf(" %02x", ptr[i]);

        /* And store a printable ASCII character for later */
        /* Replace invalid ACII characters with dots */
        if ((ptr[i] < 0x20) || (ptr[i] > 0x7e)) {
            secbuf[i % colnum] = '.';
        } else {
            secbuf[i % colnum] = ptr[i];
        }

        /* Add the null-byte at the end of the buffer */
        secbuf[(i % colnum) + 1] = '\0';
    }

    /* Pad out last line if not exactly DUMP_LEN characters */
    while ((i % colnum) != 0) {
        printf("   ");
        i++;
    }

    /* And print the final ASCII bit */
    printf(" | %s\n", secbuf);
}

/*
 * A simple function to useful informations about a datagram,
 * into the terminal.
 *
 * @buf: The buffer containing the raw datagram
 * @len: The length of the packet-buffer in bytes
*/
void dump_packet(char *buf, int len)
{
	char pos = 0;
	struct iphdr ip_hdr;
	short ip_hdr_len;
	struct tcphdr tcp_hdr;
	unsigned char *off;
	uint32_t srcaddr, dstaddr;
	unsigned short srcport, dstport;

	/* Unwrap both headers */
	ip_hdr_len = strip_ip_hdr(&ip_hdr, buf, len);
	strip_tcp_hdr(&tcp_hdr, (buf + ip_hdr_len), (len - ip_hdr_len));

	/* Get the IP-addresses */
	srcaddr = ip_hdr.saddr;
	dstaddr = ip_hdr.daddr;

	printf("[*]");

	/* Ouput the source-IP-address */
	off = (unsigned char*)&srcaddr;
	for(pos = 0; pos < 4; pos++) {
		printf("%d", *((unsigned char*)off + pos));
		if(pos < 3) {
			printf(".");
		}
	}
	/* Print the source-port */
	srcport = tcp_hdr.source;	
	printf(":%d", ntohs(srcport));

	printf(" -> ");

	/* Output the destination-IP-address */
	off = (unsigned char*)&dstaddr;
	for(pos = 0; pos < 4; pos++) {
		printf("%d", *((unsigned char*)off + pos));
		if(pos < 3) {
			printf(".");
		}
	}

	/* Print the destination-port */
	dstport = tcp_hdr.dest;	
	printf(":%d", ntohs(dstport));

	/* Display the packet-flags */
	printf(" | (");
	if(tcp_hdr.urg) printf(" urg: %x", tcp_hdr.urg);
	if(tcp_hdr.ack) printf(" ack: %x", tcp_hdr.ack);
	if(tcp_hdr.psh) printf(" psh: %x", tcp_hdr.psh);
	if(tcp_hdr.rst) printf(" rst: %x", tcp_hdr.rst);
	if(tcp_hdr.syn) printf(" syn: %x", tcp_hdr.syn);
	if(tcp_hdr.fin) printf(" fin: %x", tcp_hdr.fin);
	printf(" )");

	printf("\n");
}
