#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#include "arp_packet.h"

/*
 * Converts struct sockaddr with an IPv4 address to network byte order uin32_t.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {struct sockaddr*} pAddr_ - The address to convert
 * @param {uint32_t*} iIP_ - Buffer containing address in network byte order
 */
int int_ip4(struct sockaddr* pAddr_, uint32_t* pIP_) {
    if (pAddr_->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) pAddr_;
        *pIP_ = i->sin_addr.s_addr;
        return (0);
    } else {
        return (1);
    }
} // int_ip4

/*
 * Formats sockaddr containing IPv4 address as human readable string.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {struct sockaddr*} pAddr_ - The address to convert
 * @param {char*} pOut_ - The output buffer
 */
int format_ip4(struct sockaddr* pAddr_, char* pOut_) {
    if (pAddr_->sa_family == AF_INET) {
        struct sockaddr_in *pAddrPtr = (struct sockaddr_in *) pAddr_;
        const char* pIP = inet_ntoa(pAddrPtr->sin_addr);
        if (!pIP) {
            return (-2);
        } else {
            strcpy(pOut_, pIP);
            return (0);
        }
    } else {
        return (-1);
    }
} // format_ip4

/*
 * Writes interface IPv4 address as network byte order to ip.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {int} iFd_ - The socket-handler
 * @param {const char*} pIfName_ - The interface-name
 * @param {uint32_t*} pIP_ - Pointer to write IP-address to
 */
int get_if_ip4(int iFd_, const char* pIfName_, uint32_t* pIP_) {
    int err = -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(pIfName_) > (IFNAMSIZ - 1)) {
        goto out;
    }

    strcpy(ifr.ifr_name, pIfName_);
    if (ioctl(iFd_, SIOCGIFADDR, &ifr) == -1) {
        goto out;
    }

    if (int_ip4(&ifr.ifr_addr, pIP_)) {
        goto out;
    }
    err = 0;
out:
    return (err);
} // get_if_ip4

/*
 * Sends an ARP who-has request to dst_ip on interface ifindex, 
 * using source mac src_mac and source ip src_ip.
 *
 * @returns {int} Returns 0 on success
 *
 * @param {int} iFd_ - The socket-handler
 * @param {int] iIfIndex_ - Index of the interface in use
 * @param {const unsigned char*} pSrcMax_ - The source-MAC-address
 * @param {uint32_t} iSrcIP_ - The source-IP-address
 * @param {uint32_t} iDstIP_ - The destination-IP-address
 */
int send_arp(int iFd_, int iIfIndex_, const unsigned char* pSrcMac_, uint32_t iSrcIP_, uint32_t iDstIP_) {
    int err = -1;
    unsigned char buffer[BUF_SIZE];
    memset(buffer, 0, sizeof(buffer));

    struct sockaddr_ll socket_address;
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = iIfIndex_;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = (PACKET_BROADCAST);
    socket_address.sll_halen = MAC_LENGTH;
    socket_address.sll_addr[6] = 0x00;
    socket_address.sll_addr[7] = 0x00;

    struct ethhdr *send_req = (struct ethhdr *) buffer;
    struct arp_header *arp_req = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    ssize_t ret;

    //Broadcast
    memset(send_req->h_dest, 0xff, MAC_LENGTH);

    //Target MAC zero
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);

    //Set source mac to our MAC address
    memcpy(send_req->h_source, pSrcMac_, MAC_LENGTH);
    memcpy(arp_req->sender_mac, pSrcMac_, MAC_LENGTH);
    memcpy(socket_address.sll_addr, pSrcMac_, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(HW_TYPE);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);

    memcpy(arp_req->sender_ip, &iSrcIP_, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &iDstIP_, sizeof(uint32_t));

    ret = sendto(iFd_, buffer, 42, 0, (struct sockaddr *) &socket_address, sizeof(socket_address));
    if (ret == -1) {
        printf("ERROR: Couldn't send data.\n");
        goto out;
    }
    err = 0;
out:
    return (err);
} // send_arp

/*
 * Gets interface information by name:
 * IPv4, MAC, ifindex
 *
 * @returns {int} Returns 0 on success
 *
 * @param {const char*} pIfName_ - Name of the interface
 * @param {uint32_t*} pIP_ - Memory to write IP-address to
 * @param {char*} pMAC_ - Memory to write MAC-address to
 * @param {int*} pIfIndex_ - Memory to write interface-index to
 */
int get_if_info(const char* pIfName_, uint32_t* pIP_, char* pMAC_, int* pIfIndex_) {
    int err = -1;
    struct ifreq ifr;
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        goto out;
    }
    if (strlen(pIfName_) > (IFNAMSIZ - 1)) {
        goto out;
    }

    strcpy(ifr.ifr_name, pIfName_);

    // Get interface index using name.
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        goto out;
    }
    *pIfIndex_ = ifr.ifr_ifindex;

    // Get MAC address of the interface.
    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        goto out;
    }

    //Copy mac address to output
    memcpy(pMAC_, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, pIfName_, pIP_)) {
        goto out;
    }

    err = 0;
out:
    if (sd > 0) {
        close(sd);
    }
    return (err);
} // get_if_info

/*
 * Creates a raw socket that listens for ARP traffic on specific ifindex.
 * Writes out the socket's FD.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {int} iIfIndex_ - The interface-index
 * @param {int*} pFd_ - The socket-handler
 */
int bind_arp(int iIfIndex_, int* pFd_) {
    int ret = -1;

    // Submit request for a raw socket descriptor.
    *pFd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*pFd_ < 1) {
        perror("socket()");
        goto out;
    }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(struct sockaddr_ll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = iIfIndex_;
    if (bind(*pFd_, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        goto out;
    }

    ret = 0;
out:
    if (ret && *pFd_ > 0) {
        close(*pFd_);
    }
    return (ret);
} // bind_arp

/*
 * Reads a single ARP reply from fd.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {int} iFd_ - The socket-handler
 */
int read_arp(int iFd_, char* pAddrBuf_) {
    int ret = -1;
    unsigned char buffer[BUF_SIZE];
    ssize_t length = recvfrom(iFd_, buffer, BUF_SIZE, 0, NULL, NULL);
    if (length == -1) {
        perror("recvfrom()");
        goto out;
    }
    struct ethhdr *rcv_resp = (struct ethhdr *) buffer;
    struct arp_header *arp_resp = (struct arp_header *) (buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP) {
        goto out;
    }
    if (ntohs(arp_resp->opcode) != ARP_REPLY) {
        goto out;
    }
    struct in_addr sender_a;
    memset(&sender_a, 0, sizeof(struct in_addr));
    memcpy(&sender_a.s_addr, arp_resp->sender_ip, sizeof(uint32_t));

	memcpy(pAddrBuf_, &arp_resp->sender_mac, 6);
    ret = 0;

out:
    return (ret);
} // read_arp

/*
 *
 * Sample code that sends an ARP who-has request on
 * interface <pIfName_> to IPv4 address <pIP_>.
 * 
 * @returns {int} Returns 0 on success
 *
 * @param {const char*} pIfName_ - The interface-name
 * @param {const char*} pIP_ - The IP-address to get MAC-address from
 */
int get_mac(const char* pIfName_, const char* pIP_, char* pAddrBuf_) {
    int ret = -1;
    uint32_t dst = inet_addr(pIP_);
    if (dst == 0 || dst == 0xffffffff) {
        return (1);
    }

    uint32_t src;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(pIfName_, &src, mac, &ifindex)) {
        goto out;
    }
    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        goto out;
    }

	// If the host is searching for itself.
	if(memcmp((void*)&src, (void*)&dst, 4) == 0) {
		memcpy(pAddrBuf_, mac, 8);
		ret = 0;
		goto out;
	}

    if (send_arp(arp_fd, ifindex, (unsigned char*)mac, src, dst)) {
        goto out;
    }

    while(1) {
        int r = read_arp(arp_fd, pAddrBuf_);
        if (r == 0) {
            break;
        }
    }

    ret = 0;
out:
    if (arp_fd) {
        close(arp_fd);
        arp_fd = 0;
    }
    return (ret);
} // get_mac
