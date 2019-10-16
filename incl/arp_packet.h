// ==== DEFINES ====
#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define HW_TYPE 1
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

// ==== DEFINE STRUCTS ====
struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

// ==== DEFINE PROTOTYPES ====
int int_ip4(struct sockaddr*, uint32_t*);
int format_ip4(struct sockaddr*, char*);
int get_if_ip4(int, const char*, uint32_t*);
int send_arp(int, int, const unsigned char*, uint32_t, uint32_t);
int get_if_info(const char*, uint32_t*, char*, int*);
int bind_arp(int, int*);
int read_arp(int, char*);
int get_mac(const char*, const char*, char*);

