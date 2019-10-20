#ifndef _BSC_EXT_H_
#define _BSC_EXT_H_

// ==== DEFINES ====
#ifndef DUMP_LEN
#define DUMP_LEN 16
#endif

// ==== DEFINE PROTOTYPES ====
void hexDump(void*, int);
void dump_packet(char*, int);
void show_interfaces();

#endif
