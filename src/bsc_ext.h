#ifndef _BSC_EXT_H_
#define _BSC_EXT_H_

#ifndef DUMP_LEN
#define DUMP_LEN 16
#endif

/* Dump a buffer into terminal */
void hexDump(void *buf, int len);

/* Dump a raw packet into the terminal */
void dump_packet(char *buf, int len);

#endif
