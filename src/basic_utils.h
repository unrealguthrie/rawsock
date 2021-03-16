#ifndef _BASIC_UTILS_H
#define _BASIC_UTILS_H

#ifndef DUMP_LEN
#define DUMP_LEN 16
#endif

/*
 * Dump a chunk of data into the terminal. Each character is display
 * as a hex-number and as a readable ASCII-character. Invalid characters
 * are replaced by dots.
 *
 * @buf: The adress of the buffer to display
 * @len: The amount of bytes to display starting from the specified address
 */
void hexDump(void *buf, int len);


/*
 * A simple function to display useful informations about a datagram in the
 * terminal.
 *
 * @buf: The buffer containing the raw datagram
 * @len: The length of the packet-buffer in bytes
 */
void dump_packet(char *buf, int len);

#endif /* _BASIC_UTILS_H */
