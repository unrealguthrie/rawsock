// ==== INCLUDES ====
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bsc_ext.h"

/**
 * Dump a chunk of data into the terminal. Each character is display
 * as a hex-number and as a readable ASCII-character. Invalid characters
 * are replaced by dots.
 *
 * @param {void*} pAddr_ - The adress of the data to display
 * @param {int} iLen_ - The amount of bytes to display starting from the specified address
 */
void hexDump(void *pAddr_, int iLen_) {
    int i;
    unsigned char sBuf[17];
    unsigned char *pPtr = (unsigned char *)pAddr_;

    // Process every byte in the data.
    for (i = 0; i < iLen_; i++) {
        // Multiple of DUMP_LEN means new line (with line offset).
        if ((i % DUMP_LEN) == 0) {
            // Just don't print ASCII for the zeroth line.
            if (i != 0) {
                printf(" | %s\n", sBuf);
            }

            // Output the offset.
            printf(" %03x: ", i);
        }

        // Now the hex code for the specific character.
        printf(" %02x", pPtr[i]);

        // And store a printable ASCII character for later.
        // Replace invalid ACII characters with dots.
        if ((pPtr[i] < 0x20) || (pPtr[i] > 0x7e)) {
            sBuf[i % DUMP_LEN] = '.';
        } else {
            sBuf[i % DUMP_LEN] = pPtr[i];
        }

        // Add the null-byte at the end of the buffer.
        sBuf[(i % DUMP_LEN) + 1] = '\0';
    }

    // Pad out last line if not exactly DUMP_LEN characters.
    while ((i % DUMP_LEN) != 0) {
        printf("   ");
        i++;
    }

    // And print the final ASCII bit.
    printf(" | %s\n", sBuf);
}  // hexDump
