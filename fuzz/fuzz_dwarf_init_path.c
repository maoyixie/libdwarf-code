#include <fcntl.h> /* open() O_RDONLY O_BINARY */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Libdwarf library callers can only use these headers.
 */
#include "dwarf.h"
#include "libdwarf.h"

extern int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
{
    // Copy input data into a null-terminated buffer
    char *dw_path = (char *)malloc(Size + 1);
    if (dw_path == NULL)
    {
        return 0;
    }
    memcpy(dw_path, Data, Size);
    dw_path[Size] = '\0';

    // Create other required parameters for dwarf_init_path
    char dw_true_path_out_buffer[1024];
    unsigned int dw_true_path_bufferlen = sizeof(dw_true_path_out_buffer);
    unsigned int dw_groupnumber = 0;
    Dwarf_Handler dw_errhand = NULL;
    Dwarf_Ptr dw_errarg = NULL;
    Dwarf_Debug dw_dbg = NULL;
    Dwarf_Error dw_error = NULL;

    // Call the function to be fuzzed
    int result = dwarf_init_path(dw_path, dw_true_path_out_buffer, dw_true_path_bufferlen, dw_groupnumber, dw_errhand, dw_errarg, &dw_dbg, &dw_error);

    // Free resources
    free(dw_path);

    // Return the result
    return result;
}