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
    int fd = 0;
    unsigned int groupnumber = 0;
    Dwarf_Debug dbg;
    Dwarf_Error error;
    Dwarf_Handler errhand = NULL;
    Dwarf_Ptr errarg = NULL;

    // Create a temporary file for fuzzing
    char template[] = "/tmp/libdwarf_fuzzer_XXXXXX";
    fd = mkstemp(template);
    if (fd < 0)
    {
        perror("Error creating temporary file");
        return 0;
    }

    // Write the input data to the temporary file
    if (write(fd, Data, Size) != Size)
    {
        perror("Error writing data to temporary file");
        close(fd);
        unlink(template);
        return 0;
    }

    // Set the file descriptor position to the start of the file
    if (lseek(fd, 0, SEEK_SET) < 0)
    {
        perror("Error setting file descriptor position");
        close(fd);
        unlink(template);
        return 0;
    }

    // Call the function to be fuzzed
    dwarf_init_b(fd, groupnumber, errhand, errarg, &dbg, &error);

    // Clean up
    close(fd);
    unlink(template);

    return 0;
}