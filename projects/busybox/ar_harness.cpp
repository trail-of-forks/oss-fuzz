#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <setjmp.h>

// Jump buffer for catching busybox exit() calls
static jmp_buf jump_buffer;
static bool jump_set = false;

// BusyBox headers
extern "C" {
    int ar_main(int argc, char **argv);

    // Stubs for appletlib symbols we excluded
    const char *applet_name = "ar";

    void bb_show_usage(void) {
        if (jump_set) {
            longjmp(jump_buffer, 1);
        }
    }

    int string_array_len(char **argv) {
        int count = 0;
        while (argv && argv[count]) count++;
        return count;
    }

    // Override xfunc_die to use longjmp instead of exit()
    void xfunc_die(void) {
        if (jump_set) {
            longjmp(jump_buffer, 1);
        }
        _exit(1);  // Fallback if jump not set
    }
}

// Temporary file counter for unique filenames
static int file_counter = 0;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    // Create unique temporary filenames
    char input_file[256];
    snprintf(input_file, sizeof(input_file), "/tmp/fuzz_ar_input_%d_%d", 
             getpid(), file_counter);
    file_counter++;

    // Write fuzzer input to a temporary file
    int fd = open(input_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return 0;
    }
    
    write(fd, data+2, size-2);
    close(fd);

    // Determine operation based on first byte
    uint8_t operation = data[0] % 3;
    uint8_t flags = data[1];
    
    // Build argv based on operation
    char *argv[8];
    int argc = 0;
    
    argv[argc++] = (char *)"ar";
    
    // Add operation flag
    switch (operation) {
        case 0: // Extract to stdout
            argv[argc++] = (char *)"p";
            break;
        case 1: // List contents
            argv[argc++] = (char *)"t";
            break;
        case 2: // Extract files
            argv[argc++] = (char *)"x";
            break;
    }

    // Add optional flags
    if (flags & 0x01) {
        argv[argc++] = (char *)"-v";  // Verbose
    }
    if (flags & 0x02) {
        argv[argc++] = (char *)"-o";  // Preserve original dates
    }
    
    // Add archive file
    argv[argc++] = input_file;
    
    argv[argc] = NULL;


    // Call the ar main function with setjmp to catch exit() calls
    jump_set = true;
    if (setjmp(jump_buffer) == 0) {
        ar_main(argc, argv);
    }
    // If we get here via longjmp, busybox tried to exit - that's fine
    jump_set = false;

    // Clean up temporary files
    unlink(input_file);

    return 0;
}
