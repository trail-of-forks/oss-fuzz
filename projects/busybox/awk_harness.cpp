#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <setjmp.h>
#include <errno.h>

// Jump buffer for catching busybox exit() calls
static jmp_buf jump_buffer;
static bool jump_set = false;

// BusyBox headers
extern "C" {
    int awk_main(int argc, char **argv);

    extern int *bb_errno;
    int *get_perrno(void) {
        bb_errno = &errno;
        return bb_errno;
    }

    // Stubs for appletlib symbols we excluded
    const char *applet_name = "awk";

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

    void xfunc_die(void) {
        if (jump_set) {
            longjmp(jump_buffer, 1);
        }
        _exit(1);
    }

    // Intercept exit() calls from awk_exit() which calls exit() directly.
    // Without this, awk_exit() would terminate the entire fuzzer process.
    void __real_exit(int status);
    void __wrap_exit(int status) {
        if (jump_set) {
            longjmp(jump_buffer, 1);
        }
        __real_exit(status);
    }
}

static int file_counter = 0;
static int max_fd_at_init = -1;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    // One-time: record the highest open FD at startup so we can close
    // any FDs leaked by awk without closing libFuzzer's own FDs.
    if (max_fd_at_init == -1) {
        for (int i = 1023; i >= 0; i--) {
            if (fcntl(i, F_GETFD) != -1) {
                max_fd_at_init = i;
                break;
            }
        }
        if (max_fd_at_init < 2) max_fd_at_init = 2;
    }

    // Use first byte to determine where to split data into program vs input
    uint8_t split_pct = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    // Split payload into awk program and input data
    size_t prog_size = (payload_size * split_pct) / 256;
    if (prog_size == 0) prog_size = 1;
    if (prog_size >= payload_size) prog_size = payload_size - 1;

    // Create unique temporary filenames
    char input_file[256];
    char prog_file[256];
    int pid = getpid();
    snprintf(input_file, sizeof(input_file), "/tmp/fuzz_awk_input_%d_%d",
             pid, file_counter);
    snprintf(prog_file, sizeof(prog_file), "/tmp/fuzz_awk_prog_%d_%d",
             pid, file_counter);
    file_counter++;

    // Write input data to a temporary file
    int fd = open(input_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return 0;
    }
    write(fd, payload + prog_size, payload_size - prog_size);
    close(fd);

    // Write awk program to a file
    fd = open(prog_file, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        unlink(input_file);
        return 0;
    }
    write(fd, payload, prog_size);
    close(fd);

    // Build argv: awk -f <program_file> <input_file>
    char *argv[] = {
        (char *)"awk",
        (char *)"-f", prog_file,
        input_file,
        NULL
    };
    int argc = 4;

    // Redirect stdout/stderr to /dev/null to reduce noise
    int saved_stdout = dup(STDOUT_FILENO);
    int saved_stderr = dup(STDERR_FILENO);
    int devnull = open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
        dup2(devnull, STDOUT_FILENO);
        dup2(devnull, STDERR_FILENO);
        close(devnull);
    }

    get_perrno();

    // Call awk_main. INIT_G() inside allocates fresh zeroed globals, so each
    // call starts with clean state. __wrap_exit catches awk_exit()'s exit()
    // call via longjmp, keeping the fuzzer process alive.
    jump_set = true;
    if (setjmp(jump_buffer) == 0) {
        awk_main(argc, argv);
    }
    jump_set = false;

    // Restore stdout/stderr
    dup2(saved_stdout, STDOUT_FILENO);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stdout);
    close(saved_stderr);

    // Note: we intentionally do NOT free ptr_to_globals here.
    // SET_OFFSET_PTR_TO_GLOBALS stores ptr_to_globals at an offset from the
    // xzalloc result, so free(ptr_to_globals) would be a bad-free. Sub-
    // allocations (hash tables, parsed nodes) also leak. This is tolerated
    // via detect_leaks=0; the RSS limit restarts the fuzzer when needed.
    // Each call to INIT_G() in awk_main allocates fresh zeroed globals,
    // so the next iteration starts with clean state regardless.

    // Close any file descriptors leaked by awk (pipes, redirections, etc.)
    // that weren't cleaned up due to longjmp. Only close FDs above the
    // startup baseline to avoid closing libFuzzer's internal FDs.
    for (int i = max_fd_at_init + 1; i < 1024; i++) {
        close(i);
    }

    // Clean up temporary files
    unlink(input_file);
    unlink(prog_file);

    return 0;
}
