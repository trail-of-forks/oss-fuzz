/*
 * sockbuf_mem.h — Memory-backed Sockbuf I/O layer for fuzzing
 *
 * Provides a Sockbuf_IO implementation that reads from an in-memory
 * buffer instead of a real socket. Used by all BER wire-format
 * fuzzing harnesses to feed data through ber_get_next().
 *
 * This is the I/O layer shared by slapd and libldap clients.
 */

#ifndef SOCKBUF_MEM_H
#define SOCKBUF_MEM_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <lber.h>

struct mem_buffer {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static int sb_mem_setup(Sockbuf_IO_Desc *sbiod, void *arg) {
    sbiod->sbiod_pvt = arg;
    return 0;
}

static int sb_mem_remove(Sockbuf_IO_Desc *sbiod) {
    return 0;
}

static ber_slen_t sb_mem_read(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len) {
    struct mem_buffer *mb = sbiod->sbiod_pvt;
    size_t remaining = mb->size - mb->pos;
    size_t to_read = (len < remaining) ? len : remaining;

    if (to_read == 0) {
        return 0;  /* EOF */
    }

    memcpy(buf, mb->data + mb->pos, to_read);
    mb->pos += to_read;
    return to_read;
}

static ber_slen_t sb_mem_write(Sockbuf_IO_Desc *sbiod, void *buf, ber_len_t len) {
    return len;  /* Discard writes */
}

/*
 * Handle Sockbuf control operations.
 *
 * LBER_SB_OPT_DATA_READY is queried by ber_get_next() to check if
 * more data is available without blocking. We must return 1 when
 * unread data remains, otherwise ber_get_next() may return early
 * without parsing, silently reducing coverage.
 */
static int sb_mem_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg) {
    if (opt == LBER_SB_OPT_DATA_READY) {
        struct mem_buffer *mb = sbiod->sbiod_pvt;
        return (mb->pos < mb->size) ? 1 : 0;
    }
    return 0;
}

static int sb_mem_close(Sockbuf_IO_Desc *sbiod) {
    return 0;
}

static Sockbuf_IO sb_mem_io = {
    sb_mem_setup,
    sb_mem_remove,
    sb_mem_ctrl,
    sb_mem_read,
    sb_mem_write,
    sb_mem_close
};

#endif /* SOCKBUF_MEM_H */
