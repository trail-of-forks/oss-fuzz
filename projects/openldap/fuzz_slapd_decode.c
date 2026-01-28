/*
 * Harness: fuzz_slapd_decode
 *
 * TIER:    1 (Server-Exploitable - High Priority)
 * TESTS:   BER decoding through server entry point
 * PATH:    Network -> Sockbuf -> ber_get_next() -> various BER decoders
 * CONFIG:  sb_max_incoming = 262143 (256KB - unauthenticated default)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 *
 * This harness exercises various BER decoding functions through the
 * actual server entry point (ber_get_next). It tests low-level BER
 * decoding primitives based on the tag type of the input.
 *
 * Targets: ber_scanf(), ber_get_int(), ber_get_stringbv(),
 *          ber_peek_tag(), ber_skip_element(), ber_first_element()
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <lber.h>

/* Memory-backed Sockbuf I/O handlers */
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

static int sb_mem_ctrl(Sockbuf_IO_Desc *sbiod, int opt, void *arg) {
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

/* Maximum incoming message size (matches slapd default) */
#define MAX_INCOMING_SIZE (262143)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Sockbuf *sb = NULL;
    BerElement *ber = NULL;
    struct mem_buffer mb;
    ber_tag_t tag;
    ber_len_t len;

    if (size < 2 || size > MAX_INCOMING_SIZE) {
        return 0;
    }

    /* Set up memory buffer as socket input */
    mb.data = data;
    mb.size = size;
    mb.pos = 0;

    /* Create Sockbuf with security limits */
    sb = ber_sockbuf_alloc();
    if (!sb) return 0;

    ber_sockbuf_add_io(sb, &sb_mem_io, LBER_SBIOD_LEVEL_PROVIDER, &mb);

    {
        ber_len_t max = MAX_INCOMING_SIZE;
        ber_sockbuf_ctrl(sb, LBER_SB_OPT_SET_MAX_INCOMING, &max);
    }

    ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) {
        ber_sockbuf_free(sb);
        return 0;
    }

    /* Use ber_get_next - the actual server entry point */
    tag = ber_get_next(sb, &len, ber);

    if (tag == LBER_ERROR) {
        goto cleanup;
    }

    /* Successfully framed - test based on tag type */
    tag = ber_peek_tag(ber, &len);
    if (tag == LBER_DEFAULT) {
        goto cleanup;
    }

    /* Test type-specific decoders based on the tag */
    switch (tag) {
        case LBER_INTEGER:
        case 0x0a:  /* ENUMERATED */
            {
                ber_int_t intval;
                ber_get_int(ber, &intval);
            }
            break;

        case LBER_OCTETSTRING:  /* 0x04 */
            {
                struct berval str_bv;
                ber_get_stringbv(ber, &str_bv, LBER_BV_NOTERM);
            }
            break;

        case LBER_BOOLEAN:
            {
                ber_int_t boolval;
                ber_get_int(ber, &boolval);
            }
            break;

        case LBER_SEQUENCE:
        case LBER_SET:
            {
                /* Test sequence iteration */
                char *last = NULL;
                ber_len_t elem_len;
                ber_tag_t inner_tag;

                inner_tag = ber_first_element(ber, &elem_len, &last);

                int max_elements = 50;
                while (inner_tag != LBER_DEFAULT && max_elements-- > 0) {
                    struct berval inner_bv;
                    if (ber_skip_element(ber, &inner_bv) == LBER_DEFAULT) {
                        break;
                    }
                    inner_tag = ber_next_element(ber, &elem_len, last);
                }
            }
            break;

        default:
            /* For other tags, try ber_scanf patterns */
            if (tag & 0x20) {
                /* Constructed - try as sequence with content */
                ber_int_t i1;
                struct berval bv1;
                ber_tag_t inner_tag;

                /* Try common LDAP patterns */
                if (ber_scanf(ber, "{i", &i1) != LBER_ERROR) {
                    /* Got an integer, try to read more */
                    ber_peek_tag(ber, &len);
                }
            } else {
                /* Primitive - skip it */
                struct berval elem_bv;
                ber_skip_element(ber, &elem_bv);
            }
            break;
    }

cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
