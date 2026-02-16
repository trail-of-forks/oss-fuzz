/*
 * Harness: fuzz_liblber_sockbuf_decode
 *
 * TIER:    2 (BER wire-format parsing, shared between client and server)
 * TESTS:   BER primitive decoding through Sockbuf I/O layer
 * PATH:    Sockbuf -> ber_get_next() -> type-specific BER decoders
 * CONFIG:  sb_max_incoming = 262143 (256KB - matches slapd unauthenticated default)
 *
 * Tests BER framing and decoding through Sockbuf, then exercises
 * type-specific BER decoders based on the tag: ber_get_int(),
 * ber_get_stringbv(), ber_peek_tag(), ber_skip_element(),
 * ber_first_element().
 *
 * Note: This harness links against libldap/liblber client libraries.
 * slapd server code is NOT compiled or tested here.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include <lber.h>

#include "sockbuf_mem.h"

/* Maximum incoming message size (matches slapd unauthenticated default) */
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

    mb.data = data;
    mb.size = size;
    mb.pos = 0;

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

    /* Read and validate BER framing via Sockbuf */
    tag = ber_get_next(sb, &len, ber);

    if (tag == LBER_ERROR) {
        goto cleanup;
    }

    /* Test type-specific decoders based on the tag */
    tag = ber_peek_tag(ber, &len);
    if (tag == LBER_DEFAULT) {
        goto cleanup;
    }

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
            if (tag & 0x20) {
                /* Constructed - try as sequence with content */
                ber_int_t i1;

                if (ber_scanf(ber, "{i", &i1) != LBER_ERROR) {
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
