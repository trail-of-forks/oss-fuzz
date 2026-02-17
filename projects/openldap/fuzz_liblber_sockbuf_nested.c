/*
 * Harness: fuzz_liblber_sockbuf_nested
 *
 * TIER:    3 (Client Library - BER recursive structure parsing)
 * TESTS:   Deeply nested BER structure parsing through Sockbuf I/O layer
 * PATH:    Sockbuf -> ber_get_next() -> recursive BER element traversal
 * CONFIG:  sb_max_incoming = 262143 (256KB - matches slapd unauthenticated default)
 *
 * Tests BER framing through Sockbuf, then exercises recursive BER
 * structure parsing. Targets deep nesting (SEQUENCE within SEQUENCE),
 * LDAP filter-like structures (context-specific tags [0]-[9]),
 * and bounds checking on nested element traversal.
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

/* Maximum recursion depth to prevent stack overflow under ASan */
#define MAX_DEPTH 32

/*
 * Recursively parse BER elements, similar to how LDAP filters
 * are processed. This exercises nested SEQUENCE/SET handling.
 */
static void parse_recursive(BerElement *ber, int depth) {
    ber_tag_t tag;
    ber_len_t len;

    if (depth > MAX_DEPTH) {
        return;
    }

    tag = ber_peek_tag(ber, &len);
    if (tag == LBER_DEFAULT) {
        return;
    }

    if (tag & 0x20) {
        /* Constructed: SEQUENCE, SET, or context-specific constructed */
        char *last = NULL;
        ber_len_t elem_len;

        tag = ber_first_element(ber, &elem_len, &last);

        int max_elements = 20;
        while (tag != LBER_DEFAULT && max_elements-- > 0) {
            parse_recursive(ber, depth + 1);
            tag = ber_next_element(ber, &elem_len, last);
        }
    } else {
        /* Primitive: skip the element */
        struct berval bv;
        ber_skip_element(ber, &bv);
    }
}

/*
 * Parse LDAP filter-like context-specific tagged structures.
 * LDAP filters use tags [0]-[9] for AND, OR, NOT, equality, etc.
 */
static void parse_filter_like(BerElement *ber) {
    ber_tag_t tag;
    ber_len_t len;

    tag = ber_peek_tag(ber, &len);
    if (tag == LBER_DEFAULT) {
        return;
    }

    if ((tag & 0xc0) == 0x80) {  /* Context-specific class */
        int tag_num = tag & 0x1f;

        switch (tag_num) {
            case 0:  /* AND - SET OF Filter */
            case 1:  /* OR - SET OF Filter */
                {
                    char *last = NULL;
                    ber_len_t elem_len;
                    ber_tag_t inner = ber_first_element(ber, &elem_len, &last);
                    int max = 20;
                    while (inner != LBER_DEFAULT && max-- > 0) {
                        struct berval elem;
                        ber_skip_element(ber, &elem);
                        inner = ber_next_element(ber, &elem_len, last);
                    }
                }
                break;
            case 2:  /* NOT - single Filter */
                {
                    struct berval elem;
                    ber_skip_element(ber, &elem);
                }
                break;
            case 3:  /* equalityMatch - AttributeValueAssertion */
            case 5:  /* greaterOrEqual */
            case 6:  /* lessOrEqual */
            case 8:  /* approxMatch */
                {
                    struct berval attr, val;
                    ber_scanf(ber, "{mm}", &attr, &val);
                }
                break;
            case 4:  /* substrings */
                {
                    struct berval attr;
                    ber_scanf(ber, "{m", &attr);
                    char *last = NULL;
                    ber_len_t elem_len;
                    ber_tag_t inner = ber_first_element(ber, &elem_len, &last);
                    int max = 20;
                    while (inner != LBER_DEFAULT && max-- > 0) {
                        struct berval substr;
                        ber_skip_element(ber, &substr);
                        inner = ber_next_element(ber, &elem_len, last);
                    }
                }
                break;
            case 7:  /* present - just attribute description */
                {
                    struct berval attr;
                    ber_scanf(ber, "m", &attr);
                }
                break;
            case 9:  /* extensibleMatch */
                {
                    struct berval bv;
                    ber_skip_element(ber, &bv);
                }
                break;
            default:
                {
                    struct berval bv;
                    ber_skip_element(ber, &bv);
                }
                break;
        }
    } else if (tag & 0x20) {
        parse_recursive(ber, 0);
    } else {
        struct berval bv;
        ber_skip_element(ber, &bv);
    }
}

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

    /* Use first byte of original data to select parsing strategy */
    if (size > 0 && (data[0] & 1)) {
        parse_recursive(ber, 0);
    } else {
        parse_filter_like(ber);
    }

cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
