/*
 * Harness: fuzz_slapd_nested
 *
 * TIER:    1 (Server-Exploitable - High Priority)
 * TESTS:   Deeply nested BER structure parsing through server entry point
 * PATH:    Network -> Sockbuf -> ber_get_next() -> recursive parsing
 * CONFIG:  sb_max_incoming = 262143 (256KB - unauthenticated default)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 *
 * This harness exercises recursive BER structure parsing through the
 * actual server entry point (ber_get_next). It specifically targets:
 *
 * - Deep nesting (SEQUENCE within SEQUENCE within SEQUENCE...)
 * - LDAP filter-like structures (context-specific tags [0]-[9])
 * - Stack exhaustion from excessive recursion
 * - Bounds checking on nested element traversal
 *
 * This simulates parsing of complex LDAP filters which can be
 * arbitrarily nested: (&(|(cn=a)(cn=b))(!(sn=c)))
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

/* Maximum recursion depth to prevent stack overflow */
#define MAX_DEPTH 100

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

    /* Check if this is a constructed type (bit 5 set) */
    if (tag & 0x20) {
        /* Constructed: SEQUENCE, SET, or context-specific constructed */
        char *last = NULL;
        ber_len_t elem_len;

        tag = ber_first_element(ber, &elem_len, &last);

        int max_elements = 100;
        while (tag != LBER_DEFAULT && max_elements-- > 0) {
            /* Recursively parse child elements */
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

    /* Context-specific tags used by LDAP filters */
    if ((tag & 0xc0) == 0x80) {  /* Context-specific class */
        int tag_num = tag & 0x1f;

        switch (tag_num) {
            case 0:  /* AND - SET OF Filter */
            case 1:  /* OR - SET OF Filter */
                {
                    char *last = NULL;
                    ber_len_t elem_len;
                    ber_tag_t inner = ber_first_element(ber, &elem_len, &last);
                    int max = 100;
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
                    /* AVA ::= SEQUENCE { attr, value } */
                    struct berval attr, val;
                    ber_scanf(ber, "{mm}", &attr, &val);
                }
                break;
            case 4:  /* substrings */
                {
                    struct berval attr;
                    ber_scanf(ber, "{m", &attr);
                    /* SubstringFilter has nested SEQUENCE */
                    char *last = NULL;
                    ber_len_t elem_len;
                    ber_tag_t inner = ber_first_element(ber, &elem_len, &last);
                    int max = 100;
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
                    /* Has optional components with context tags */
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
        /* Generic constructed - recurse */
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

    /* Use first byte of original data to select parsing strategy */
    if (size > 0 && (data[0] & 1)) {
        /* Test 1: Recursive structure parsing */
        parse_recursive(ber, 0);
    } else {
        /* Test 2: LDAP filter-like tagged choices */
        parse_filter_like(ber);
    }

cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
