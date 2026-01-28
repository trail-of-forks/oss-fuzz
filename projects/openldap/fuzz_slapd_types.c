/*
 * Harness: fuzz_slapd_types
 *
 * TIER:    1 (Server-Exploitable - High Priority)
 * TESTS:   ASN.1/DER primitive type decoding through server entry point
 * PATH:    Network -> Sockbuf -> ber_get_next() -> type-specific decoders
 * CONFIG:  sb_max_incoming = 262143 (256KB - unauthenticated default)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 *
 * This harness exercises ASN.1 primitive type decoding through the
 * actual server entry point (ber_get_next). It specifically targets:
 *
 * - INTEGER (sign extension, overflow, large values)
 * - OCTET STRING / BIT STRING (length handling)
 * - BOOLEAN (non-canonical encodings)
 * - NULL (should have zero length)
 * - OID-like structures
 * - Time strings (GeneralizedTime, UTCTime)
 *
 * These are the building blocks of all LDAP messages, and bugs in
 * primitive decoding affect all operations.
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

/* ASN.1 Universal tags */
#define ASN1_BOOLEAN        0x01
#define ASN1_INTEGER        0x02
#define ASN1_BITSTRING      0x03
#define ASN1_OCTETSTRING    0x04
#define ASN1_NULL           0x05
#define ASN1_OID            0x06
#define ASN1_ENUMERATED     0x0a
#define ASN1_UTF8STRING     0x0c
#define ASN1_SEQUENCE       0x30
#define ASN1_SET            0x31
#define ASN1_PRINTABLESTR   0x13
#define ASN1_IA5STRING      0x16
#define ASN1_UTCTIME        0x17
#define ASN1_GENERALIZEDTIME 0x18

/*
 * Test integer decoding - sign extension, overflow, edge cases
 */
static void test_integer(BerElement *ber) {
    ber_int_t val;
    ber_get_int(ber, &val);
}

/*
 * Test string/octet string decoding
 */
static void test_string(BerElement *ber) {
    struct berval bv;
    ber_get_stringbv(ber, &bv, LBER_BV_NOTERM);
}

/*
 * Test boolean decoding
 */
static void test_boolean(BerElement *ber) {
    ber_int_t val;
    /* BER booleans are encoded as integers */
    ber_get_int(ber, &val);
}

/*
 * Test bitstring decoding
 */
static void test_bitstring(BerElement *ber) {
    struct berval bv;
    ber_get_stringbv(ber, &bv, LBER_BV_NOTERM);
}

/*
 * Test sequence iteration
 */
static void test_sequence(BerElement *ber) {
    char *last = NULL;
    ber_len_t elem_len;
    ber_tag_t tag;

    tag = ber_first_element(ber, &elem_len, &last);

    int max = 50;
    while (tag != LBER_DEFAULT && max-- > 0) {
        struct berval bv;
        ber_skip_element(ber, &bv);
        tag = ber_next_element(ber, &elem_len, last);
    }
}

/*
 * Test certificate-like structure (common in LDAP)
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 */
static void test_certificate_like(BerElement *ber) {
    ber_tag_t tag;
    ber_len_t len;
    char *last = NULL;

    tag = ber_first_element(ber, &len, &last);
    if (tag == LBER_DEFAULT) return;

    /* First element - try to parse as sequence (tbsCertificate) */
    if (tag == LBER_SEQUENCE) {
        struct berval tbs;
        ber_skip_element(ber, &tbs);
    }

    tag = ber_next_element(ber, &len, last);
    if (tag == LBER_DEFAULT) return;

    /* Second element - signatureAlgorithm (usually SEQUENCE with OID) */
    {
        struct berval alg;
        ber_skip_element(ber, &alg);
    }

    tag = ber_next_element(ber, &len, last);
    if (tag == LBER_DEFAULT) return;

    /* Third element - signature (BIT STRING) */
    {
        struct berval sig;
        ber_skip_element(ber, &sig);
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

    /* Determine type from tag and test accordingly */
    tag = ber_peek_tag(ber, &len);

    switch (tag) {
        case ASN1_INTEGER:
        case ASN1_ENUMERATED:
            test_integer(ber);
            break;

        case ASN1_BOOLEAN:
            test_boolean(ber);
            break;

        case ASN1_OCTETSTRING:
        case ASN1_UTF8STRING:
        case ASN1_PRINTABLESTR:
        case ASN1_IA5STRING:
            test_string(ber);
            break;

        case ASN1_BITSTRING:
            test_bitstring(ber);
            break;

        case ASN1_UTCTIME:
        case ASN1_GENERALIZEDTIME:
            test_string(ber);  /* Time values are string-like */
            break;

        case ASN1_SEQUENCE:
            /* Use input byte to select test strategy */
            if (size > 1 && (data[1] & 1)) {
                test_certificate_like(ber);
            } else {
                test_sequence(ber);
            }
            break;

        case ASN1_SET:
            test_sequence(ber);  /* Sets iterate similarly */
            break;

        case ASN1_NULL:
            /* NULL should have zero content */
            {
                struct berval bv;
                ber_skip_element(ber, &bv);
            }
            break;

        case ASN1_OID:
            /* OIDs are variable-length encoded */
            {
                struct berval bv;
                ber_skip_element(ber, &bv);
            }
            break;

        default:
            /* Unknown or context-specific tag */
            if (tag & 0x20) {
                /* Constructed - iterate */
                test_sequence(ber);
            } else {
                /* Primitive - treat as octet string */
                test_string(ber);
            }
            break;
    }


cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
