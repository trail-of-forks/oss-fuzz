/*
 * Harness: fuzz_liblber_sockbuf_types
 *
 * TIER:    2 (BER wire-format parsing, shared between client and server)
 * TESTS:   ASN.1/DER primitive type decoding through Sockbuf I/O layer
 * PATH:    Sockbuf -> ber_get_next() -> type-specific BER decoders
 * CONFIG:  sb_max_incoming = 262143 (256KB - matches slapd unauthenticated default)
 *
 * Tests BER framing through Sockbuf, then exercises ASN.1 primitive
 * type decoding: INTEGER, OCTET STRING, BIT STRING, BOOLEAN, NULL,
 * OID-like structures, and time strings. These are the building
 * blocks of all LDAP messages.
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

/* ASN.1 Universal tags not defined in lber.h */
#define ASN1_OID             0x06
#define ASN1_UTCTIME         0x17
#define ASN1_GENERALIZEDTIME 0x18

static void test_integer(BerElement *ber) {
    ber_int_t val;
    ber_get_int(ber, &val);
}

static void test_string(BerElement *ber) {
    struct berval bv;
    ber_get_stringbv(ber, &bv, LBER_BV_NOTERM);
}

static void test_boolean(BerElement *ber) {
    ber_int_t val;
    ber_get_int(ber, &val);
}

static void test_bitstring(BerElement *ber) {
    struct berval bv;
    ber_get_stringbv(ber, &bv, LBER_BV_NOTERM);
}

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
 * Test certificate-like structure (common in LDAP):
 * Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signature }
 */
static void test_certificate_like(BerElement *ber) {
    ber_tag_t tag;
    ber_len_t len;
    char *last = NULL;

    tag = ber_first_element(ber, &len, &last);
    if (tag == LBER_DEFAULT) return;

    if (tag == LBER_SEQUENCE) {
        struct berval tbs;
        ber_skip_element(ber, &tbs);
    }

    tag = ber_next_element(ber, &len, last);
    if (tag == LBER_DEFAULT) return;

    {
        struct berval alg;
        ber_skip_element(ber, &alg);
    }

    tag = ber_next_element(ber, &len, last);
    if (tag == LBER_DEFAULT) return;

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

    tag = ber_peek_tag(ber, &len);

    switch (tag) {
        case LBER_INTEGER:
        case LBER_ENUMERATED:
            test_integer(ber);
            break;

        case LBER_BOOLEAN:
            test_boolean(ber);
            break;

        case LBER_OCTETSTRING:
        case LBER_UTF8_STRING:     /* 0x0c - from lber.h if defined */
        case 0x13:                 /* PrintableString */
        case 0x16:                 /* IA5String */
            test_string(ber);
            break;

        case LBER_BITSTRING:
            test_bitstring(ber);
            break;

        case ASN1_UTCTIME:
        case ASN1_GENERALIZEDTIME:
            test_string(ber);  /* Time values are string-like */
            break;

        case LBER_SEQUENCE:
            if (size > 1 && (data[1] & 1)) {
                test_certificate_like(ber);
            } else {
                test_sequence(ber);
            }
            break;

        case LBER_SET:
            test_sequence(ber);
            break;

        case LBER_NULL:
            {
                struct berval bv;
                ber_skip_element(ber, &bv);
            }
            break;

        case ASN1_OID:
            {
                struct berval bv;
                ber_skip_element(ber, &bv);
            }
            break;

        default:
            if (tag & 0x20) {
                test_sequence(ber);
            } else {
                test_string(ber);
            }
            break;
    }

cleanup:
    if (ber) ber_free(ber, 1);
    if (sb) ber_sockbuf_free(sb);
    return 0;
}
