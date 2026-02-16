/*
 * Harness: fuzz_liblber_encode
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   liblber BER encoding with decode round-trip
 * PATH:    ber_put_* / ber_printf -> ber_flatten2 -> ber_init -> ber_scanf
 * CONFIG:  Tests encoder and decoder together via round-trip
 *
 * This harness interprets fuzz input as a sequence of encoding commands,
 * builds a BER element via the encoding API, then decodes the output
 * as a round-trip test. This structure-aware approach exercises diverse
 * encoding patterns driven by the fuzzer's mutations.
 *
 * Targets: ber_put_int(), ber_put_ostring(), ber_put_boolean(),
 *          ber_put_null(), ber_put_enum(), ber_start_seq(),
 *          ber_put_seq(), ber_start_set(), ber_put_set(),
 *          ber_flatten2(), ber_encode_oid()
 *
 * Value of this harness:
 * - Structure-aware encoding driven by fuzzer input
 * - Round-trip validation: encode -> flatten -> decode
 * - Tests nesting with depth tracking
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <lber.h>

/* Maximum input size */
#define MAX_INPUT_SIZE 65536
/* Maximum encoding operations per input */
#define MAX_OPS 100
/* Maximum nesting depth for sequences/sets */
#define MAX_DEPTH 16

/* Operation opcodes */
#define OP_PUT_INT       0
#define OP_PUT_OSTRING   1
#define OP_PUT_BOOLEAN   2
#define OP_PUT_NULL      3
#define OP_PUT_ENUM      4
#define OP_START_SEQ     5
#define OP_END_SEQ       6
#define OP_START_SET     7
#define OP_END_SET       8
#define OP_NUM           9

/* Helper: read a byte from the fuzz input, advance pointer */
static inline int read_byte(const uint8_t **p, const uint8_t *end) {
    if (*p >= end) return -1;
    int b = **p;
    (*p)++;
    return b;
}

/* Helper: read N bytes from the fuzz input */
static inline int read_bytes(const uint8_t **p, const uint8_t *end,
                             void *dst, size_t n) {
    if (*p + n > end) return -1;
    memcpy(dst, *p, n);
    *p += n;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > MAX_INPUT_SIZE) {
        return 0;
    }

    BerElement *ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) return 0;

    const uint8_t *p = data;
    const uint8_t *end = data + size;
    int ops = 0;
    int depth = 0;
    /* Track whether each nesting level is a seq or set */
    int nesting_type[MAX_DEPTH]; /* 0=seq, 1=set */

    while (p < end && ops < MAX_OPS) {
        int op_byte = read_byte(&p, end);
        if (op_byte < 0) break;

        int op = op_byte % OP_NUM;
        ops++;

        switch (op) {

        case OP_PUT_INT: {
            /* Read 4 bytes as integer value */
            ber_int_t val = 0;
            if (read_bytes(&p, end, &val, sizeof(val)) < 0) goto done;
            ber_put_int(ber, val, LBER_INTEGER);
            break;
        }

        case OP_PUT_OSTRING: {
            /* Read 1 byte length, then that many bytes of data */
            int len = read_byte(&p, end);
            if (len < 0) goto done;
            /* Clamp length to available data */
            size_t actual = (size_t)len;
            if (p + actual > end) actual = (size_t)(end - p);
            ber_put_ostring(ber, (const char *)p, actual, LBER_OCTETSTRING);
            p += actual;
            break;
        }

        case OP_PUT_BOOLEAN: {
            int val = read_byte(&p, end);
            if (val < 0) goto done;
            ber_put_boolean(ber, (ber_int_t)(val & 1), LBER_BOOLEAN);
            break;
        }

        case OP_PUT_NULL:
            ber_put_null(ber, LBER_NULL);
            break;

        case OP_PUT_ENUM: {
            ber_int_t val = 0;
            if (read_bytes(&p, end, &val, sizeof(val)) < 0) goto done;
            ber_put_enum(ber, val, LBER_ENUMERATED);
            break;
        }

        case OP_START_SEQ:
            if (depth < MAX_DEPTH) {
                ber_start_seq(ber, LBER_SEQUENCE);
                nesting_type[depth] = 0;
                depth++;
            }
            break;

        case OP_END_SEQ:
            if (depth > 0 && nesting_type[depth - 1] == 0) {
                ber_put_seq(ber);
                depth--;
            }
            break;

        case OP_START_SET:
            if (depth < MAX_DEPTH) {
                ber_start_set(ber, LBER_SET);
                nesting_type[depth] = 1;
                depth++;
            }
            break;

        case OP_END_SET:
            if (depth > 0 && nesting_type[depth - 1] == 1) {
                ber_put_set(ber);
                depth--;
            }
            break;
        }
    }

done:
    /* Close any unclosed sequences/sets */
    while (depth > 0) {
        depth--;
        if (nesting_type[depth] == 0)
            ber_put_seq(ber);
        else
            ber_put_set(ber);
    }

    /* === Flatten and decode round-trip === */
    struct berval flat = { 0, NULL };
    if (ber_flatten2(ber, &flat, 1) == 0 && flat.bv_val) {
        /* Decode the encoded output (only if non-empty) */
        if (flat.bv_len > 0) {
            BerElement *ber2 = ber_init(&flat);
            if (ber2) {
                /* Walk elements to exercise decoder */
                ber_tag_t tag;
                ber_len_t len;
                int walk_count = 0;

                tag = ber_peek_tag(ber2, &len);
                while (tag != LBER_ERROR && tag != LBER_DEFAULT && walk_count < 100) {
                    struct berval elem = { 0, NULL };
                    if (ber_skip_element(ber2, &elem) == LBER_ERROR) break;
                    tag = ber_peek_tag(ber2, &len);
                    walk_count++;
                }

                ber_free(ber2, 1);
            }
        }
        ber_memfree(flat.bv_val);
    }

    ber_free(ber, 1);

    /* === Test OID encoding === */
    if (size >= 4) {
        struct berval oid_in;
        oid_in.bv_val = (char *)data;
        oid_in.bv_len = size;

        struct berval oid_out = { 0, NULL };
        int rc = ber_encode_oid(&oid_in, &oid_out);
        if (rc == 0 && oid_out.bv_val) {
            /* Decode the encoded OID */
            struct berval decoded = { 0, NULL };
            ber_decode_oid(&oid_out, &decoded);
            if (decoded.bv_val) ber_memfree(decoded.bv_val);
            ber_memfree(oid_out.bv_val);
        }
    }

    return 0;
}
