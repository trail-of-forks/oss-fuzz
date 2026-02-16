/*
 * Harness: fuzz_liblber_ber_init
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   liblber direct BER decoding via ber_init()
 * PATH:    ber_init() -> ber_scanf() / ber_get_* / ber_decode_oid()
 * CONFIG:  Bypasses Sockbuf framing — tests BER decoding directly
 *
 * This harness tests BER decoding by feeding raw BER data directly
 * to ber_init() (bypassing the Sockbuf/ber_get_next framing layer).
 * It exercises multiple ber_scanf format strings and individual
 * decode functions for integers, strings, booleans, sequences, etc.
 *
 * Targets: ber_init(), ber_scanf(), ber_get_int(), ber_get_stringbv(),
 *          ber_get_boolean(), ber_get_null(), ber_get_bitstringa(),
 *          ber_first_element(), ber_next_element(), ber_skip_element(),
 *          ber_peek_tag(), ber_decode_oid()
 *
 * Value of this harness:
 * - Tests BER decoding without Sockbuf length limits
 * - Exercises multiple parsing patterns via ber_scanf
 * - Tests OID decoding separately
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <lber.h>

/* Maximum BER input size */
#define MAX_BER_SIZE 262144

/* ber_scanf format strings to test */
static const char *scanf_fmts[] = {
    "{im}",     /* sequence: integer + octet string */
    "{iii}",    /* sequence: 3 integers */
    "{m{m}}",   /* nested sequence with strings */
    "m",        /* bare octet string */
    "i",        /* bare integer */
    "b",        /* bare boolean */
    "{it}",     /* sequence: integer + tag peek */
    "{mmm}",    /* sequence: 3 octet strings */
};
#define NUM_FMTS (sizeof(scanf_fmts) / sizeof(scanf_fmts[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > MAX_BER_SIZE) {
        return 0;
    }

    /* Use first 2 bytes as selectors */
    uint8_t fmt_selector = data[0];
    uint8_t mode_selector = data[1];
    const uint8_t *payload = data + 2;
    size_t payload_size = size - 2;

    if (payload_size == 0) return 0;

    struct berval bv;
    bv.bv_val = (char *)payload;
    bv.bv_len = payload_size;

    /* === Test 1: ber_scanf with selected format === */
    {
        BerElement *ber = ber_init(&bv);
        if (ber) {
            const char *fmt = scanf_fmts[fmt_selector % NUM_FMTS];
            ber_tag_t tag;

            if (strcmp(fmt, "i") == 0) {
                ber_int_t num;
                ber_get_int(ber, &num);
            } else if (strcmp(fmt, "b") == 0) {
                ber_int_t bval;
                ber_get_boolean(ber, &bval);
            } else if (strcmp(fmt, "m") == 0) {
                struct berval sv = { 0, NULL };
                ber_get_stringbv(ber, &sv, 0);  /* in-place, no alloc */
            } else if (strcmp(fmt, "{im}") == 0) {
                ber_int_t num;
                struct berval sv = { 0, NULL };
                tag = ber_scanf(ber, "{im}", &num, &sv);
            } else if (strcmp(fmt, "{iii}") == 0) {
                ber_int_t a, b, c;
                tag = ber_scanf(ber, "{iii}", &a, &b, &c);
            } else if (strcmp(fmt, "{m{m}}") == 0) {
                struct berval s1 = { 0, NULL }, s2 = { 0, NULL };
                tag = ber_scanf(ber, "{m{m}}", &s1, &s2);
            } else if (strcmp(fmt, "{it}") == 0) {
                ber_int_t num;
                ber_tag_t inner_tag;
                tag = ber_scanf(ber, "{it}", &num, &inner_tag);
            } else if (strcmp(fmt, "{mmm}") == 0) {
                struct berval s1 = { 0, NULL }, s2 = { 0, NULL }, s3 = { 0, NULL };
                tag = ber_scanf(ber, "{mmm}", &s1, &s2, &s3);
            }

            ber_free(ber, 1);
        }
    }

    /* === Test 2: Walk elements with peek/skip === */
    if (mode_selector & 0x01) {
        BerElement *ber = ber_init(&bv);
        if (ber) {
            ber_tag_t tag;
            ber_len_t len;

            tag = ber_peek_tag(ber, &len);
            if (tag != LBER_ERROR) {
                struct berval elem = { 0, NULL };
                ber_skip_element(ber, &elem);

                /* Try to get next element */
                tag = ber_peek_tag(ber, &len);
                if (tag != LBER_ERROR) {
                    ber_skip_element(ber, &elem);
                }
            }

            ber_free(ber, 1);
        }
    }

    /* === Test 3: Sequence iteration === */
    if (mode_selector & 0x02) {
        BerElement *ber = ber_init(&bv);
        if (ber) {
            ber_len_t len;
            char *last = NULL;
            ber_tag_t tag;
            int count = 0;

            for (tag = ber_first_element(ber, &len, &last);
                 tag != LBER_ERROR && tag != LBER_DEFAULT && count < 100;
                 tag = ber_next_element(ber, &len, last)) {
                struct berval elem = { 0, NULL };
                ber_skip_element(ber, &elem);
                count++;
            }

            ber_free(ber, 1);
        }
    }

    /* === Test 4: OID decoding === */
    if (mode_selector & 0x04) {
        struct berval oid_in;
        oid_in.bv_val = (char *)payload;
        oid_in.bv_len = payload_size;

        struct berval oid_out = { 0, NULL };
        int rc = ber_decode_oid(&oid_in, &oid_out);
        if (rc == 0 && oid_out.bv_val) {
            ber_memfree(oid_out.bv_val);
        }
    }

    /* === Test 5: Additional decode functions === */
    if (mode_selector & 0x08) {
        BerElement *ber = ber_init(&bv);
        if (ber) {
            /* Try ber_get_null */
            ber_get_null(ber);
            ber_free(ber, 1);
        }

        ber = ber_init(&bv);
        if (ber) {
            /* Try ber_get_bitstringa */
            char *bits = NULL;
            ber_len_t blen = 0;
            ber_tag_t tag = ber_get_bitstringa(ber, &bits, &blen);
            if (tag != LBER_ERROR && bits) {
                ber_memfree(bits);
            }
            ber_free(ber, 1);
        }
    }

    return 0;
}
