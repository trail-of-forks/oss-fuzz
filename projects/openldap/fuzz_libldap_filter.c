/*
 * Harness: fuzz_libldap_filter
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap LDAP filter string to BER encoding
 * PATH:    ldap_pvt_put_filter() -> BER encode -> BER decode round-trip
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests the LDAP search filter parser which converts
 * RFC 4515 filter strings into BER-encoded ASN.1 structures. The
 * parser handles nested boolean operators, extensible matching,
 * escape sequences, and substring matching.
 *
 * Targets: ldap_pvt_put_filter(), plus BER decode round-trip
 *
 * Value of this harness:
 * - Tests recursive filter parser with nesting
 * - Validates BER encoding output via decode round-trip
 * - Exercises escape sequence handling in filter values
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <lber.h>
#include <ldap.h>
#include <openldap.h>

/* Maximum filter string size */
#define MAX_FILTER_SIZE 65536

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_FILTER_SIZE) {
        return 0;
    }

    /* Create null-terminated copy */
    char *filter_str = malloc(size + 1);
    if (!filter_str) return 0;
    memcpy(filter_str, data, size);
    filter_str[size] = '\0';

    /* === Test 1: Encode filter string to BER === */
    BerElement *ber = ber_alloc_t(LBER_USE_DER);
    if (!ber) {
        free(filter_str);
        return 0;
    }

    int rc = ldap_pvt_put_filter(ber, filter_str);
    if (rc == 0) {
        /* === Test 2: Flatten the BER output === */
        struct berval bv = { 0, NULL };
        if (ber_flatten2(ber, &bv, 1) == 0 && bv.bv_val) {
            /* === Test 3: Decode round-trip — walk the BER output === */
            BerElement *ber2 = ber_init(&bv);
            if (ber2) {
                ber_tag_t tag;
                ber_len_t len;

                /* Walk elements to exercise the decoder on encoder output */
                tag = ber_peek_tag(ber2, &len);
                if (tag != LBER_ERROR) {
                    struct berval skip_bv = { 0, NULL };
                    ber_skip_element(ber2, &skip_bv);
                }

                ber_free(ber2, 1);
            }
            ber_memfree(bv.bv_val);
        }
    }

    ber_free(ber, 1);
    free(filter_str);
    return 0;
}
