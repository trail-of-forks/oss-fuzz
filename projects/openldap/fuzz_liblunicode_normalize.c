/*
 * Harness: fuzz_liblunicode_normalize
 *
 * TIER:    1 (Server-Exploitable - High Priority)
 * TESTS:   Unicode NFKC normalization via UTF8bvnormalize()
 * PATH:    Every LDAP search filter, DN comparison, attribute value
 *          -> UTF8bvnormalize()
 * CONFIG:  Library-only (no slapd build needed)
 *
 * BUGS FOUND HERE ARE LIKELY SERVER-EXPLOITABLE
 *
 * UTF8bvnormalize() processes every search filter, DN comparison,
 * and attribute value in slapd. ber_get_stringbv() does zero UTF-8
 * validation, so raw bytes from the wire reach this function.
 *
 * Bug Triage: Run crash inputs through validate_unicode_crash to classify:
 *   Tier 1: Passes UTF8StringValidate() -> directly exploitable via LDAP
 *   Tier 2: Fails UTF8StringValidate() -> library bug, lower severity
 *
 * Targets: UTF8bvnormalize() in libraries/liblunicode/ucstr.c
 *   - NFKC decomposition + composition
 *   - Optional case folding
 *   - Approximate matching normalization
 */

#include "portable.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include <lber.h>
#include <ldap_pvt_uc.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct berval input = { .bv_len = size, .bv_val = (char *)data };
    struct berval output = { 0 };

    /* Test case-fold normalization (caseIgnoreMatch path) */
    struct berval *result = UTF8bvnormalize(&input, &output, LDAP_UTF8_CASEFOLD, NULL);
    if (result) ber_memfree(output.bv_val);

    /* Test exact normalization (caseExactMatch path) */
    memset(&output, 0, sizeof(output));
    result = UTF8bvnormalize(&input, &output, LDAP_UTF8_NOCASEFOLD, NULL);
    if (result) ber_memfree(output.bv_val);

    /* Test approximate normalization (approxMatch path) */
    memset(&output, 0, sizeof(output));
    result = UTF8bvnormalize(&input, &output, LDAP_UTF8_APPROX, NULL);
    if (result) ber_memfree(output.bv_val);

    return 0;
}
