/*
 * Harness: fuzz_libldap_url
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap LDAP URL parsing
 * PATH:    ldap_url_parse() / ldap_url_desc2str()
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests LDAP URL parsing which has complex structure:
 * ldap://host:port/dn?attrs?scope?filter?extensions
 *
 * Targets: ldap_url_parse(), ldap_url_desc2str(), ldap_is_ldap_url()
 *
 * Value of this harness:
 * - Protects LDAP client applications using libldap
 * - Tests URL component extraction and escaping
 * - Validates round-trip URL parsing and generation
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ldap.h>

#define MAX_URL_SIZE 8192

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    LDAPURLDesc *ludp = NULL;
    char *url_out = NULL;
    int rc;

    if (size == 0 || size > MAX_URL_SIZE) {
        return 0;
    }

    /* Create null-terminated URL string */
    char *url = malloc(size + 1);
    if (!url) return 0;
    memcpy(url, data, size);
    url[size] = '\0';

    /* =============================================
     * Test 1: Parse raw fuzzer input as URL
     * =============================================
     */
    rc = ldap_url_parse(url, &ludp);
    if (rc == LDAP_URL_SUCCESS && ludp) {
        /* Round-trip: convert back to string */
        url_out = ldap_url_desc2str(ludp);
        if (url_out) {
            /* Parse the output */
            LDAPURLDesc *ludp2 = NULL;
            ldap_url_parse(url_out, &ludp2);
            if (ludp2) ldap_free_urldesc(ludp2);
            ldap_memfree(url_out);
        }
        ldap_free_urldesc(ludp);
        ludp = NULL;
    }

    /* =============================================
     * Test 2: Prefix with ldap:// scheme
     * =============================================
     */
    char *prefixed = malloc(size + 16);
    if (prefixed) {
        snprintf(prefixed, size + 16, "ldap://%s", url);
        rc = ldap_url_parse(prefixed, &ludp);
        if (rc == LDAP_URL_SUCCESS && ludp) {
            ldap_free_urldesc(ludp);
            ludp = NULL;
        }
        free(prefixed);
    }

    /* =============================================
     * Test 3: Test as ldaps:// (TLS)
     * =============================================
     */
    prefixed = malloc(size + 16);
    if (prefixed) {
        snprintf(prefixed, size + 16, "ldaps://%s", url);
        rc = ldap_url_parse(prefixed, &ludp);
        if (rc == LDAP_URL_SUCCESS && ludp) {
            ldap_free_urldesc(ludp);
            ludp = NULL;
        }
        free(prefixed);
    }

    /* =============================================
     * Test 4: Check URL validity function
     * =============================================
     */
    ldap_is_ldap_url(url);

    free(url);
    return 0;
}
