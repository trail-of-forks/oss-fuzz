/*
 * Harness: fuzz_libldap_url_filter
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap URL parsing with filter string component
 * PATH:    ldap_url_parse() with filter in URL
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests URL parsing including filter component STORAGE,
 * not filter syntax parsing. The filter is stored as a string in
 * ludp->lud_filter but not validated for LDAP filter syntax.
 *
 * NOTE: Server-side filter parsing (get_filter0 in servers/slapd/filter.c)
 * requires full slapd initialization - see fuzz_slapd_filter (Phase 4).
 *
 * LDAP filters have complex recursive structure:
 * Filter ::= CHOICE {
 *   and         [0] SET OF Filter,
 *   or          [1] SET OF Filter,
 *   not         [2] Filter,
 *   equalityMatch   [3] AttributeValueAssertion,
 *   substrings      [4] SubstringFilter,
 *   ...
 * }
 *
 * Value of this harness:
 * - Protects LDAP client applications parsing URLs with filters
 * - Tests filter string storage and URL escaping
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ldap.h>

/* Maximum filter string length */
#define MAX_FILTER_SIZE 65536

/*
 * Test filter string via URL parsing.
 *
 * This exercises libldap's filter string validation and storage,
 * NOT the server-side BER filter parser (get_filter0).
 */
static void test_str_filter(const char *filter_str, size_t filter_len) {
    /* URL format: ldap://localhost/dc=test??sub?FILTER
     * Prefix is 29 chars, need space for filter + null */
    static const char prefix[] = "ldap://localhost/dc=test??sub?";
    size_t url_size = sizeof(prefix) + filter_len;

    char *url = malloc(url_size);
    if (!url) return;

    memcpy(url, prefix, sizeof(prefix) - 1);
    memcpy(url + sizeof(prefix) - 1, filter_str, filter_len);
    url[url_size - 1] = '\0';

    LDAPURLDesc *ludp = NULL;
    int rc = ldap_url_parse(url, &ludp);

    if (rc == LDAP_URL_SUCCESS && ludp) {
        /* URL parsed - filter string was accepted and stored */
        ldap_free_urldesc(ludp);
    }

    free(url);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_FILTER_SIZE) {
        return 0;
    }

    /* Create null-terminated string */
    char *filter_str = malloc(size + 1);
    if (!filter_str) return 0;
    memcpy(filter_str, data, size);
    filter_str[size] = '\0';

    /* =============================================
     * Test 1: Basic filter string parsing
     * =============================================
     */
    test_str_filter(filter_str, size);

    /* =============================================
     * Test 2: Wrapped in standard filter syntax
     * =============================================
     * Many filters are wrapped: (&(objectClass=*)(...)
     */
    size_t wrapped_size = size + 32;
    char *wrapped = malloc(wrapped_size);
    if (wrapped) {
        int n = snprintf(wrapped, wrapped_size, "(&(objectClass=*)%s)", filter_str);
        if (n > 0 && (size_t)n < wrapped_size) {
            test_str_filter(wrapped, n);
        }
        free(wrapped);
    }

    /* =============================================
     * Test 3: As substring filter component
     * =============================================
     */
    wrapped = malloc(wrapped_size);
    if (wrapped) {
        int n = snprintf(wrapped, wrapped_size, "(cn=*%s*)", filter_str);
        if (n > 0 && (size_t)n < wrapped_size) {
            test_str_filter(wrapped, n);
        }
        free(wrapped);
    }

    free(filter_str);
    return 0;
}
