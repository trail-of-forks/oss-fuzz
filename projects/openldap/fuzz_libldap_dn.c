/*
 * Harness: fuzz_libldap_dn
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap Distinguished Name (DN) parsing
 * PATH:    ldap_str2dn() / ldap_dn2str() / ldap_str2rdn()
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests DN parsing which has complex state machine logic
 * with escape sequence handling, multi-byte character support, and
 * format conversion. Historical bugs include off-by-one errors,
 * integer overflows, and memory corruption in escape processing.
 *
 * Targets: ldap_str2dn(), ldap_dn2str(), ldap_str2rdn(), ldap_bv2dn()
 *
 * Value of this harness:
 * - Protects LDAP client applications using libldap
 * - Tests complex string parsing logic with escape handling
 * - Validates format conversion between LDAPv2/v3/DCE/UFN
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <ldap.h>

/* Maximum DN length - prevent OOM on degenerate inputs */
#define MAX_DN_SIZE 65536

/* DN format flags to test */
static const unsigned int dn_flags[] = {
    LDAP_DN_FORMAT_LDAPV3,
    LDAP_DN_FORMAT_LDAPV2,
    LDAP_DN_FORMAT_DCE,
    LDAP_DN_FORMAT_LDAPV3 | LDAP_DN_PEDANTIC,
    LDAP_DN_FORMAT_LDAPV2 | LDAP_DN_PEDANTIC,
};
#define NUM_FLAGS (sizeof(dn_flags) / sizeof(dn_flags[0]))

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    LDAPDN dn = NULL;
    LDAPRDN rdn = NULL;
    char *str_out = NULL;
    struct berval bv;
    int rc;

    /* Reject empty or oversized input */
    if (size == 0 || size > MAX_DN_SIZE) {
        return 0;
    }

    /* Create null-terminated copy for string functions */
    char *dn_str = malloc(size + 1);
    if (!dn_str) return 0;
    memcpy(dn_str, data, size);
    dn_str[size] = '\0';

    /* =============================================
     * Test 1: Parse DN with different format flags
     * =============================================
     */
    for (size_t i = 0; i < NUM_FLAGS; i++) {
        rc = ldap_str2dn(dn_str, &dn, dn_flags[i]);

        if (rc == LDAP_SUCCESS && dn != NULL) {
            /* =============================================
             * Test 2: Round-trip conversion
             * =============================================
             * Parse -> convert to string -> parse again
             * Should produce equivalent structures
             */
            rc = ldap_dn2str(dn, &str_out, LDAP_DN_FORMAT_LDAPV3);
            if (rc == LDAP_SUCCESS && str_out != NULL) {
                /* Try parsing the output */
                LDAPDN dn2 = NULL;
                ldap_str2dn(str_out, &dn2, LDAP_DN_FORMAT_LDAPV3);
                if (dn2) ldap_dnfree(dn2);
                ldap_memfree(str_out);
                str_out = NULL;
            }

            /* =============================================
             * Test 3: Format conversion
             * =============================================
             * Convert to different formats - tests escaping
             */
            rc = ldap_dn2str(dn, &str_out, LDAP_DN_FORMAT_LDAPV2);
            if (rc == LDAP_SUCCESS && str_out) {
                ldap_memfree(str_out);
                str_out = NULL;
            }

            rc = ldap_dn2str(dn, &str_out, LDAP_DN_FORMAT_UFN);
            if (rc == LDAP_SUCCESS && str_out) {
                ldap_memfree(str_out);
                str_out = NULL;
            }

            ldap_dnfree(dn);
            dn = NULL;
        } else if (dn != NULL) {
            /* Defensive cleanup if parse failed but dn was partially set */
            ldap_dnfree(dn);
            dn = NULL;
        }
    }

    /* =============================================
     * Test 4: RDN parsing (individual component)
     * =============================================
     */
    char *next = NULL;
    rc = ldap_str2rdn(dn_str, &rdn, &next, LDAP_DN_FORMAT_LDAPV3);
    if (rc == LDAP_SUCCESS && rdn != NULL) {
        /* Convert RDN back to string */
        rc = ldap_rdn2str(rdn, &str_out, LDAP_DN_FORMAT_LDAPV3);
        if (rc == LDAP_SUCCESS && str_out) {
            ldap_memfree(str_out);
            str_out = NULL;
        }
        ldap_rdnfree(rdn);
        rdn = NULL;
    }

    /* =============================================
     * Test 5: berval-based parsing
     * =============================================
     * Tests the bv2dn path which handles length differently
     */
    bv.bv_val = dn_str;
    bv.bv_len = size;
    rc = ldap_bv2dn(&bv, &dn, LDAP_DN_FORMAT_LDAPV3);
    if (rc == LDAP_SUCCESS && dn) {
        ldap_dnfree(dn);
        dn = NULL;
    }

    free(dn_str);
    return 0;
}
