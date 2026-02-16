/*
 * Harness: fuzz_libldap_schema
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap schema definition parsing
 * PATH:    ldap_str2objectclass() / ldap_str2attributetype() / etc.
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests schema definition string parsers which have
 * complex tokenization logic with parentheses, quoting, OID handling,
 * and keyword matching. Uses first byte to select among 8 different
 * schema types.
 *
 * Targets: ldap_str2objectclass(), ldap_str2attributetype(),
 *          ldap_str2syntax(), ldap_str2matchingrule(),
 *          ldap_str2matchingruleuse(), ldap_str2contentrule(),
 *          ldap_str2nameform(), ldap_str2structurerule()
 *
 * Value of this harness:
 * - Tests complex schema definition parser with many code paths
 * - Validates round-trip parsing and serialization
 * - Tests with both strict and permissive parsing flags
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include <ldap.h>
#include <ldap_schema.h>

/* Maximum schema definition size */
#define MAX_SCHEMA_SIZE 65536

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    int code;
    const char *errp;

    /* Need at least 1 selector byte + 1 content byte */
    if (size < 2 || size > MAX_SCHEMA_SIZE) {
        return 0;
    }

    /* Use first byte as selector, rest as schema string */
    uint8_t selector = data[0];
    const uint8_t *payload = data + 1;
    size_t payload_size = size - 1;

    /* Create null-terminated copy */
    char *str = malloc(payload_size + 1);
    if (!str) return 0;
    memcpy(str, payload, payload_size);
    str[payload_size] = '\0';

    /* Test with both strict and permissive flags */
    unsigned int flags_to_test[] = {
        LDAP_SCHEMA_ALLOW_NONE,
        LDAP_SCHEMA_ALLOW_ALL,
    };

    for (int fi = 0; fi < 2; fi++) {
        unsigned int flags = flags_to_test[fi];

        switch (selector % 8) {

        /* === Case 0: ObjectClass === */
        case 0: {
            LDAPObjectClass *oc = ldap_str2objectclass(str, &code, &errp, flags);
            if (oc) {
                /* Round-trip: struct -> string -> struct */
                char *s = ldap_objectclass2str(oc);
                if (s) {
                    LDAPObjectClass *oc2 = ldap_str2objectclass(s, &code, &errp, flags);
                    if (oc2) ldap_objectclass_free(oc2);
                    ldap_memfree(s);
                }
                /* Also test berval variant */
                struct berval bv = { 0, NULL };
                ldap_objectclass2bv(oc, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_objectclass_free(oc);
            }
            break;
        }

        /* === Case 1: AttributeType === */
        case 1: {
            LDAPAttributeType *at = ldap_str2attributetype(str, &code, &errp, flags);
            if (at) {
                char *s = ldap_attributetype2str(at);
                if (s) {
                    LDAPAttributeType *at2 = ldap_str2attributetype(s, &code, &errp, flags);
                    if (at2) ldap_attributetype_free(at2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_attributetype2bv(at, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_attributetype_free(at);
            }
            break;
        }

        /* === Case 2: Syntax === */
        case 2: {
            LDAPSyntax *syn = ldap_str2syntax(str, &code, &errp, flags);
            if (syn) {
                char *s = ldap_syntax2str(syn);
                if (s) {
                    LDAPSyntax *syn2 = ldap_str2syntax(s, &code, &errp, flags);
                    if (syn2) ldap_syntax_free(syn2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_syntax2bv(syn, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_syntax_free(syn);
            }
            break;
        }

        /* === Case 3: MatchingRule === */
        case 3: {
            LDAPMatchingRule *mr = ldap_str2matchingrule(str, &code, &errp, flags);
            if (mr) {
                char *s = ldap_matchingrule2str(mr);
                if (s) {
                    LDAPMatchingRule *mr2 = ldap_str2matchingrule(s, &code, &errp, flags);
                    if (mr2) ldap_matchingrule_free(mr2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_matchingrule2bv(mr, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_matchingrule_free(mr);
            }
            break;
        }

        /* === Case 4: MatchingRuleUse === */
        case 4: {
            LDAPMatchingRuleUse *mru = ldap_str2matchingruleuse(str, &code, &errp, flags);
            if (mru) {
                char *s = ldap_matchingruleuse2str(mru);
                if (s) {
                    LDAPMatchingRuleUse *mru2 = ldap_str2matchingruleuse(s, &code, &errp, flags);
                    if (mru2) ldap_matchingruleuse_free(mru2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_matchingruleuse2bv(mru, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_matchingruleuse_free(mru);
            }
            break;
        }

        /* === Case 5: ContentRule === */
        case 5: {
            LDAPContentRule *cr = ldap_str2contentrule(str, &code, &errp, flags);
            if (cr) {
                char *s = ldap_contentrule2str(cr);
                if (s) {
                    LDAPContentRule *cr2 = ldap_str2contentrule(s, &code, &errp, flags);
                    if (cr2) ldap_contentrule_free(cr2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_contentrule2bv(cr, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_contentrule_free(cr);
            }
            break;
        }

        /* === Case 6: NameForm === */
        case 6: {
            LDAPNameForm *nf = ldap_str2nameform(str, &code, &errp, flags);
            if (nf) {
                char *s = ldap_nameform2str(nf);
                if (s) {
                    LDAPNameForm *nf2 = ldap_str2nameform(s, &code, &errp, flags);
                    if (nf2) ldap_nameform_free(nf2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_nameform2bv(nf, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_nameform_free(nf);
            }
            break;
        }

        /* === Case 7: StructureRule === */
        case 7: {
            LDAPStructureRule *sr = ldap_str2structurerule(str, &code, &errp, flags);
            if (sr) {
                char *s = ldap_structurerule2str(sr);
                if (s) {
                    LDAPStructureRule *sr2 = ldap_str2structurerule(s, &code, &errp, flags);
                    if (sr2) ldap_structurerule_free(sr2);
                    ldap_memfree(s);
                }
                struct berval bv = { 0, NULL };
                ldap_structurerule2bv(sr, &bv);
                if (bv.bv_val) ldap_memfree(bv.bv_val);
                ldap_structurerule_free(sr);
            }
            break;
        }
        }
    }

    free(str);
    return 0;
}
