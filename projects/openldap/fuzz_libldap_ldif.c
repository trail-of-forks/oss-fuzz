/*
 * Harness: fuzz_libldap_ldif
 *
 * TIER:    3 (Client Libraries - Lower Priority)
 * TESTS:   libldap LDIF record parsing and serialization
 * PATH:    ldif_parse_line2() / ldif_open_mem() / ldif_read_record()
 * CONFIG:  Client-side code (not slapd server attack surface)
 *
 * BUGS FOUND HERE ARE NOT SERVER-EXPLOITABLE
 * (This is client library code, not server code)
 *
 * This harness tests LDIF parsing which handles base64-encoded values,
 * URL references, line continuations, and multi-record files. The
 * parsing functions modify input buffers in-place so mutable copies
 * are required.
 *
 * Targets: ldif_parse_line2(), ldif_open_mem(), ldif_read_record(),
 *          ldif_close(), ldif_getline(), ldif_countlines(), ldif_put()
 *
 * Value of this harness:
 * - Tests LDIF parsing with in-place buffer modification
 * - Validates multi-record streaming parser
 * - Tests serialization round-trip via ldif_put
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <ldap.h>
#include <ldif.h>

/* Maximum LDIF input size */
#define MAX_LDIF_SIZE 262144
/* Maximum records to parse per input */
#define MAX_RECORDS 10

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > MAX_LDIF_SIZE) {
        return 0;
    }

    /* === Test 1: Single-line parsing with ldif_parse_line2 === */
    {
        /* ldif_parse_line2 modifies the buffer in-place */
        char *line = malloc(size + 1);
        if (!line) return 0;
        memcpy(line, data, size);
        line[size] = '\0';

        struct berval type = { 0, NULL };
        struct berval value = { 0, NULL };
        int freeval = 0;

        int rc = ldif_parse_line2(line, &type, &value, &freeval);
        if (rc == 0) {
            /* Successful parse — test serialization round-trip */
            char *ldif_out = ldif_put(LDIF_PUT_VALUE, type.bv_val,
                                      value.bv_val, value.bv_len);
            if (ldif_out) {
                ber_memfree(ldif_out);
            }

            /* If value was base64-decoded, free it */
            if (freeval) {
                ber_memfree(value.bv_val);
            }
        }

        free(line);
    }

    /* === Test 2: Multi-line record parsing with ldif_open_mem === */
    {
        /* ldif_open_mem needs a mutable buffer */
        char *buf = malloc(size + 1);
        if (!buf) return 0;
        memcpy(buf, data, size);
        buf[size] = '\0';

        LDIFFP *fp = ldif_open_mem(buf, size, "r");
        if (fp) {
            unsigned long lineno = 0;
            int records = 0;

            while (records < MAX_RECORDS) {
                char *bufp = NULL;
                int buflen = 0;

                int rc = ldif_read_record(fp, &lineno, &bufp, &buflen);
                if (rc <= 0) {
                    /* rc==0 means EOF, rc<0 means error */
                    if (bufp) ber_memfree(bufp);
                    break;
                }

                /* Parse individual lines from the record */
                if (bufp && buflen > 0) {
                    char *next = bufp;
                    char *line;
                    while ((line = ldif_getline(&next)) != NULL) {
                        struct berval type = { 0, NULL };
                        struct berval value = { 0, NULL };
                        int freeval = 0;
                        int prc = ldif_parse_line2(line, &type, &value, &freeval);
                        if (prc == 0 && freeval) {
                            ber_memfree(value.bv_val);
                        }
                    }
                    ber_memfree(bufp);
                }

                records++;
            }

            ldif_close(fp);
        }

        free(buf);
    }

    /* === Test 3: ldif_countlines === */
    {
        char *str = malloc(size + 1);
        if (str) {
            memcpy(str, data, size);
            str[size] = '\0';
            ldif_countlines(str);
            free(str);
        }
    }

    return 0;
}
