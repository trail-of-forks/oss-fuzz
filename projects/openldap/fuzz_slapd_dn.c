/*
 * Harness: fuzz_slapd_dn
 *
 * TIER:    1 (Server-Side Parsers - Highest Priority)
 * TESTS:   slapd server-side DN normalization
 * PATH:    dnPrettyNormal() -> schema resolution -> matching rules
 * CONFIG:  Server-side code (slapd attack surface)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 * (This is slapd server code processing DN values)
 *
 * This harness tests server-side DN normalization. Unlike the
 * client-side ldap_str2dn() already fuzzed, dnPrettyNormal() calls
 * into the full slapd schema system to resolve attribute types and
 * apply matching rules for normalization.
 *
 * Note: This harness does not use slab memory — dnPrettyNormal()
 * with NULL memctx uses the regular heap allocator (ch_malloc).
 *
 * Targets: dnPrettyNormal(), UTF-8 processing, attribute type resolution,
 *          matching rule application, case normalization, DN escaping
 */

#include "slapd_fuzz_init.h"

static int fuzz_init_ok = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* DN harness doesn't need a fake connection or slab memory.
     * It only needs slapd schema initialized. */
    static Connection dummy_conn;
    static OperationBuffer dummy_opbuf;
    void *thrctx;

    if (fuzz_init_ok) return 0;

    if (slapd_fuzz_init(argc, argv, &dummy_conn, &dummy_opbuf, &thrctx) != 0) {
        return 0;
    }

    fuzz_init_ok = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct berval in, pretty = {0, NULL}, normal = {0, NULL};
    int rc;

    if (!fuzz_init_ok || size == 0 || size > 65536) {
        return 0;
    }

    /* Create null-terminated berval from fuzz data */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    in.bv_val = buf;
    in.bv_len = size;

    /* Server-side DN normalization with full schema */
    rc = dnPrettyNormal(NULL, &in, &pretty, &normal, NULL);
    (void)rc;

    /* Always free — outputs may be partially set even on failure */
    if (pretty.bv_val) ber_memfree(pretty.bv_val);
    if (normal.bv_val) ber_memfree(normal.bv_val);

    free(buf);
    return 0;
}
