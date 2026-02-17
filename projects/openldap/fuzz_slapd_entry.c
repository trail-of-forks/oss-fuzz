/*
 * Harness: fuzz_slapd_entry
 *
 * TIER:    1 (Server-Side Parsers - Highest Priority)
 * TESTS:   slapd LDIF entry parser with schema validation
 * PATH:    str2entry2() -> slap_str2ad() -> syntax validation -> normalization
 * CONFIG:  Server-side code (slapd attack surface)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 * (This is slapd server code processing entries)
 *
 * This harness tests the LDIF-format entry parser inside slapd.
 * str2entry2() parses "attribute: value" lines, resolves attribute
 * descriptions against the loaded schema, validates syntax, handles
 * binary values (base64), continuation lines, and duplicate value
 * detection.
 *
 * Note: This harness does not use slab memory — str2entry2() uses
 * ch_malloc() internally.
 *
 * Targets: str2entry2(), slap_str2ad(), syntax validation, normalization
 */

#include "slapd_fuzz_init.h"

static int fuzz_init_ok = 0;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* Entry harness doesn't need a fake connection or slab memory.
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
    Entry *entry;
    struct berval bv;

    if (!fuzz_init_ok || size == 0 || size > 65536) {
        return 0;
    }

    /* str2entry2 expects null-terminated input */
    char *buf = malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    bv.bv_val = buf;
    bv.bv_len = size;

    /* Parse the LDIF entry (1 = check for duplicate values) */
    entry = str2entry2(&bv, 1);

    if (entry != NULL) {
        entry_free(entry);
    }

    free(buf);
    return 0;
}
