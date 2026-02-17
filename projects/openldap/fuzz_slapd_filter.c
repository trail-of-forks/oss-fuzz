/*
 * Harness: fuzz_slapd_filter
 *
 * TIER:    1 (Server-Side Parsers - Highest Priority)
 * TESTS:   slapd server-side BER filter parser
 * PATH:    get_filter() -> get_filter0() -> slap_bv2ad() -> matching rules
 * CONFIG:  Server-side code (slapd attack surface)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 * (This is slapd server code processing unauthenticated input)
 *
 * This harness tests the LDAP search filter BER decoder inside slapd.
 * Unlike the client-side filter string parser, this operates on raw
 * BER-encoded data received from the network. It recursively parses
 * AND/OR/NOT boolean filters, equality/substring/GE/LE/present/approx/
 * extensible match filters, resolving attribute descriptions against
 * the loaded schema.
 *
 * Historical bugs: CVE-2020-12243 (nested boolean filter DoS)
 *
 * Targets: get_filter(), get_filter0(), get_ssa(), slap_bv2ad()
 */

#include "slapd_fuzz_init.h"

static int fuzz_init_ok = 0;
static Connection fuzz_conn;
static OperationBuffer fuzz_opbuf;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    void *thrctx;

    if (fuzz_init_ok) return 0;

    if (slapd_fuzz_init(argc, argv, &fuzz_conn, &fuzz_opbuf, &thrctx) != 0) {
        return 0;
    }

    fuzz_init_ok = 1;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    Filter *filter = NULL;
    const char *text = NULL;
    Operation *op = &fuzz_opbuf.ob_op;

    if (!fuzz_init_ok || size == 0 || size > 65536) {
        return 0;
    }

    /* Reset slab memory for this iteration */
    slapd_fuzz_reset_slab(op);

    /* Create BerElement from fuzz data */
    struct berval bv;
    bv.bv_val = (char *)data;
    bv.bv_len = size;

    BerElement *ber = ber_init(&bv);
    if (!ber) return 0;

    /* Parse the BER-encoded filter */
    int rc = get_filter(op, ber, &filter, &text);

    if (rc == LDAP_SUCCESS && filter != NULL) {
        filter_free_x(op, filter, 1);
    }

    ber_free(ber, 1);

    return 0;
}
