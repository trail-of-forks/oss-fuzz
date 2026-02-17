/*
 * Harness: fuzz_slapd_search
 *
 * TIER:    1 (Server-Side Operations - Highest Priority)
 * TESTS:   slapd full SearchRequest processing path
 * PATH:    do_search() -> BER parse -> dnPrettyNormal() -> get_filter() ->
 *          get_ctrls() -> fe_op_search() -> backend dispatch
 * CONFIG:  Server-side code (slapd attack surface)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 * (This is slapd server code processing unauthenticated SearchRequests)
 *
 * This harness exercises the complete SearchRequest processing path in
 * slapd. It covers BER parsing of SearchRequest fields, DN normalization,
 * filter parsing with schema resolution, control parsing (complex per-
 * control parsers), attribute list parsing, scope/deref/limit validation,
 * and the interactions between all of these in a single operation.
 *
 * This is the single most important harness — SearchRequest is the most
 * complex unauthenticated LDAP operation.
 *
 * Targets: do_search(), dnPrettyNormal(), get_filter(), get_ctrls(),
 *          slap_bv2ad(), fe_op_search()
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
    Operation *op = &fuzz_opbuf.ob_op;
    SlapReply rs = {REP_RESULT};

    if (!fuzz_init_ok || size == 0 || size > 65536) {
        return 0;
    }

    /* Reset slab memory for this iteration */
    slapd_fuzz_reset_slab(op);

    /* Zero out operation fields that do_search's cleanup checks.
     * Without this, early-exit paths (BER parse error) would try to
     * free stale pointers from a previous iteration's reset slab. */
    BER_BVZERO(&op->o_req_dn);
    BER_BVZERO(&op->o_req_ndn);
    op->ors_filter = NULL;
    BER_BVZERO(&op->ors_filterstr);
    op->ors_attrs = NULL;
    op->o_ctrls = NULL;

    /* Create BerElement from fuzz data.
     * do_search() expects op->o_ber positioned at the SearchRequest
     * APPLICATION[3] tag. The BER data should be:
     *   0x63 <len> { base, scope, deref, sizelimit, timelimit, attrsonly,
     *                filter, attributes }
     * optionally followed by:
     *   0xa0 <len> { controls... }
     */
    struct berval bv;
    bv.bv_val = (char *)data;
    bv.bv_len = size;

    BerElement *ber = ber_init(&bv);
    if (!ber) return 0;

    op->o_ber = ber;
    op->o_tag = LDAP_REQ_SEARCH;

    do_search(op, &rs);

    /* do_search() handles its own cleanup at return_results: label,
     * freeing o_req_dn, o_req_ndn, ors_filterstr, ors_filter, ors_attrs.
     * We just need to free the BerElement. */
    ber_free(ber, 1);

    return 0;
}
