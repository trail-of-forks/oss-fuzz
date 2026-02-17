/*
 * Harness: fuzz_slapd_bind
 *
 * TIER:    1 (Server-Side Operations - Highest Priority)
 * TESTS:   slapd BindRequest processing path
 * PATH:    do_bind() -> BER parse -> get_ctrls() -> dnPrettyNormal() ->
 *          fe_op_bind() -> backend dispatch
 * CONFIG:  Server-side code (slapd attack surface)
 *
 * BUGS FOUND HERE ARE SERVER-EXPLOITABLE
 * (This is slapd server code processing unauthenticated BindRequests)
 *
 * BindRequest is the first operation on any LDAP connection and is
 * always unauthenticated. This harness exercises:
 * - BER parsing of BindRequest (version, DN, auth method, credentials)
 * - DN normalization via dnPrettyNormal()
 * - Simple bind path (password comparison against rootpw)
 * - SASL method tag parsing (returns error early without Cyrus SASL,
 *   but exercises BER parsing of mechanism + credentials)
 * - Control parsing via get_ctrls()
 *
 * Targets: do_bind(), dnPrettyNormal(), get_ctrls(), fe_op_bind()
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

    /* Zero out operation fields that do_bind's cleanup checks */
    BER_BVZERO(&op->o_req_dn);
    BER_BVZERO(&op->o_req_ndn);
    op->o_ctrls = NULL;

    /* Create BerElement from fuzz data.
     * do_bind() expects op->o_ber positioned at the BindRequest
     * APPLICATION[0] tag. The BER data should be:
     *   0x60 <len> { version, name, authentication }
     * optionally followed by:
     *   0xa0 <len> { controls... }
     */
    struct berval bv;
    bv.bv_val = (char *)data;
    bv.bv_len = size;

    BerElement *ber = ber_init(&bv);
    if (!ber) return 0;

    op->o_ber = ber;
    op->o_tag = LDAP_REQ_BIND;
    op->o_protocol = LDAP_VERSION3;

    do_bind(op, &rs);

    /* do_bind() handles its own cleanup at cleanup: label,
     * freeing o_req_dn and o_req_ndn. */
    ber_free(ber, 1);

    return 0;
}
