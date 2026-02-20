/*
 * slapd_fuzz_init.h — Shared initialization for slapd fuzzing harnesses
 *
 * Provides common setup code used by all slapd-side fuzz harnesses:
 * - Config file discovery
 * - slap_sl_mem_init(), slap_init(), thread pool init, read_config(), slap_startup()
 * - connection_fake_init() with real thread context
 * - No-op send callbacks to prevent crashes on fake connections
 * - Per-iteration slab memory reset
 */

#ifndef SLAPD_FUZZ_INIT_H
#define SLAPD_FUZZ_INIT_H

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "portable.h"
#include <lber.h>
#include <ldap.h>
#include "slap.h"

/* No-op send callbacks — prevent crashes when slapd operations try to
 * send results/errors on the fake connection. do_search(), do_bind(),
 * etc. call send_ldap_result() on error paths, which would crash
 * without a real Sockbuf.
 *
 * Return types must match the typedefs in slap.h:
 *   SEND_LDAP_RESULT      -> void
 *   SEND_SEARCH_ENTRY     -> int
 *   SEND_SEARCH_REFERENCE -> int
 *   SEND_LDAP_EXTENDED    -> void
 *   SEND_LDAP_INTERMEDIATE -> void
 */
static void fuzz_send_ldap_result(Operation *op, SlapReply *rs) {
    (void)op; (void)rs;
}

static int fuzz_send_search_entry(Operation *op, SlapReply *rs) {
    (void)op; (void)rs;
    return LDAP_SUCCESS;
}

static int fuzz_send_search_reference(Operation *op, SlapReply *rs) {
    (void)op; (void)rs;
    return LDAP_SUCCESS;
}

static void fuzz_send_ldap_extended(Operation *op, SlapReply *rs) {
    (void)op; (void)rs;
}

static void fuzz_send_ldap_intermediate(Operation *op, SlapReply *rs) {
    (void)op; (void)rs;
}

/*
 * Initialize slapd subsystems for fuzzing.
 *
 * Sets up: slab memory, server mode, thread pool, config, backends.
 * Creates a fake connection with a real thread context (not NULL)
 * so that slab memory is properly tracked in thread-local storage.
 *
 * Returns 0 on success, -1 on failure.
 */
static int slapd_fuzz_init(int *argc, char ***argv,
                           Connection *conn, OperationBuffer *opbuf,
                           void **thrctx_out) {
    const char *configfile = NULL;
    static char config_path[1024];

    /* Find config file: next to binary or via env */
    const char *env_conf = getenv("SLAPD_FUZZ_CONF");
    if (env_conf) {
        configfile = env_conf;
    } else {
        const char *progname = (*argv)[0];
        const char *slash = strrchr(progname, '/');
        if (slash) {
            size_t dirlen = (size_t)(slash - progname);
            snprintf(config_path, sizeof(config_path),
                     "%.*s/slapd_fuzz.conf", (int)dirlen, progname);
        } else {
            snprintf(config_path, sizeof(config_path), "slapd_fuzz.conf");
        }
        configfile = config_path;
    }

    /* Initialize slapd subsystems */
    slap_sl_mem_init();

    if (slap_init(SLAP_SERVER_MODE, "slapd-fuzz") != 0) {
        return -1;
    }

    /* Initialize thread pool — needed by connection_fake_init() which
     * calls ldap_pvt_thread_pool_tid(&connection_pool). */
    ldap_pvt_thread_pool_init(&connection_pool, 0, 0);

    if (read_config(configfile, NULL) != 0) {
        return -1;
    }

    /* Disable the config backend's db_open.  config_back_db_open()
     * builds the full cn=config DIT tree and calls through BackendInfo
     * function pointers that our linker stubs leave uninitialized
     * (ldif_back_initialize, monitor_back_initialize are no-ops).
     * This causes a wild jump during startup.  The cn=config backend
     * is not needed for fuzzing — we only need the schema (loaded by
     * read_config above) and the null backend. */
    {
        BackendDB *b;
        LDAP_STAILQ_FOREACH(b, &backendDB, be_next) {
            if (b->bd_info && b->bd_info->bi_type &&
                strcmp(b->bd_info->bi_type, "config") == 0) {
                b->bd_info->bi_db_open = NULL;
                break;
            }
        }
    }

    if (slap_startup(NULL) != 0) {
        return -1;
    }

    /* Initialize connection table — needed by connection2anonymous()
     * in do_bind() which asserts connections != NULL. Set dtblsize to 1
     * (normally set by slapd_daemon_init which we skip). */
    dtblsize = 1;
    connections_init();

    /* Get a real thread context — passing NULL to connection_fake_init()
     * creates a slab that is never stored in thread-local storage, so it
     * can never be found again for reset. This causes unbounded memory
     * growth under OSS-Fuzz. */
    *thrctx_out = ldap_pvt_thread_pool_context();

    memset(conn, 0, sizeof(*conn));
    connection_fake_init(conn, opbuf, *thrctx_out);

    /* Initialize connection mutexes — do_bind() locks c_mutex,
     * send_ldap_ber() locks c_write1_mutex. connection_fake_init
     * doesn't initialize these. Zero-init works on Linux (equivalent
     * to PTHREAD_MUTEX_INITIALIZER) but explicit init is portable. */
    ldap_pvt_thread_mutex_init(&conn->c_mutex);
    ldap_pvt_thread_mutex_init(&conn->c_write1_mutex);
    ldap_pvt_thread_cond_init(&conn->c_write1_cv);

    /* Install no-op send callbacks on the fake connection.
     * send_ldap_result/error go through these callbacks. */
    conn->c_send_ldap_result = fuzz_send_ldap_result;
    conn->c_send_search_entry = fuzz_send_search_entry;
    conn->c_send_search_reference = fuzz_send_search_reference;
    conn->c_send_ldap_extended = fuzz_send_ldap_extended;
    conn->c_send_ldap_intermediate = fuzz_send_ldap_intermediate;

    /* Set up a Sockbuf that discards writes and returns EOF on reads.
     * send_ldap_discon() calls send_ldap_disconnect() -> send_ldap_response()
     * -> send_ldap_ber() which writes to conn->c_sb. With c_conn_state =
     * SLAP_C_INVALID (0), send_ldap_ber returns early via !connection_valid(),
     * but having a valid Sockbuf prevents crashes if any other code path
     * dereferences c_sb. */
    conn->c_sb = ber_sockbuf_alloc();

    return 0;
}

/*
 * Reset slab memory for a new fuzzing iteration.
 *
 * Must be called at the top of LLVMFuzzerTestOneInput() for any
 * harness that uses slab-allocated memory (get_filter, do_search,
 * do_bind, etc.). Re-creates the slab with reset flag=1, which
 * resets the stack pointer to the beginning.
 */
static void slapd_fuzz_reset_slab(Operation *op) {
    op->o_tmpmemctx = slap_sl_mem_create(SLAP_SLAB_SIZE, SLAP_SLAB_STACK,
                                          op->o_threadctx, 1);
}

#endif /* SLAPD_FUZZ_INIT_H */
