/*
 * Harness: fuzz_lmdb_read
 *
 * Fuzzes LMDB by treating the input as a corrupted .mdb database file,
 * opening it, and attempting read operations (cursor iteration).
 *
 * LMDB uses memory-mapped files with minimal validation of on-disk
 * structures. Corrupted database files are known to cause SIGBUS,
 * SIGSEGV, and wild pointer dereferences (cf. libmdbx issue #217).
 *
 * Attack surface: Any application that opens untrusted or potentially
 * corrupted .mdb files (database recovery, backup restore, shared
 * storage, etc.). Widely deployed in OpenLDAP back-mdb, Monero,
 * PowerDNS, Knot DNS, CFEngine, and many others.
 *
 * Targets: mdb_env_open(), page parsing, B+ tree traversal
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "lmdb.h"

/* Minimum viable .mdb file: must have at least one page header */
#define MIN_MDB_SIZE 4096

/* Cap input to avoid excessive memory mapping */
#define MAX_MDB_SIZE (4 * 1024 * 1024)

/* Maximum entries to iterate before bailing out */
#define MAX_ITERATIONS 1000

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < MIN_MDB_SIZE || size > MAX_MDB_SIZE) {
        return 0;
    }

    /* Write fuzz data to temp file (use /dev/shm for RAM-backed I/O) */
    char path[] = "/dev/shm/fuzz_lmdb_XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;

    if (write(fd, data, size) != (ssize_t)size) {
        close(fd);
        unlink(path);
        return 0;
    }
    close(fd);

    MDB_env *env = NULL;
    MDB_txn *txn = NULL;
    MDB_dbi dbi;
    MDB_cursor *cursor = NULL;

    if (mdb_env_create(&env) != 0) goto cleanup;

    /* Set map size to accommodate the fuzz input */
    mdb_env_set_mapsize(env, size + 4096);

    /*
     * MDB_NOSUBDIR: path is the data file itself, not a directory
     * MDB_RDONLY:    read-only access (we're fuzzing the read path)
     * MDB_NOLOCK:    no lock file (simpler cleanup, single-threaded fuzzer)
     */
    if (mdb_env_open(env, path, MDB_NOSUBDIR | MDB_RDONLY | MDB_NOLOCK, 0644) != 0)
        goto cleanup;

    if (mdb_txn_begin(env, NULL, MDB_RDONLY, &txn) != 0) goto cleanup;
    if (mdb_dbi_open(txn, NULL, 0, &dbi) != 0) goto cleanup;
    if (mdb_cursor_open(txn, dbi, &cursor) != 0) goto cleanup;

    /* Iterate entries — exercises page parsing and B+ tree traversal */
    MDB_val key, val;
    int count = 0;
    while (mdb_cursor_get(cursor, &key, &val, MDB_NEXT) == 0) {
        /* Access data to trigger page reads */
        volatile char c;
        if (key.mv_size > 0) c = ((char *)key.mv_data)[0];
        if (val.mv_size > 0) c = ((char *)val.mv_data)[0];
        (void)c;

        if (++count >= MAX_ITERATIONS) break;
    }

    /* Also try reverse iteration to exercise different page traversal */
    count = 0;
    while (mdb_cursor_get(cursor, &key, &val, MDB_PREV) == 0) {
        volatile char c;
        if (key.mv_size > 0) c = ((char *)key.mv_data)[0];
        if (val.mv_size > 0) c = ((char *)val.mv_data)[0];
        (void)c;

        if (++count >= MAX_ITERATIONS) break;
    }

cleanup:
    if (cursor) mdb_cursor_close(cursor);
    if (txn) mdb_txn_abort(txn);
    if (env) mdb_env_close(env);
    unlink(path);

    /* Clean up lock file if created despite MDB_NOLOCK */
    char lock_path[sizeof(path) + 16];
    snprintf(lock_path, sizeof(lock_path), "%s-lock", path);
    unlink(lock_path);

    return 0;
}
