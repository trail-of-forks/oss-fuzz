/*
 * Harness: fuzz_lmdb_load
 *
 * Exercises the LMDB write path by interpreting fuzz data as a sequence
 * of key-value insertions, then reading them back. This tests the B+ tree
 * write/split/merge/rebalance code paths with adversarial data patterns.
 *
 * Complements fuzz_lmdb_read (corrupted file parsing) by exercising the
 * internal tree manipulation logic that can only be reached through the
 * write API.
 *
 * The environment is created once in LLVMFuzzerInitialize() and reused
 * across iterations. Each iteration clears the database with mdb_drop()
 * instead of recreating the directory, avoiding filesystem overhead.
 *
 * Targets: mdb_put(), mdb_del(), B+ tree page splits, overflow pages,
 *          cursor positioning after modifications
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

#include "lmdb.h"

/* Maximum map size for the temporary database */
#define MAP_SIZE (2 * 1024 * 1024)

/* Maximum key size in LMDB (default page size) */
#define MAX_KEY_SIZE 511

/* Operation types derived from fuzz data */
enum op_type {
    OP_PUT = 0,
    OP_PUT_NOOVERWRITE,
    OP_DEL,
    OP_GET,
};

/* Persistent state across fuzzer iterations */
static MDB_env *g_env = NULL;
static MDB_dbi g_dbi;
static int g_dbi_opened = 0;
static char g_tmpdir[64];

static void cleanup_dir(const char *dir) {
    char buf[256];
    snprintf(buf, sizeof(buf), "%s/data.mdb", dir);
    unlink(buf);
    snprintf(buf, sizeof(buf), "%s/lock.mdb", dir);
    unlink(buf);
    rmdir(dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    /* Use /dev/shm for RAM-backed I/O */
    snprintf(g_tmpdir, sizeof(g_tmpdir), "/dev/shm/fuzz_lmdb_wr_XXXXXX");
    if (!mkdtemp(g_tmpdir)) return 0;

    if (mdb_env_create(&g_env) != 0) {
        cleanup_dir(g_tmpdir);
        g_env = NULL;
        return 0;
    }
    mdb_env_set_mapsize(g_env, MAP_SIZE);

    /*
     * MDB_NOSYNC: don't fsync (speed up fuzzing, we don't care about durability)
     * MDB_NOLOCK: no lock file needed for single-threaded fuzzer
     * MDB_WRITEMAP: use writable mmap (exercises different code paths)
     */
    if (mdb_env_open(g_env, g_tmpdir, MDB_NOSYNC | MDB_NOLOCK | MDB_WRITEMAP, 0644) != 0) {
        mdb_env_close(g_env);
        cleanup_dir(g_tmpdir);
        g_env = NULL;
        return 0;
    }

    /* Open the default database once */
    MDB_txn *txn;
    if (mdb_txn_begin(g_env, NULL, 0, &txn) != 0) {
        mdb_env_close(g_env);
        cleanup_dir(g_tmpdir);
        g_env = NULL;
        return 0;
    }
    if (mdb_dbi_open(txn, NULL, 0, &g_dbi) != 0) {
        mdb_txn_abort(txn);
        mdb_env_close(g_env);
        cleanup_dir(g_tmpdir);
        g_env = NULL;
        return 0;
    }
    mdb_txn_commit(txn);
    g_dbi_opened = 1;

    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4 || !g_env || !g_dbi_opened) return 0;

    MDB_txn *txn = NULL;
    MDB_cursor *cursor = NULL;
    int rc;

    /* Clear the database from the previous iteration */
    rc = mdb_txn_begin(g_env, NULL, 0, &txn);
    if (rc != 0) return 0;

    mdb_drop(txn, g_dbi, 0);

    /* Interpret fuzz data as a stream of operations */
    const uint8_t *ptr = data;
    const uint8_t *end = data + size;

    while (ptr + 3 <= end) {
        enum op_type op = *ptr++ % 4;

        uint8_t raw_key_len = *ptr++;
        size_t key_len = raw_key_len == 0 ? 1 : raw_key_len;
        if (key_len > MAX_KEY_SIZE) key_len = MAX_KEY_SIZE;
        if (ptr + key_len > end) break;

        MDB_val key = { key_len, (void *)ptr };
        ptr += key_len;

        switch (op) {
            case OP_PUT:
            case OP_PUT_NOOVERWRITE: {
                if (ptr >= end) goto done_ops;
                uint8_t raw_val_len = *ptr++;
                size_t val_len = raw_val_len;
                if (ptr + val_len > end) val_len = end - ptr;

                MDB_val val = { val_len, (void *)ptr };
                ptr += val_len;

                unsigned int flags = (op == OP_PUT_NOOVERWRITE) ? MDB_NOOVERWRITE : 0;
                mdb_put(txn, g_dbi, &key, &val, flags);
                break;
            }

            case OP_DEL: {
                mdb_del(txn, g_dbi, &key, NULL);
                break;
            }

            case OP_GET: {
                MDB_val val;
                mdb_get(txn, g_dbi, &key, &val);
                break;
            }
        }
    }

done_ops:
    /* Commit the write transaction */
    rc = mdb_txn_commit(txn);
    txn = NULL;

    if (rc != 0) return 0;

    /* Read back everything with a cursor to exercise tree traversal */
    rc = mdb_txn_begin(g_env, NULL, MDB_RDONLY, &txn);
    if (rc != 0) return 0;

    rc = mdb_cursor_open(txn, g_dbi, &cursor);
    if (rc != 0) {
        mdb_txn_abort(txn);
        return 0;
    }

    MDB_val key, val;
    int count = 0;
    while (mdb_cursor_get(cursor, &key, &val, MDB_NEXT) == 0) {
        volatile char c;
        if (key.mv_size > 0) c = ((char *)key.mv_data)[0];
        if (val.mv_size > 0) c = ((char *)val.mv_data)[0];
        (void)c;
        if (++count >= 10000) break;
    }

    /* Also try some cursor positioning operations */
    if (count > 0) {
        mdb_cursor_get(cursor, &key, &val, MDB_FIRST);
        mdb_cursor_get(cursor, &key, &val, MDB_LAST);
    }

    mdb_cursor_close(cursor);
    mdb_txn_abort(txn);
    return 0;
}
