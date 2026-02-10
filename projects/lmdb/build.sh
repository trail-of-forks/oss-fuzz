#!/bin/bash -eu
# Copyright 2025 Trail of Bits
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

cd $SRC/lmdb/libraries/liblmdb

# Build LMDB static library with fuzzer-compatible flags
# LMDB's Makefile uses its own CFLAGS, so we build manually
$CC $CFLAGS -c mdb.c -o mdb.o
$CC $CFLAGS -c midl.c -o midl.o
ar rcs liblmdb.a mdb.o midl.o

INCLUDES="-I$SRC/lmdb/libraries/liblmdb"
LIBS="$SRC/lmdb/libraries/liblmdb/liblmdb.a -lpthread"

# Build fuzz_lmdb_read: corrupted database file fuzzer
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_lmdb_read.c -o fuzz_lmdb_read.o
$CXX $CXXFLAGS fuzz_lmdb_read.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_lmdb_read

# Build fuzz_lmdb_load: write-path exerciser
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_lmdb_load.c -o fuzz_lmdb_load.o
$CXX $CXXFLAGS fuzz_lmdb_load.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_lmdb_load

# Build mdb_load utility for seed corpus generation
$CC $CFLAGS mdb_load.c liblmdb.a -lpthread -o mdb_load_tool
$CC $CFLAGS mdb_stat.c liblmdb.a -lpthread -o mdb_stat_tool

# === Generate seed corpus for fuzz_lmdb_read ===
mkdir -p $OUT/fuzz_lmdb_read_seed_corpus

# Create a valid database with sample data using the LMDB API
cat > /tmp/gen_seed.c << 'SEED_EOF'
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include "lmdb.h"

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;

    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    int rc;

    mkdir(argv[1], 0755);

    rc = mdb_env_create(&env);
    if (rc) return 1;
    mdb_env_set_mapsize(env, 1048576);
    rc = mdb_env_open(env, argv[1], MDB_NOSYNC, 0644);
    if (rc) return 1;

    rc = mdb_txn_begin(env, NULL, 0, &txn);
    if (rc) { mdb_env_close(env); return 1; }

    rc = mdb_dbi_open(txn, NULL, 0, &dbi);
    if (rc) { mdb_txn_abort(txn); mdb_env_close(env); return 1; }

    /* Insert sample key-value pairs */
    char *keys[] = {"alpha", "beta", "gamma", "delta", "epsilon",
                    "cn=admin,dc=example,dc=com", "uid=user1",
                    "objectClass=person"};
    char *vals[] = {"first", "second", "third", "fourth", "fifth",
                    "admin-entry", "user-entry", "person-class"};
    int n = sizeof(keys) / sizeof(keys[0]);

    for (int i = 0; i < n; i++) {
        MDB_val k = { strlen(keys[i]), keys[i] };
        MDB_val v = { strlen(vals[i]), vals[i] };
        mdb_put(txn, dbi, &k, &v, 0);
    }

    mdb_txn_commit(txn);
    mdb_env_close(env);
    return 0;
}
SEED_EOF

$CC $CFLAGS -I. /tmp/gen_seed.c liblmdb.a -lpthread -o /tmp/gen_seed

# Generate a seed database
/tmp/gen_seed /tmp/seed_db
if [ -f /tmp/seed_db/data.mdb ]; then
    cp /tmp/seed_db/data.mdb $OUT/fuzz_lmdb_read_seed_corpus/valid_db
fi
rm -rf /tmp/seed_db /tmp/gen_seed /tmp/gen_seed.c

# Create minimal empty database seed
mkdir -p /tmp/empty_db
cat > /tmp/gen_empty.c << 'EMPTY_EOF'
#include <stdio.h>
#include <sys/stat.h>
#include "lmdb.h"

int main(int argc, char *argv[]) {
    if (argc < 2) return 1;
    MDB_env *env;
    MDB_txn *txn;
    MDB_dbi dbi;
    mkdir(argv[1], 0755);
    if (mdb_env_create(&env)) return 1;
    mdb_env_set_mapsize(env, 1048576);
    if (mdb_env_open(env, argv[1], MDB_NOSYNC, 0644)) return 1;
    if (mdb_txn_begin(env, NULL, 0, &txn)) { mdb_env_close(env); return 1; }
    if (mdb_dbi_open(txn, NULL, 0, &dbi)) { mdb_txn_abort(txn); mdb_env_close(env); return 1; }
    mdb_txn_commit(txn);
    mdb_env_close(env);
    return 0;
}
EMPTY_EOF

$CC $CFLAGS -I. /tmp/gen_empty.c liblmdb.a -lpthread -o /tmp/gen_empty
/tmp/gen_empty /tmp/empty_db
if [ -f /tmp/empty_db/data.mdb ]; then
    cp /tmp/empty_db/data.mdb $OUT/fuzz_lmdb_read_seed_corpus/empty_db
fi
rm -rf /tmp/empty_db /tmp/gen_empty /tmp/gen_empty.c

# === Generate seed corpus for fuzz_lmdb_load ===
mkdir -p $OUT/fuzz_lmdb_load_seed_corpus

# Simple key-value insertion sequences (op=0/PUT, key_len, key, val_len, val)
# Single PUT: op=0, key_len=5, "hello", val_len=5, "world"
printf '\x00\x05hello\x05world' > $OUT/fuzz_lmdb_load_seed_corpus/single_put
# Multiple PUTs with increasing keys
printf '\x00\x01a\x01x\x00\x01b\x01y\x00\x01c\x01z' > $OUT/fuzz_lmdb_load_seed_corpus/multi_put
# PUT then DELETE
printf '\x00\x03foo\x03bar\x02\x03foo' > $OUT/fuzz_lmdb_load_seed_corpus/put_del
# PUT with NOOVERWRITE
printf '\x00\x03key\x05value\x01\x03key\x06value2' > $OUT/fuzz_lmdb_load_seed_corpus/nooverwrite
# Many small keys (triggers page splits)
printf '\x00\x01\x01\x01\x41\x00\x01\x02\x01\x42\x00\x01\x03\x01\x43\x00\x01\x04\x01\x44\x00\x01\x05\x01\x45\x00\x01\x06\x01\x46\x00\x01\x07\x01\x47\x00\x01\x08\x01\x48' > $OUT/fuzz_lmdb_load_seed_corpus/many_small

# Zip seed corpora
cd $OUT
for corpus_dir in *_seed_corpus; do
    if [ -d "$corpus_dir" ] && [ "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        fuzzer_name="${corpus_dir%_seed_corpus}"
        zip -rj "${fuzzer_name}_seed_corpus.zip" "$corpus_dir/" || true
        rm -rf "$corpus_dir"
    fi
done
