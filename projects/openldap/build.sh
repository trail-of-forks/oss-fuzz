#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

cd $SRC/openldap

# Configure for Phase 1-3: liblber/libldap fuzzing only
# slapd is disabled - server-side harnesses require Phase 4 build
./configure \
    --prefix=$SRC/openldap-install \
    --enable-static \
    --disable-shared \
    --disable-slapd \
    --disable-backends \
    --disable-overlays \
    --without-cyrus-sasl \
    --without-tls \
    --disable-syslog \
    --disable-debug

# NOTE: For Phase 4 slapd harnesses, use instead:
# ./configure \
#     --prefix=$SRC/openldap-install \
#     --enable-static \
#     --disable-shared \
#     --enable-slapd \
#     --enable-null \
#     --disable-overlays \
#     --without-cyrus-sasl \
#     --without-tls \
#     --disable-syslog

# Build liblutil first (liblber depends on it), then liblber, then libldap
make -j$(nproc) depend
make -j$(nproc) -C libraries/liblutil
make -j$(nproc) -C libraries/liblber
make -j$(nproc) -C libraries/libldap

# Install headers and libraries in dependency order
make -j$(nproc) -C include install
make -j$(nproc) -C libraries/liblber install
make -j$(nproc) -C libraries/libldap install

# liblutil is not installed by make install, copy it manually from build dir
mkdir -p $SRC/openldap-install/lib
cp $SRC/openldap/libraries/liblutil/liblutil.a $SRC/openldap-install/lib/

# Build fuzzers
# Note: Link order matters for static libraries - dependents before dependencies
# libldap depends on liblber; liblutil may be needed by libldap for some functions
INCLUDES="-I$SRC/openldap-install/include"
LIBS="$SRC/openldap-install/lib/libldap.a \
      $SRC/openldap-install/lib/liblber.a \
      $SRC/openldap-install/lib/liblutil.a"

# Add pthread if needed (some OpenLDAP configurations require it)
# Uncomment if you see undefined references to pthread functions:
# LIBS="$LIBS -lpthread"

# Tier 1: Server-exploitable harnesses (all use ber_get_next with sb_max_incoming)

# Server message parser - unauthenticated (256KB limit)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_slapd_unauth.c -o fuzz_slapd_unauth.o
$CXX $CXXFLAGS fuzz_slapd_unauth.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_slapd_unauth

# Server message parser - authenticated (16MB limit)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_slapd_auth.c -o fuzz_slapd_auth.o
$CXX $CXXFLAGS fuzz_slapd_auth.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_slapd_auth

# BER primitive decoders through server entry point
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_slapd_decode.c -o fuzz_slapd_decode.o
$CXX $CXXFLAGS fuzz_slapd_decode.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_slapd_decode

# Nested/recursive structure parsing through server entry point
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_slapd_nested.c -o fuzz_slapd_nested.o
$CXX $CXXFLAGS fuzz_slapd_nested.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_slapd_nested

# ASN.1 type variations through server entry point
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_slapd_types.c -o fuzz_slapd_types.o
$CXX $CXXFLAGS fuzz_slapd_types.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_slapd_types

# Tier 2: Client library harnesses

# DN parser (libldap client code)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_dn.c -o fuzz_libldap_dn.o
$CXX $CXXFLAGS fuzz_libldap_dn.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_dn

# URL parser (libldap client code)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_url.c -o fuzz_libldap_url.o
$CXX $CXXFLAGS fuzz_libldap_url.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_url

# URL parser with filter component (libldap client code)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_url_filter.c -o fuzz_libldap_url_filter.o
$CXX $CXXFLAGS fuzz_libldap_url_filter.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_url_filter

# Copy verification script
cp $SRC/verify_crash.py $OUT/
chmod +x $OUT/verify_crash.py

# Copy dictionaries
cp $SRC/*.dict $OUT/ 2>/dev/null || true

# Create seed corpora
mkdir -p $OUT/fuzz_slapd_unauth_seed_corpus
mkdir -p $OUT/fuzz_libldap_dn_seed_corpus
mkdir -p $OUT/fuzz_libldap_url_seed_corpus

# DN seeds from LDIF files (extract DN lines)
for ldif in $SRC/openldap/tests/data/*.ldif; do
    if [ -f "$ldif" ]; then
        grep -h "^dn:" "$ldif" 2>/dev/null | sed 's/^dn: //' | while read -r dn; do
            echo -n "$dn" > "$OUT/fuzz_libldap_dn_seed_corpus/$(echo "$dn" | md5sum | cut -c1-16)"
        done
    fi
done

# Create minimal BER seed corpus (hand-crafted valid structures)
# These are minimal valid BER-encoded LDAP messages
# LDAP BindRequest: SEQUENCE { msgid=1, BindRequest { version=3, name="", simple="" } }
printf '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' > $OUT/fuzz_slapd_unauth_seed_corpus/bind_simple
# LDAP SearchRequest minimal
printf '\x30\x1d\x02\x01\x01\x63\x18\x04\x00\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x00\x30\x00' > $OUT/fuzz_slapd_unauth_seed_corpus/search_minimal
# Simple SEQUENCE with INTEGER
printf '\x30\x03\x02\x01\x01' > $OUT/fuzz_slapd_unauth_seed_corpus/seq_int
# Nested SEQUENCEs
printf '\x30\x08\x30\x06\x30\x04\x30\x02\x05\x00' > $OUT/fuzz_slapd_unauth_seed_corpus/nested_seq

# URL seeds
echo -n "ldap://localhost/dc=example,dc=com" > $OUT/fuzz_libldap_url_seed_corpus/basic
echo -n "ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(objectClass=*)" > $OUT/fuzz_libldap_url_seed_corpus/full
echo -n "ldaps://localhost/dc=test??one?(cn=test)" > $OUT/fuzz_libldap_url_seed_corpus/ldaps

# Zip seed corpora
cd $OUT
for corpus_dir in *_seed_corpus; do
    if [ -d "$corpus_dir" ] && [ "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        fuzzer_name="${corpus_dir%_seed_corpus}"
        zip -rj "${fuzzer_name}_seed_corpus.zip" "$corpus_dir/" || true
        rm -rf "$corpus_dir"
    fi
done
