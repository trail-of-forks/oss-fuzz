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

# Build liblutil first (liblber depends on it), then liblber, libldap, liblunicode
make -j$(nproc) depend
make -j$(nproc) -C libraries/liblutil
make -j$(nproc) -C libraries/liblber
make -j$(nproc) -C libraries/libldap
make -j$(nproc) -C libraries/liblunicode

# Install headers and libraries in dependency order
make -j$(nproc) -C include install
make -j$(nproc) -C libraries/liblber install
make -j$(nproc) -C libraries/libldap install

# liblutil and liblunicode are not installed by make install, copy manually
mkdir -p $SRC/openldap-install/lib
cp $SRC/openldap/libraries/liblutil/liblutil.a $SRC/openldap-install/lib/
cp $SRC/openldap/libraries/liblunicode/liblunicode.a $SRC/openldap-install/lib/

# Build fuzzers
# Note: Link order matters for static libraries - dependents before dependencies
# libldap depends on liblber; liblutil may be needed by libldap for some functions
INCLUDES="-I$SRC/openldap-install/include"
LIBS="$SRC/openldap-install/lib/libldap.a \
      $SRC/openldap-install/lib/liblber.a \
      $SRC/openldap-install/lib/liblutil.a"

# liblunicode needs internal headers (ldap_pvt_uc.h is not installed)
# Include paths: installed public headers, source internal headers, source root (for portable.h)
INCLUDES_INTERNAL="-I$SRC/openldap-install/include -I$SRC/openldap/include -I$SRC/openldap"
LIBS_UNICODE="$SRC/openldap-install/lib/liblunicode.a \
              $SRC/openldap-install/lib/libldap.a \
              $SRC/openldap-install/lib/liblber.a \
              $SRC/openldap-install/lib/liblutil.a"

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

# Unicode normalization (liblunicode)
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/fuzz_liblunicode_normalize.c -o fuzz_liblunicode_normalize.o
$CXX $CXXFLAGS fuzz_liblunicode_normalize.o $LIBS_UNICODE $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblunicode_normalize

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

# Build crash triage tool (standalone binary, not a fuzzer)
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/validate_unicode_crash.c -o validate_unicode_crash.o
$CC $CFLAGS validate_unicode_crash.o $LIBS_UNICODE -o $OUT/validate_unicode_crash

# Copy verification script
cp $SRC/verify_crash.py $OUT/
chmod +x $OUT/verify_crash.py

# Copy dictionaries
cp $SRC/*.dict $OUT/ 2>/dev/null || true

# Associate unicode dictionary with the liblunicode harness
cp $OUT/unicode.dict $OUT/fuzz_liblunicode_normalize.dict 2>/dev/null || true

# Create seed corpora
mkdir -p $OUT/fuzz_slapd_unauth_seed_corpus
mkdir -p $OUT/fuzz_libldap_dn_seed_corpus
mkdir -p $OUT/fuzz_libldap_url_seed_corpus
mkdir -p $OUT/fuzz_liblunicode_normalize_seed_corpus

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

# Unicode normalization seed corpus
echo -n "Hello, World!" > $OUT/fuzz_liblunicode_normalize_seed_corpus/ascii
printf '\xc3\x89\x74\x75\x64\x65' > $OUT/fuzz_liblunicode_normalize_seed_corpus/latin_accents
printf '\x45\xcc\x81\x74\x75\x64\x65' > $OUT/fuzz_liblunicode_normalize_seed_corpus/latin_decomposed
printf '\xe4\xb8\xad\xe6\x96\x87\xe6\xb5\x8b\xe8\xaf\x95' > $OUT/fuzz_liblunicode_normalize_seed_corpus/cjk
printf '\xea\xb0\x80\xeb\x82\x98\xeb\x8b\xa4' > $OUT/fuzz_liblunicode_normalize_seed_corpus/hangul
printf '\xe1\x84\x80\xe1\x85\xa1\xe1\x84\x82\xe1\x85\xa1\xe1\x84\x83\xe1\x85\xa1' > $OUT/fuzz_liblunicode_normalize_seed_corpus/hangul_jamo
printf '\xd8\xa7\xd9\x84\xd8\xb9\xd8\xb1\xd8\xa8\xd9\x8a\xd8\xa9' > $OUT/fuzz_liblunicode_normalize_seed_corpus/arabic
printf '\x41\x42\x43\xc3\xa9\xe4\xb8\xad\xf0\x9f\x98\x80' > $OUT/fuzz_liblunicode_normalize_seed_corpus/mixed
printf '\xef\xac\x81\xef\xac\x82' > $OUT/fuzz_liblunicode_normalize_seed_corpus/compat_ligatures
printf '\xc3\x9f\x53\x54\x52\x41\xc3\x9f\x45' > $OUT/fuzz_liblunicode_normalize_seed_corpus/casefold
printf '\x61\xcc\x81\xcc\x88\xcc\xa7\xcc\x8c' > $OUT/fuzz_liblunicode_normalize_seed_corpus/multi_combining
printf '\xef\xbb\xbf\x74\x65\x73\x74' > $OUT/fuzz_liblunicode_normalize_seed_corpus/bom_prefix
printf '\x63\x6e\x3d\xc3\xa9\x74\x75\x64\x65\x2c\x64\x63\x3d\xe4\xb8\xad\xe6\x96\x87' > $OUT/fuzz_liblunicode_normalize_seed_corpus/dn_unicode

# Zip seed corpora
cd $OUT
for corpus_dir in *_seed_corpus; do
    if [ -d "$corpus_dir" ] && [ "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        fuzzer_name="${corpus_dir%_seed_corpus}"
        zip -rj "${fuzzer_name}_seed_corpus.zip" "$corpus_dir/" || true
        rm -rf "$corpus_dir"
    fi
done
