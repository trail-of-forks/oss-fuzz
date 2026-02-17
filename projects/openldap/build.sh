#!/bin/bash -eu
# Copyright 2024 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.

cd $SRC/openldap

# Phase 1-3: liblber/libldap client library fuzzing
# slapd is disabled here; Phase 4 below builds slapd separately
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

# Tier 3: Client library — BER wire-format parsing through Sockbuf

# Sockbuf BER framing + LDAP message parsing (256KB unauthenticated limit)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_liblber_sockbuf.c -o fuzz_liblber_sockbuf.o
$CXX $CXXFLAGS fuzz_liblber_sockbuf.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblber_sockbuf

# Nested/recursive BER structure parsing through Sockbuf
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_liblber_sockbuf_nested.c -o fuzz_liblber_sockbuf_nested.o
$CXX $CXXFLAGS fuzz_liblber_sockbuf_nested.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblber_sockbuf_nested

# Tier 1: Unicode normalization (genuinely server-exploitable via liblunicode)
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/fuzz_liblunicode_normalize.c -o fuzz_liblunicode_normalize.o
$CXX $CXXFLAGS fuzz_liblunicode_normalize.o $LIBS_UNICODE $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblunicode_normalize

# Tier 2: Client library harnesses

# DN parser (libldap client code)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_dn.c -o fuzz_libldap_dn.o
$CXX $CXXFLAGS fuzz_libldap_dn.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_dn

# URL parser (libldap client code)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_url.c -o fuzz_libldap_url.o
$CXX $CXXFLAGS fuzz_libldap_url.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_url

# Tier 3: Additional client library harnesses

# Schema definition parser (libldap)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_schema.c -o fuzz_libldap_schema.o
$CXX $CXXFLAGS fuzz_libldap_schema.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_schema

# LDIF record parser (libldap)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_libldap_ldif.c -o fuzz_libldap_ldif.o
$CXX $CXXFLAGS fuzz_libldap_ldif.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_ldif

# Filter string -> BER encoder (libldap)
# openldap.h is in the source include dir, not installed — needs INCLUDES_INTERNAL
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/fuzz_libldap_filter.c -o fuzz_libldap_filter.o
$CXX $CXXFLAGS fuzz_libldap_filter.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_libldap_filter

# Direct BER decoding via ber_init (liblber, no Sockbuf)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_liblber_ber_init.c -o fuzz_liblber_ber_init.o
$CXX $CXXFLAGS fuzz_liblber_ber_init.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblber_ber_init

# BER encode-decode round-trip (liblber)
$CC $CFLAGS $INCLUDES -c $SRC/fuzz_liblber_encode.c -o fuzz_liblber_encode.o
$CXX $CXXFLAGS fuzz_liblber_encode.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_liblber_encode

# Base64 decode/encode round-trip (liblutil)
# Needs internal includes for lutil.h -> portable.h and ac/socket.h
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/fuzz_lutil_base64.c -o fuzz_lutil_base64.o
$CXX $CXXFLAGS fuzz_lutil_base64.o $LIBS $LIB_FUZZING_ENGINE -o $OUT/fuzz_lutil_base64

# Build crash triage tool (standalone binary, not a fuzzer)
$CC $CFLAGS $INCLUDES_INTERNAL -c $SRC/validate_unicode_crash.c -o validate_unicode_crash.o
$CC $CFLAGS validate_unicode_crash.o $LIBS_UNICODE -o $OUT/validate_unicode_crash

# Copy verification script
cp $SRC/verify_crash.py $OUT/
chmod +x $OUT/verify_crash.py

# === Phase 4: slapd server-side harnesses ===
# Build slapd with null backend to get server-side object files
cd $SRC/openldap
make clean

./configure \
    --prefix=$SRC/openldap-slapd-install \
    --enable-static \
    --disable-shared \
    --enable-slapd \
    --enable-null \
    --enable-backends=no \
    --enable-overlays=no \
    --without-cyrus-sasl \
    --without-tls \
    --disable-syslog \
    --disable-debug

make -j$(nproc) depend
make -j$(nproc)
make install

# Copy internal libraries not installed by make install
cp $SRC/openldap/libraries/liblutil/liblutil.a $SRC/openldap-slapd-install/lib/
cp $SRC/openldap/libraries/liblunicode/liblunicode.a $SRC/openldap-slapd-install/lib/

# Create slapd static archive from all .o files except main.o
cd servers/slapd
ar rcs libslapd_fuzz.a $(ls *.o | grep -v main.o)

# Create null backend static archive
cd back-null
ar rcs libnull_fuzz.a *.o
cd $SRC/openldap

# Copy schema files to $OUT so they're available at runtime
cp -r $SRC/openldap-slapd-install/etc/openldap/schema $OUT/schema

# Generate slapd.conf — use path relative to where harness runs (/out/)
sed "s|SCHEMA_DIR|/out/schema|g" $SRC/slapd_fuzz.conf > $OUT/slapd_fuzz.conf

# Slapd include paths and libraries
SLAPD_INCLUDES="-I$SRC/openldap/servers/slapd \
    -I$SRC/openldap/include \
    -I$SRC/openldap-slapd-install/include"

SLAPD_LIBS="$SRC/openldap/servers/slapd/libslapd_fuzz.a \
    $SRC/openldap/servers/slapd/back-null/libnull_fuzz.a \
    $SRC/openldap-slapd-install/lib/liblunicode.a \
    $SRC/openldap/libraries/librewrite/librewrite.a \
    $SRC/openldap-slapd-install/lib/liblutil.a \
    $SRC/openldap-slapd-install/lib/libldap.a \
    $SRC/openldap-slapd-install/lib/liblber.a"

WRAP_FLAGS="-Wl,--wrap=sleep,--wrap=nanosleep,--wrap=gettimeofday,--wrap=ldap_pvt_thread_pool_tid"

# Compile stubs
$CC $CFLAGS $SLAPD_INCLUDES -c $SRC/slapd_stubs.c -o $SRC/slapd_stubs.o

# Build each slapd harness
for harness in fuzz_slapd_filter fuzz_slapd_entry fuzz_slapd_dn fuzz_slapd_search fuzz_slapd_bind; do
    $CC $CFLAGS $SLAPD_INCLUDES -c $SRC/${harness}.c -o $SRC/${harness}.o
    $CXX $CXXFLAGS $LIB_FUZZING_ENGINE \
        $SRC/${harness}.o $SRC/slapd_stubs.o \
        $SLAPD_LIBS $WRAP_FLAGS \
        -lresolv -lpthread \
        -o $OUT/${harness}
done

# Copy dictionaries
cp $SRC/*.dict $OUT/ 2>/dev/null || true

# Associate dictionaries with harnesses
cp $OUT/unicode.dict $OUT/fuzz_liblunicode_normalize.dict 2>/dev/null || true
cp $OUT/schema.dict $OUT/fuzz_libldap_schema.dict 2>/dev/null || true
cp $OUT/ldif.dict $OUT/fuzz_libldap_ldif.dict 2>/dev/null || true
cp $OUT/filter.dict $OUT/fuzz_libldap_filter.dict 2>/dev/null || true
cp $OUT/ber.dict $OUT/fuzz_liblber_ber_init.dict 2>/dev/null || true
cp $OUT/ber.dict $OUT/fuzz_liblber_encode.dict 2>/dev/null || true
cp $OUT/base64.dict $OUT/fuzz_lutil_base64.dict 2>/dev/null || true
cp $OUT/dn.dict $OUT/fuzz_libldap_dn.dict 2>/dev/null || true

# Associate BER dictionary with Sockbuf-based harnesses
cp $OUT/ber.dict $OUT/fuzz_liblber_sockbuf.dict 2>/dev/null || true
cp $OUT/ber.dict $OUT/fuzz_liblber_sockbuf_nested.dict 2>/dev/null || true

# Associate dictionaries with slapd harnesses
cp $OUT/ber.dict $OUT/fuzz_slapd_filter.dict 2>/dev/null || true
cp $OUT/ldif.dict $OUT/fuzz_slapd_entry.dict 2>/dev/null || true
cp $OUT/dn.dict $OUT/fuzz_slapd_dn.dict 2>/dev/null || true
cp $OUT/ber.dict $OUT/fuzz_slapd_search.dict 2>/dev/null || true
cp $OUT/ber.dict $OUT/fuzz_slapd_bind.dict 2>/dev/null || true

# Create seed corpora
mkdir -p $OUT/fuzz_liblber_sockbuf_seed_corpus
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
# LDAP BindRequest: SEQUENCE { msgid=1, BindRequest { version=3, name="", simple="" } }
printf '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' > $OUT/fuzz_liblber_sockbuf_seed_corpus/bind_simple
# LDAP SearchRequest minimal
printf '\x30\x1d\x02\x01\x01\x63\x18\x04\x00\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x00\x30\x00' > $OUT/fuzz_liblber_sockbuf_seed_corpus/search_minimal
# Simple SEQUENCE with INTEGER
printf '\x30\x03\x02\x01\x01' > $OUT/fuzz_liblber_sockbuf_seed_corpus/seq_int
# Nested SEQUENCEs
printf '\x30\x08\x30\x06\x30\x04\x30\x02\x05\x00' > $OUT/fuzz_liblber_sockbuf_seed_corpus/nested_seq

# URL seeds (including filter component for coverage — replaces fuzz_libldap_url_filter)
echo -n "ldap://localhost/dc=example,dc=com" > $OUT/fuzz_libldap_url_seed_corpus/basic
echo -n "ldap://localhost:389/dc=example,dc=com?cn,sn?sub?(objectClass=*)" > $OUT/fuzz_libldap_url_seed_corpus/full
echo -n "ldaps://localhost/dc=test??one?(cn=test)" > $OUT/fuzz_libldap_url_seed_corpus/ldaps
echo -n "ldap://localhost/dc=test??sub?(cn=test)" > $OUT/fuzz_libldap_url_seed_corpus/url_with_filter

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

# Schema seed corpus
mkdir -p $OUT/fuzz_libldap_schema_seed_corpus
echo -n "( 2.5.6.6 NAME 'person' DESC 'RFC2256: a person' SUP top STRUCTURAL MUST ( sn \$ cn ) MAY ( userPassword \$ telephoneNumber \$ seeAlso \$ description ) )" > $OUT/fuzz_libldap_schema_seed_corpus/objectclass
echo -n "( 2.5.4.3 NAME ( 'cn' 'commonName' ) DESC 'RFC4519: common name' SUP name )" > $OUT/fuzz_libldap_schema_seed_corpus/attributetype
echo -n "( 1.3.6.1.4.1.1466.115.121.1.15 DESC 'Directory String' )" > $OUT/fuzz_libldap_schema_seed_corpus/syntax
echo -n "( 2.5.13.2 NAME 'caseIgnoreMatch' SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )" > $OUT/fuzz_libldap_schema_seed_corpus/matchingrule
echo -n "( 2.5.13.2 NAME 'caseIgnoreMatch' APPLIES ( cn \$ sn \$ description ) )" > $OUT/fuzz_libldap_schema_seed_corpus/matchingruleuse
echo -n "( 2.5.6.6 NAME 'personContent' AUX posixAccount MUST uid MAY description )" > $OUT/fuzz_libldap_schema_seed_corpus/contentrule
echo -n "( 1.3.6.1.4.1.99999.1 NAME 'personForm' OC person MUST cn )" > $OUT/fuzz_libldap_schema_seed_corpus/nameform
echo -n "( 1 NAME 'personStructure' FORM personForm )" > $OUT/fuzz_libldap_schema_seed_corpus/structurerule

# LDIF seed corpus
mkdir -p $OUT/fuzz_libldap_ldif_seed_corpus
for ldif in $SRC/openldap/tests/data/*.ldif; do
    if [ -f "$ldif" ]; then
        base=$(basename "$ldif" .ldif)
        head -50 "$ldif" > "$OUT/fuzz_libldap_ldif_seed_corpus/$base" 2>/dev/null || true
    fi
done
printf 'dn: cn=test,dc=example,dc=com\nobjectClass: person\ncn: test\nsn: user\n' > $OUT/fuzz_libldap_ldif_seed_corpus/simple_entry
printf 'dn:: Y249dGVzdCxkYz1leGFtcGxlLGRjPWNvbQ==\nobjectClass: person\ncn: test\nsn: user\n' > $OUT/fuzz_libldap_ldif_seed_corpus/base64_dn
printf 'dn: cn=test,dc=example,dc=com\nchangetype: modify\nadd: description\ndescription: test value\n-\n' > $OUT/fuzz_libldap_ldif_seed_corpus/modify_entry

# Filter seed corpus
mkdir -p $OUT/fuzz_libldap_filter_seed_corpus
echo -n "(objectClass=*)" > $OUT/fuzz_libldap_filter_seed_corpus/present
echo -n "(cn=test)" > $OUT/fuzz_libldap_filter_seed_corpus/equality
echo -n "(&(objectClass=person)(cn=John*))" > $OUT/fuzz_libldap_filter_seed_corpus/and_substr
echo -n "(|(uid=admin)(uid=root))" > $OUT/fuzz_libldap_filter_seed_corpus/or
echo -n "(!(cn=disabled))" > $OUT/fuzz_libldap_filter_seed_corpus/not
echo -n "(cn=test\\28with parens\\29)" > $OUT/fuzz_libldap_filter_seed_corpus/escaped
echo -n "(cn:caseIgnoreMatch:=test)" > $OUT/fuzz_libldap_filter_seed_corpus/extensible
echo -n "(cn>=M)" > $OUT/fuzz_libldap_filter_seed_corpus/greater_or_equal
echo -n "(sn=*müller*)" > $OUT/fuzz_libldap_filter_seed_corpus/substring_utf8

# BER init seed corpus (raw BER, no Sockbuf wrapper)
mkdir -p $OUT/fuzz_liblber_ber_init_seed_corpus
printf '\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00' > $OUT/fuzz_liblber_ber_init_seed_corpus/bind
printf '\x02\x01\x01' > $OUT/fuzz_liblber_ber_init_seed_corpus/integer
printf '\x04\x05hello' > $OUT/fuzz_liblber_ber_init_seed_corpus/string
printf '\x30\x06\x02\x01\x01\x02\x01\x02' > $OUT/fuzz_liblber_ber_init_seed_corpus/seq_ints
printf '\x01\x01\xff' > $OUT/fuzz_liblber_ber_init_seed_corpus/bool_true
printf '\x01\x01\x00' > $OUT/fuzz_liblber_ber_init_seed_corpus/bool_false
printf '\x05\x00' > $OUT/fuzz_liblber_ber_init_seed_corpus/null_val
printf '\x03\x03\x04\x0a\xc0' > $OUT/fuzz_liblber_ber_init_seed_corpus/bitstring

# BER encode seed corpus (command sequences)
mkdir -p $OUT/fuzz_liblber_encode_seed_corpus
# Encode an integer (opcode 0 + 4 bytes of value)
printf '\x00\x00\x00\x00\x01' > $OUT/fuzz_liblber_encode_seed_corpus/encode_int
# Encode a string (opcode 1 + 1 byte length + data)
printf '\x01\x05hello' > $OUT/fuzz_liblber_encode_seed_corpus/encode_string
# Encode a sequence with integer and string
printf '\x05\x00\x00\x00\x00\x01\x01\x05hello\x06' > $OUT/fuzz_liblber_encode_seed_corpus/encode_seq
# Encode boolean true
printf '\x02\x01' > $OUT/fuzz_liblber_encode_seed_corpus/encode_bool
# Encode null
printf '\x03' > $OUT/fuzz_liblber_encode_seed_corpus/encode_null

# Base64 seed corpus
mkdir -p $OUT/fuzz_lutil_base64_seed_corpus
echo -n "dGVzdA==" > $OUT/fuzz_lutil_base64_seed_corpus/test
echo -n "SGVsbG8gV29ybGQ=" > $OUT/fuzz_lutil_base64_seed_corpus/hello_world
echo -n "AAAA" > $OUT/fuzz_lutil_base64_seed_corpus/nulls
echo -n "/////w==" > $OUT/fuzz_lutil_base64_seed_corpus/allff
echo -n "YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=" > $OUT/fuzz_lutil_base64_seed_corpus/alphabet
echo -n "" > $OUT/fuzz_lutil_base64_seed_corpus/empty
echo -n "QQ==" > $OUT/fuzz_lutil_base64_seed_corpus/single_char

# === Slapd harness seed corpora ===

# BER-encoded filter seeds for fuzz_slapd_filter
mkdir -p $OUT/fuzz_slapd_filter_seed_corpus
# (objectClass=*) — present filter (tag 0x87)
printf '\x87\x0bobjectClass' > $OUT/fuzz_slapd_filter_seed_corpus/present
# (cn=test) — equality filter (tag 0xa3)
printf '\xa3\x0c\x04\x02cn\x04\x04test' > $OUT/fuzz_slapd_filter_seed_corpus/equality
# (&(objectClass=*)(cn=test)) — AND filter (tag 0xa0)
printf '\xa0\x1b\x87\x0bobjectClass\xa3\x0c\x04\x02cn\x04\x04test' > $OUT/fuzz_slapd_filter_seed_corpus/and_filter
# (|(cn=a)(cn=b)) — OR filter (tag 0xa1)
printf '\xa1\x14\xa3\x09\x04\x02cn\x04\x01a\xa3\x09\x04\x02cn\x04\x01b' > $OUT/fuzz_slapd_filter_seed_corpus/or_filter
# (!(cn=test)) — NOT filter (tag 0xa2)
printf '\xa2\x0e\xa3\x0c\x04\x02cn\x04\x04test' > $OUT/fuzz_slapd_filter_seed_corpus/not_filter
# (cn=te*st) — substring filter (tag 0xa4)
printf '\xa4\x10\x04\x02cn\x30\x0a\x80\x02te\x82\x02st' > $OUT/fuzz_slapd_filter_seed_corpus/substring
# (cn>=test) — GE filter (tag 0xa5)
printf '\xa5\x0c\x04\x02cn\x04\x04test' > $OUT/fuzz_slapd_filter_seed_corpus/ge_filter
# (cn<=test) — LE filter (tag 0xa6)
printf '\xa6\x0c\x04\x02cn\x04\x04test' > $OUT/fuzz_slapd_filter_seed_corpus/le_filter

# LDIF entry seeds for fuzz_slapd_entry
mkdir -p $OUT/fuzz_slapd_entry_seed_corpus
printf 'dn: cn=test,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: test\nsn: Test\n' > $OUT/fuzz_slapd_entry_seed_corpus/person
printf 'dn: dc=example,dc=com\nobjectClass: top\nobjectClass: domain\ndc: example\n' > $OUT/fuzz_slapd_entry_seed_corpus/domain
printf 'dn: ou=people,dc=example,dc=com\nobjectClass: top\nobjectClass: organizationalUnit\nou: people\n' > $OUT/fuzz_slapd_entry_seed_corpus/ou
printf 'dn: cn=admin,dc=example,dc=com\nobjectClass: top\nobjectClass: person\ncn: admin\nsn: Admin\ndescription: Administrator account\n' > $OUT/fuzz_slapd_entry_seed_corpus/admin

# DN string seeds for fuzz_slapd_dn
mkdir -p $OUT/fuzz_slapd_dn_seed_corpus
echo -n "cn=test,dc=example,dc=com" > $OUT/fuzz_slapd_dn_seed_corpus/simple
echo -n "cn=test+sn=user,ou=people,dc=example,dc=com" > $OUT/fuzz_slapd_dn_seed_corpus/multivalued
echo -n "cn=test\,escaped,dc=example,dc=com" > $OUT/fuzz_slapd_dn_seed_corpus/escaped
echo -n "dc=example,dc=com" > $OUT/fuzz_slapd_dn_seed_corpus/short
echo -n "ou=people,ou=division,o=company,c=US" > $OUT/fuzz_slapd_dn_seed_corpus/deep
echo -n "cn=#414243,dc=example,dc=com" > $OUT/fuzz_slapd_dn_seed_corpus/hex_value

# BER-encoded SearchRequest seeds for fuzz_slapd_search
# These are APPLICATION[3] CONSTRUCTED PDUs (tag 0x63) as expected by do_search().
mkdir -p $OUT/fuzz_slapd_search_seed_corpus
# Minimal SearchRequest: base="", scope=subtree, deref=never, slimit=0, tlimit=0,
# attrsonly=false, filter=(objectClass=*), attrs={}
printf '\x63\x18\x04\x00\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\x87\x0bobjectClass\x30\x00' > $OUT/fuzz_slapd_search_seed_corpus/minimal
# SearchRequest with base DN, scope=base, equality filter (cn=test), attrs={cn}
printf '\x63\x2e\x04\x11dc=example,dc=com\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa3\x0c\x04\x02cn\x04\x04test\x30\x06\x04\x02cn' > $OUT/fuzz_slapd_search_seed_corpus/eq_filter
# SearchRequest with AND filter: (&(objectClass=person)(cn=*))
printf '\x63\x2b\x04\x00\x0a\x01\x02\x0a\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0\x16\x87\x06person\xa3\x0c\x04\x02cn\x04\x04test\x30\x00' > $OUT/fuzz_slapd_search_seed_corpus/and_filter

# BER-encoded BindRequest seeds for fuzz_slapd_bind
# These are APPLICATION[0] CONSTRUCTED PDUs (tag 0x60) as expected by do_bind().
mkdir -p $OUT/fuzz_slapd_bind_seed_corpus
# Simple bind: version=3, name="", simple auth=""
printf '\x60\x07\x02\x01\x03\x04\x00\x80\x00' > $OUT/fuzz_slapd_bind_seed_corpus/anon_simple
# Simple bind: version=3, name="cn=admin,dc=example,dc=com", password="secret"
printf '\x60\x24\x02\x01\x03\x04\x19cn=admin,dc=example,dc=com\x80\x06secret' > $OUT/fuzz_slapd_bind_seed_corpus/admin_simple
# SASL bind: version=3, name="", SASL mechanism="EXTERNAL"
printf '\x60\x14\x02\x01\x03\x04\x00\xa3\x0d\x04\x08EXTERNAL\x04\x01\x00' > $OUT/fuzz_slapd_bind_seed_corpus/sasl_external

# Zip seed corpora
cd $OUT
for corpus_dir in *_seed_corpus; do
    if [ -d "$corpus_dir" ] && [ "$(ls -A "$corpus_dir" 2>/dev/null)" ]; then
        fuzzer_name="${corpus_dir%_seed_corpus}"
        zip -rj "${fuzzer_name}_seed_corpus.zip" "$corpus_dir/" || true
        rm -rf "$corpus_dir"
    fi
done
