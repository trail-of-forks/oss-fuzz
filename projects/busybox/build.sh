#!/bin/bash -eu

make clean CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
yes "" | make oldconfig CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Compile each fuzzing harness
# $CC, $CXX, $CFLAGS, $CXXFLAGS are provided by oss-fuzz
# $LIB_FUZZING_ENGINE links the fuzzing engine
# $OUT is where fuzzer binaries should be placed

ar rcs libbusybox_static.a $(find . -name "*.o" ! -name "built-in.o")
$CXX $CXXFLAGS -std=c++11 -Iinclude/ -I. \
    $SRC/ar_harness.cpp libbusybox_static.a -lresolv -o $OUT/ar \
    $LIB_FUZZING_ENGINE
