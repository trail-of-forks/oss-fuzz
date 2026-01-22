#!/bin/bash -eu

make clean CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
make allyesconfig CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
sed -i 's/^CONFIG_EXTRA_LDLIBS=.*/CONFIG_EXTRA_LDLIBS="dl audit cap-ng"/' .config
make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"

# Compile each fuzzing harness
# $CC, $CXX, $CFLAGS, $CXXFLAGS are provided by oss-fuzz
# $LIB_FUZZING_ENGINE links the fuzzing engine
# $OUT is where fuzzer binaries should be placed

# $CC $CFLAGS -I. -c harness.c -o harness.o
# $CXX $CXXFLAGS $LIB_FUZZING_ENGINE harness.o \
#     -L. -lyourlib -o $OUT/harness_fuzzer