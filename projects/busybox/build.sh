#!/bin/bash -eu

# Add debugging symbols for GDB
export CFLAGS="$CFLAGS -g -fno-omit-frame-pointer"
export CXXFLAGS="$CXXFLAGS -g -fno-omit-frame-pointer"

make clean CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
yes "" | make oldconfig CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS"
sed -i 's/CONFIG_STATIC=y/# CONFIG_STATIC is not set/' .config
sed -i 's/# CONFIG_USE_PORTABLE_CODE is not set/CONFIG_USE_PORTABLE_CODE=y/' .config
sed -i 's/CONFIG_STATIC_LIBGCC=y/# CONFIG_STATIC_LIBGCC is not set/' .config
sed -i 's/# CONFIG_AR is not set/CONFIG_AR=y/' .config
sed -i 's/# CONFIG_AWK is not set/CONFIG_AWK=y/' .config

make CC="$CC" CXX="$CXX" CFLAGS="$CFLAGS" CXXFLAGS="$CXXFLAGS" -j4

# Compile each fuzzing harness
# $CC, $CXX, $CFLAGS, $CXXFLAGS are provided by oss-fuzz
# $LIB_FUZZING_ENGINE links the fuzzing engine
# $OUT is where fuzzer binaries should be placed

ar rcs libbusybox_static.a $(find . -name "*.o" ! -name "built-in.o" ! -name "appletlib.o")
$CXX $CXXFLAGS -std=c++11 -Iinclude/ -I. \
    $SRC/ar_harness.cpp libbusybox_static.a -lresolv -o $OUT/ar \
    $LIB_FUZZING_ENGINE

$CXX $CXXFLAGS -std=c++11 -Iinclude/ -I. \
    $SRC/awk_harness.cpp libbusybox_static.a -lresolv -lm -Wl,--wrap=exit -o $OUT/awk \
    $LIB_FUZZING_ENGINE

cp $SRC/*.options $OUT/
