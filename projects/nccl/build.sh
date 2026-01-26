#!/bin/bash -eu
# Copyright 2023 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# CUDA does not support clang versions above 10.0. This should not affect the
# target of the fuzzers, however, during build we still need to allow it to
# compile with the OSS-Fuzz clang version.
sed -i 's/^NVCUFLAGS  :=/NVCUFLAGS  := -allow-unsupported-compiler/' ./makefiles/common.mk
sed -i 's/^NVCUFLAGS_SYM += -ccbin/NVCUFLAGS_SYM += -allow-unsupported-compiler -ccbin/' \
    ./src/device/Makefile

# The makefile has a target which is missing in the open-source repo
sed -i 's/^TARGETS := debian txz doc/TARGETS := debian txz/' ./pkg/Makefile

# NCCL requires libstdc++ (uses bits/c++config.h internal header)
export CXXFLAGS="$CXXFLAGS -stdlib=libstdc++"

# TODO: Remove this temporary fix once PR is merged: https://github.com/NVIDIA/nccl/pull/1971
sed -i 's/cumemhandle(nullptr)/cumemhandle(0)/g' ./src/transport/net_ib/gdaki/gin_host_gdaki.cc

make clean
make -j3 src.build

$CXX $LIB_FUZZING_ENGINE $CXXFLAGS -DNCCL_OS_LINUX $SRC/fuzz_xml.cpp -o $OUT/fuzz_xml \
    -I./src/graph/ -I./src/include -I./build/include/ -I./src/include/plugin -I./src/include/os  \
    -I/usr/local/cuda-12.9/targets/x86_64-linux/include/ -latomic -lpthread -lrt -ldl \
    ./build/lib/libnccl_static.a \
    /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcudart.so

cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcudart.so.12.9.79 $OUT/libcudart.so.12.9.79
cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcudart.so.12 $OUT/libcudart.so.12
cp /usr/local/cuda-12.9/targets/x86_64-linux/lib/libcudart.so $OUT/libcudart.so
patchelf --set-rpath '$ORIGIN/' $OUT/fuzz_xml
