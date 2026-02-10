# Copyright 2025 Trail of Bits
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y \
    make

# Clone LMDB (standalone mirror)
RUN git clone --depth 1 https://github.com/LMDB/lmdb.git

WORKDIR lmdb
COPY build.sh *.c $SRC/
