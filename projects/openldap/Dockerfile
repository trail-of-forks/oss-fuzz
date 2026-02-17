# Copyright 2025 Trail of Bits
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0

FROM gcr.io/oss-fuzz-base/base-builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    make \
    autoconf \
    automake \
    libtool \
    pkg-config \
    groff-base \
    libssl-dev \
    libsasl2-dev

# Clone OpenLDAP
RUN git clone --depth 1 https://git.openldap.org/openldap/openldap.git

# Clone seed corpus from LDAP test data
# (OpenLDAP tests contain BER-encoded messages)

WORKDIR openldap
COPY build.sh *.c *.h *.dict *.py *.conf $SRC/
