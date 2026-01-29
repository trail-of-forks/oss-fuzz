FROM gcr.io/oss-fuzz-base/base-builder
RUN apt-get update && \
    apt-get install -y make autoconf automake libtool pkg-config libselinux1-dev libpam0g-dev libaudit-dev

RUN git clone --depth 1 git://busybox.net/busybox.git
WORKDIR /src/busybox

COPY build.sh *.cpp $SRC/
