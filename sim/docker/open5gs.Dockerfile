# Open5GS from source. Two targets:
#   stock    plain v2.8.0, the baseline core and the cached base of every faulted image
#   faulted  stock + exactly one open5gs/faults/${FAULT}.patch; ninja recompiles only what it touches
FROM ubuntu:22.04 AS stock
ARG OPEN5GS_REF=v2.8.0
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git ca-certificates python3-pip python3-setuptools python3-wheel ninja-build build-essential \
      flex bison cmake pkg-config meson libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev \
      libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
      libcurl4-gnutls-dev libtins-dev libtalloc-dev \
      iproute2 iptables iputils-ping tcpdump \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${OPEN5GS_REF} https://github.com/open5gs/open5gs.git /src/open5gs
RUN cd /src/open5gs \
 && meson setup build --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
 && ninja -C build install

FROM stock AS faulted
ARG FAULT
RUN --mount=type=bind,source=open5gs/faults,target=/faults \
    test -n "${FAULT}" && cd /src/open5gs && git apply /faults/${FAULT}.patch \
 && ninja -C build install
