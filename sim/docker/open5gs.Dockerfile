# Open5GS from source, with the fault-injection hooks in open5gs/*.patch.
# Faults stay off unless FIVEG_SIM_FAULTS names them, so this is also the baseline core.
FROM ubuntu:22.04
ARG OPEN5GS_REF=v2.8.0
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git ca-certificates python3-pip python3-setuptools python3-wheel ninja-build build-essential \
      flex bison cmake pkg-config meson libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev \
      libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev \
      libcurl4-gnutls-dev libtins-dev libtalloc-dev \
      iproute2 iptables iputils-ping tcpdump \
 && rm -rf /var/lib/apt/lists/*
RUN git clone --depth 1 --branch ${OPEN5GS_REF} https://github.com/open5gs/open5gs.git /src/open5gs
COPY open5gs/*.patch /src/patches/
RUN cd /src/open5gs && git apply /src/patches/*.patch \
 && meson setup build --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
 && ninja -C build install
