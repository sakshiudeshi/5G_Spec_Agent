FROM ubuntu:22.04 AS build
ARG UERANSIM_REF=48554b7
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      git ca-certificates make g++ cmake libsctp-dev lksctp-tools && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/aligungr/UERANSIM.git /src && cd /src && git checkout ${UERANSIM_REF} && make -j"$(nproc)"

FROM ubuntu:22.04
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libsctp1 lksctp-tools iproute2 iputils-ping tcpdump tshark && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/build/nr-gnb /src/build/nr-ue /src/build/nr-cli /src/build/nr-binder /src/build/libdevbnd.so /usr/local/bin/
# Lets tshark dissect RLS (UERANSIM's simulated radio link) down to NR-RRC and 5GS-NAS.
COPY --from=build /src/tools/rls-wireshark-dissector.lua /root/.local/lib/wireshark/plugins/rls.lua
WORKDIR /ueransim
