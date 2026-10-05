#!/bin/bash
# All Open5GS 5GC NFs in one container. They talk to each other on 127.0.0.x;
# only NGAP (AMF) and GTP-U (UPF) are moved onto the container's bridge IP.
set -e
IP=$(hostname -i | awk '{print $1}')
cd /etc/open5gs
sed -i "/ngap:/,/address/ s/127\.0\.0\.5/$IP/" amf.yaml
sed -i "/gtpu:/,/address/ s/127\.0\.0\.7/$IP/" upf.yaml
sed -i '/2001:db8:cafe/d' upf.yaml smf.yaml
sed -i "s#mongodb://localhost/open5gs#mongodb://mongo/open5gs#" *.yaml

ip tuntap add name ogstun mode tun 2>/dev/null || true
ip addr add 10.45.0.1/16 dev ogstun 2>/dev/null || true
ip link set ogstun up
sysctl -qw net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.45.0.0/16 ! -o ogstun -j MASQUERADE

mkdir -p /var/log/open5gs
open5gs-nrfd -D; sleep 1
open5gs-scpd -D; sleep 1
for nf in ausf udm udr pcf nssf bsf smf upf; do open5gs-${nf}d -D; done
sleep 2
exec open5gs-amfd
