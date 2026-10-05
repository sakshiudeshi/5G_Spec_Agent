"""UERANSIM gNB pcap -> the RLC-NR raw-IP pcap that fiveg_specifier/decode.py reads.

UERANSIM has no PHY/MAC/RLC. Its "air interface" is RLS: UDP port 4997 between UE and gNB,
each PDU_TRANSMISSION carrying one UPER-encoded RRC message and its logical channel. This
script lifts every RRC PDU out of RLS and re-frames it as an rlc-nr UDP datagram, so
`run.py --capture` needs no simulator-specific code.

    python rls_to_capture.py captures/gnb.pcap captures/oracle_input.pcap
"""

from __future__ import annotations

import argparse
import struct
from pathlib import Path

RLS_PORT = 4997
RLS_PDU_TRANSMISSION = 6
RLS_PDU_RRC = 1

# UERANSIM RrcChannel (src/lib/rrc/rrc.hpp) -> name, rlc-nr (direction, bearer type).
# direction 0 = uplink, 1 = downlink; bearer types as in Wireshark's packet-rlc-nr.h.
RRC_CHANNELS = {
    0: ("BCCH-BCH", 1, 2),
    1: ("BCCH-DL-SCH", 1, 6),
    2: ("DL-CCCH", 1, 1),
    3: ("DL-DCCH", 1, 4),
    4: ("PCCH", 1, 3),
    5: ("UL-CCCH", 0, 1),
    6: ("UL-CCCH1", 0, 1),
    7: ("UL-DCCH", 0, 4),
}

_LINKTYPE_ETHERNET = 1
_LINKTYPE_LINUX_SLL = 113
_LINKTYPE_RAW_IP = 101


def read_frames(path: Path):
    """Classic little-endian pcap -> (ts_sec, ts_usec, ip_packet)."""
    data = path.read_bytes()
    magic, = struct.unpack_from("<I", data, 0)
    if magic != 0xA1B2C3D4:
        raise ValueError(f"{path}: expected microsecond little-endian pcap, magic {magic:#x}")
    linktype, = struct.unpack_from("<I", data, 20)
    strip = {_LINKTYPE_ETHERNET: 14, _LINKTYPE_LINUX_SLL: 16, _LINKTYPE_RAW_IP: 0}.get(linktype)
    if strip is None:
        raise ValueError(f"{path}: unsupported linktype {linktype}")
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl, _ = struct.unpack_from("<IIII", data, off)
        off += 16
        yield ts_sec, ts_usec, data[off + strip : off + incl]
        off += incl


def rls_rrc_pdus(ip: bytes):
    """IPv4/UDP datagram on the RLS port -> (channel, rrc_pdu), or nothing."""
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return
    ihl = (ip[0] & 0x0F) * 4
    sport, dport, ulen = struct.unpack_from("!HHH", ip, ihl)
    if RLS_PORT not in (sport, dport):
        return
    rls = ip[ihl + 8 : ihl + ulen]
    # 0x03, version(3), msgType, sti(8), pduType, pduId(4), payload(4), len(4), pdu
    if len(rls) < 26 or rls[0] != 0x03 or rls[4] != RLS_PDU_TRANSMISSION or rls[13] != RLS_PDU_RRC:
        return
    channel, length = struct.unpack_from("!II", rls, 18)
    yield channel, rls[26 : 26 + length]


def rlc_nr_datagram(direction: int, bearer_type: int, pdu: bytes) -> bytes:
    """rlc-nr UDP framing (TM, no SN) inside a bare IPv4/UDP packet."""
    payload = b"rlc-nr" + bytes([1, 0, 0x02, direction, 0x04, bearer_type, 0x01]) + pdu
    udp = struct.pack("!HHHH", 50000, 9999, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     bytes([127, 0, 0, 1]), bytes([127, 0, 0, 1]))
    return ip + udp


def convert(src: Path, dst: Path) -> list[tuple[float, str, int]]:
    out = bytearray(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, _LINKTYPE_RAW_IP))
    written = []
    for ts_sec, ts_usec, ip in read_frames(src):
        for channel, pdu in rls_rrc_pdus(ip):
            name, direction, bearer = RRC_CHANNELS.get(channel, (f"ch{channel}", 1, 0))
            frame = rlc_nr_datagram(direction, bearer, pdu)
            out += struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)) + frame
            written.append((ts_sec + ts_usec / 1e6, name, len(pdu)))
    dst.write_bytes(bytes(out))
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", type=Path)
    ap.add_argument("dst", type=Path)
    args = ap.parse_args()
    written = convert(args.src, args.dst)
    by_channel: dict[str, int] = {}
    for _, name, _ in written:
        by_channel[name] = by_channel.get(name, 0) + 1
    print(f"{args.dst}: {len(written)} RRC PDUs " + ", ".join(f"{k}={v}" for k, v in sorted(by_channel.items())))


if __name__ == "__main__":
    main()
