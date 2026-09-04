"""Capture file -> [Record].

Two capture formats reduce to one flat record type, so run.py never sees a pcap.
"""

from __future__ import annotations

import argparse
import struct
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

# TS 38.331 EstablishmentCause, ASN.1 order.
ESTABLISHMENT_CAUSES = (
    "emergency",
    "highPriorityAccess",
    "mt-Access",
    "mo-Signalling",
    "mo-Data",
    "mo-VoiceCall",
    "mo-VideoCall",
    "mo-SMS",
    "mps-PriorityAccess",
    "mcs-PriorityAccess",
    "spare6",
    "spare5",
    "spare4",
    "spare3",
    "spare2",
    "spare1",
)


@dataclass(frozen=True)
class Record:
    seq: int
    ts: float
    message_is: str | None  # "rrc_setup_request"
    id_type: str | None  # "tmsi" | "random"
    ue_identity_tmsi: str | None  # 39-char binary string
    establishment_cause: str | None  # TS 38.331 name


# --------------------------------------------------------------------------
# UL-CCCH decode: exactly 6 octets, constant bit offsets, no ASN.1 library.
#
#   bits 0-2    "000" = c1.rrcSetupRequest
#   bit  3      0 = ng-5G-S-TMSI-Part1, 1 = randomValue
#   bits 4-42   the 39-bit identity
#   bits 43-46  establishmentCause
#   bit  47     spare
# --------------------------------------------------------------------------

_UNDECODABLE = (None, None, None, None)


def decode_ul_ccch(pdu: bytes) -> tuple[str | None, str | None, str | None, str | None]:
    if len(pdu) != 6:
        return _UNDECODABLE
    bits = "".join(f"{b:08b}" for b in pdu)
    if bits[0:3] != "000":
        return _UNDECODABLE
    id_type = "random" if bits[3] == "1" else "tmsi"
    tmsi = bits[4:43] if id_type == "tmsi" else None
    cause = ESTABLISHMENT_CAUSES[int(bits[43:47], 2)]
    return ("rrc_setup_request", id_type, tmsi, cause)


# pcap adapter: little-endian pcap, linktype 101 (raw IP), RLC-NR UDP framing.

_PCAP_MAGICS = {0xA1B2C3D4: 1_000_000, 0xA1B23C4D: 1_000_000_000}
_RLC_NR_MAGIC = b"rlc-nr"
_LINKTYPE_RAW_IP = 101


def _udp_payload(frame: bytes) -> bytes | None:
    """Bare IPv4 datagram -> UDP payload, or None."""
    if len(frame) < 20 or frame[0] >> 4 != 4:
        return None
    ihl = (frame[0] & 0x0F) * 4
    if ihl < 20 or len(frame) < ihl + 8 or frame[9] != 17:
        return None
    udp_len = struct.unpack_from("!H", frame, ihl + 4)[0]
    if udp_len < 8:
        return None
    return frame[ihl + 8 : ihl + udp_len]


def _parse_rlc_nr(payload: bytes) -> tuple[int | None, int | None, bytes] | None:
    """RLC-NR UDP framing -> (direction, bearer_type, pdu), or None."""
    if not payload.startswith(_RLC_NR_MAGIC):
        return None
    i = len(_RLC_NR_MAGIC) + 2  # rlcMode, snLength
    direction = bearer_type = None
    while i < len(payload):
        tag = payload[i]
        i += 1
        if tag == 0x01:  # payload runs to the end of the packet
            return (direction, bearer_type, payload[i:])
        width = {0x02: 1, 0x03: 2, 0x04: 1, 0x05: 1}.get(tag)
        if width is None or i + width > len(payload):
            return None
        if tag == 0x02:
            direction = payload[i]
        elif tag == 0x04:
            bearer_type = payload[i]
        i += width
    return None


def read_pcap(path: str | Path) -> list[Record]:
    """Uplink CCCH records only. `seq` is the pcap frame number."""
    data = Path(path).read_bytes()
    if len(data) < 24:
        return []
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic not in _PCAP_MAGICS:
        raise ValueError(f"{path}: not a little-endian classic pcap (magic {magic:#010x})")
    divisor = _PCAP_MAGICS[magic]
    linktype = struct.unpack_from("<I", data, 20)[0]
    if linktype != _LINKTYPE_RAW_IP:
        raise ValueError(f"{path}: linktype {linktype}, expected {_LINKTYPE_RAW_IP} (raw IP)")

    records: list[Record] = []
    off, frame_no = 24, 0
    while off + 16 <= len(data):
        ts_sec, ts_frac, incl_len, _orig_len = struct.unpack_from("<IIII", data, off)
        off += 16
        frame = data[off : off + incl_len]
        off += incl_len
        if len(frame) < incl_len:
            break  # truncated final record
        frame_no += 1
        payload = _udp_payload(frame)
        if payload is None:
            continue
        parsed = _parse_rlc_nr(payload)
        if parsed is None:
            continue
        direction, bearer_type, pdu = parsed
        if direction != 0 or bearer_type != 1:  # uplink CCCH only
            continue
        records.append(Record(frame_no, ts_sec + ts_frac / divisor, *decode_ul_ccch(pdu)))
    return records


# txt adapter: SCAT-style log; a rrcSetupRequest(Up) line is followed by its "HEX: 0x..." line.

_TXT_MARKER = "rrcSetupRequest(Up)"


def _parse_clock(text: str) -> float:
    """'06:38:30.385' -> seconds since midnight."""
    hh, mm, ss = text.strip().split(":")
    return int(hh) * 3600 + int(mm) * 60 + float(ss)


def read_txt(path: str | Path) -> list[Record]:
    """`seq` is 1-based over rrcSetupRequest(Up) matches."""
    lines = Path(path).read_text(errors="replace").splitlines()
    records: list[Record] = []
    seq = 0
    for i, line in enumerate(lines):
        if _TXT_MARKER not in line:
            continue
        ts = _parse_clock(line.split(";", 1)[0])
        pdu = b""
        if i + 1 < len(lines):
            nxt = lines[i + 1].strip()
            if nxt.startswith("HEX:"):
                hexstr = nxt.split("HEX:", 1)[1].strip()
                if hexstr[:2].lower() == "0x":
                    hexstr = hexstr[2:]
                try:
                    pdu = bytes.fromhex(hexstr)
                except ValueError:
                    pdu = b""
        seq += 1
        records.append(Record(seq, ts, *decode_ul_ccch(pdu)))
    return records


def load_capture(path: str | Path) -> list[Record]:
    return read_pcap(path) if str(path).lower().endswith(".pcap") else read_txt(path)


def main() -> None:
    ap = argparse.ArgumentParser(description="decode a capture and count establishment causes")
    ap.add_argument("--capture", required=True)
    args = ap.parse_args()
    records = load_capture(args.capture)
    causes = Counter(r.establishment_cause for r in records if r.message_is == "rrc_setup_request")
    print(f"records: {len(records)}")
    print(f"rrc_setup_request: {sum(causes.values())}")
    for cause, n in causes.most_common():
        print(f"  {cause}: {n}")


if __name__ == "__main__":
    main()
