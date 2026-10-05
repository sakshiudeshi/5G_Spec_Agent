"""tshark fields (time, src, dst, info) on stdin -> a UE / gNB / core ladder on stdout."""

import re
import sys

NODES = {"10.100.200.30": "UE", "10.100.200.20": "gNB", "10.100.200.10": "core"}
COL = {"UE": 0, "gNB": 1, "core": 2}
WIDTH = 14


def arrow(src: str, dst: str) -> str:
    a, b = COL[src], COL[dst]
    lo, hi = min(a, b), max(a, b)
    line = "-" * (WIDTH * (hi - lo) - 1)
    line = line + ">" if a < b else "<" + line
    return (" " * (WIDTH * lo + WIDTH // 2) + line).ljust(WIDTH * 3)


def main() -> None:
    print(f"{'t(s)':>8}  " + "".join(n.center(WIDTH) for n in COL) + "  message")
    for row in sys.stdin:
        parts = row.rstrip("\n").split("\t")
        if len(parts) != 4:
            continue
        t, src, dst, info = parts
        # GTP/RLS-tunnelled packets list outer,inner addresses; the outer pair is the hop.
        src, dst = NODES.get(src.split(",")[0]), NODES.get(dst.split(",")[0])
        if not src or not dst:
            continue
        info = re.sub(r"SACK \([^)]*\)\s*,?\s*", "", info)
        info = re.sub(r"\s+id=0x.*", "", info).strip(" ,")
        if not info:
            continue
        print(f"{float(t):8.3f}  {arrow(src, dst)}  {info}")


if __name__ == "__main__":
    main()
