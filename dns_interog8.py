#!/usr/bin/env python3
"""
dns_interog8.py – simple DNS fuzzer (UDP) using boofuzz

Usage:
    python dns_interog8.py -i 192.168.1.10 -p 53
"""

import argparse
from boofuzz import (
    Session,
    Target,
    UDP,
    s_initialize,
    s_block_start,
    s_block_end,
    s_static,
    s_word,
    s_string,
)

###############################################################################
# 1. Argument parsing                                                         #
###############################################################################

def parse_args():
    parser = argparse.ArgumentParser(
        description="Minimal boofuzz‑based DNS fuzzer."
    )
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=53,
        help="Target UDP port (default: 53)",
    )
    parser.add_argument(
        "--srcport", type=int, default=12000, help="Source UDP port (default: 12000)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=0,
        help="Max number of fuzz cases (0 = unlimited)",
    )
    return parser.parse_args()


def init_session(dst_ip: str, dst_port: int, src_port: int, iterations: int):
    return Session(
        target=Target(connection=UDP(dst=dst_ip, dport=dst_port, srcport=src_port)),
        session_filename="dns_session.json",
        fuzz_loggers=None,
        sleep_time=0.1,
        total_fuzz_cases=iterations if iterations > 0 else None,
    )


###############################################################################
# 2. DNS request model                                                        #
###############################################################################

def build_dns_request():
    if not s_initialize("dns_query"):
        return

    # -- DNS header (12 bytes) --
    s_word(name="TransactionID")
    s_word(value=0x0100, name="Flags")
    s_word(value=1, name="QdCount")
    s_word(value=0, name="AnCount")
    s_word(value=0, name="NsCount")
    s_word(value=0, name="ArCount")

    # -- Question section --
    s_block_start("QNAME")
    for i in range(5):
        s_size("label_%d" % i, length=1, inclusive=False, math=lambda v: len(v))
        s_string("fuzz", name="label_%d" % i, fuzzable=True, max_len=20)
    s_static(b"\x00")  # terminator
    s_block_end("QNAME")

    s_word(value=1, name="QTYPE")   # A
    s_word(value=1, name="QCLASS")  # IN


###############################################################################
# 3. Main                                                                     #
###############################################################################

if __name__ == "__main__":
    args = parse_args()

    build_dns_request()

    session = init_session(
        dst_ip=args.ip, dst_port=args.port, src_port=args.srcport, iterations=args.iterations
    )
    session.connect(s_get("dns_query"))
    session.fuzz()

