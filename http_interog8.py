#!/usr/bin/env python3
"""http_interog8.py — Lightweight HTTP fuzzer using boofuzz.

Example:
    python http_interog8.py -i 192.168.1.50 -p 8080 -m GET -u /test
"""

import argparse
from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    s_initialize,
    s_static,
    s_string,
    s_delim,
    s_group,
    s_block_start,
    s_block_end,
)

###############################################################################
# Argument Parsing
###############################################################################

def parse_args():
    parser = argparse.ArgumentParser(description="Simple HTTP fuzzer (boofuzz)")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=80, help="Target TCP port (default 80)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method to fuzz (default GET)")
    parser.add_argument("-u", "--uri", default="/", help="Initial request URI (default /)")
    parser.add_argument("--iterations", type=int, default=0, help="Limit test cases (0 = unlimited)")
    return parser.parse_args()

###############################################################################
# HTTP Request Model
###############################################################################

def build_http_request(method: str, uri: str):
    if not s_initialize("http_request"):
        return

    # Request line
    s_group("method", [method, "POST", "HEAD", "OPTIONS", "PUT", "TRACE"], fuzzable=True)
    s_static(" ")
    s_string(uri, name="uri", fuzzable=True, max_len=1024)
    s_static(" HTTP/1.1")
    s_delim("\r\n")

    # Host header
    s_static("Host: ")
    s_string("example.com", name="host", fuzzable=True)
    s_delim("\r\n")

    # User-Agent
    s_static("User-Agent: ")
    s_string("boofuzz", name="ua", fuzzable=True)
    s_delim("\r\n")

    # Custom header block (optional fuzz)
    s_block_start("misc_headers")
    s_static("X-Token: ")
    s_string("fuzzme", name="x_tok", fuzzable=True)
    s_delim("\r\n")
    s_block_end("misc_headers")

    # End of headers
    s_delim("\r\n")

    # For POST/PUT we can fuzz body, but keep simple here.
    if method.upper() == "POST":
        s_string("bodydata", name="body", fuzzable=True)

###############################################################################
# Main
###############################################################################

def main():
    args = parse_args()

    # Build request template
    build_http_request(args.method, args.uri)

    # Create boofuzz session
    sess = Session(
        target=Target(
            connection=TCPSocketConnection(dst_host=args.ip, dst_port=args.port)
        ),
        total_fuzz_cases=args.iterations if args.iterations > 0 else None,
    )

    sess.connect(s_get("http_request"))
    sess.fuzz()

if __name__ == "__main__":
    main()
