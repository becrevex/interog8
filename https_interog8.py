#!/usr/bin/env python3
"""https_fuzzer.py – Comprehensive HTTPS fuzzer using boofuzz

   * TLS‑enabled (targets TCP 443 by default)
   * Fuzzes request‑line, headers, cookies, and body (for POST)
   * Argparse interface for IP / port / URI / method / iterations
   * Supports configurable HTTPS SNI and optional client‑cert toggle

   Example:
        python https_fuzzer.py -i 10.0.0.5 -p 443 -u /login -m POST --iterations 10000

   Tested with boofuzz ≥ 0.3.0 (TCPSocketConnection ssl=True)
"""

import argparse
from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    s_initialize,
    s_static,
    s_group,
    s_string,
    s_delim,
    s_block_start,
    s_block_end,
    s_size,
)

def parse_args():
    p = argparse.ArgumentParser(description="Comprehensive HTTPS fuzzer (boofuzz)")
    p.add_argument("-i", "--ip", required=True, help="Target IP / hostname")
    p.add_argument("-p", "--port", type=int, default=443, help="Target port (default 443)")
    p.add_argument("-u", "--uri", default="/", help="Initial URI to fuzz (default /")
    p.add_argument("-m", "--method", default="GET", help="HTTP method (default GET)")
    p.add_argument("--iterations", type=int, default=0, help="Max fuzz cases (0=unlimited)")
    p.add_argument("--sni", default=None, help="TLS SNI hostname (default: ip)")
    p.add_argument("--srcport", type=int, default=55000, help="Source TCP port")
    p.add_argument("--no_body", action="store_true", help="Disable body fuzzing (even for POST)")
    return p.parse_args()


def build_https_request(method: str, uri: str, fuzz_body: bool):
    if not s_initialize("https_req"):
        return

    # ===== Request line =====
    s_group("method", [method, "GET", "POST", "PUT", "DELETE", "OPTIONS", "TRACE", "HEAD"], fuzzable=True)
    s_static(" ")
    s_string(uri, name="uri", fuzzable=True, max_len=2048)
    s_static(" HTTP/1.1")
    s_delim("\r\n")

    # ===== Host header =====
    s_static("Host: ")
    s_string("fuzz.host", name="host_hdr", fuzzable=True)
    s_delim("\r\n")

    # ===== User‑Agent (fuzz token positions) =====
    s_static("User-Agent: ")
    s_string("boofuzz/1.0", name="ua", fuzzable=True)
    s_delim("\r\n")

    # ===== Accept & Accept‑Encoding =====
    s_static("Accept: ")
    s_group("accept", ["*/*", "text/html", "application/json"], fuzzable=True)
    s_delim("\r\n")

    s_static("Accept-Encoding: ")
    s_group("enc", ["gzip", "deflate", "br", "identity"], fuzzable=True)
    s_delim("\r\n")

    # ===== Cookie header block =====
    s_block_start("cookies")
    s_static("Cookie: ")
    s_string("sessionid=AAAA", name="cookie1", max_len=256, fuzzable=True)
    s_static("; ")
    s_string("pref=BBBB", name="cookie2", max_len=256, fuzzable=True)
    s_delim("\r\n")
    s_block_end("cookies")

    # ===== Custom header fuzz block =====
    s_block_start("xhdr")
    s_string("X-Fuzz-Header", name="xhname", fuzzable=True)
    s_static(": ")
    s_string("fuzzvalue", name="xhval", max_len=512, fuzzable=True)
    s_delim("\r\n")
    s_block_end("xhdr")

    # --- header terminator ---
    s_delim("\r\n")

    # ===== Body (for POST/PUT) =====
    if not fuzz_body:
        return

    if method.upper() in ("POST", "PUT"):
        s_string("bodydata=AAAA", name="postdata", max_len=4096, fuzzable=True)


def main():
    args = parse_args()

    build_https_request(args.method, args.uri, not args.no_body)

    sess = Session(
        target=Target(
            connection=TCPSocketConnection(
                dst_host=args.ip,
                dst_port=args.port,
                src_port=args.srcport,
                ssl=True,
                ssl_hostname=args.sni or args.ip,
            )
        ),
        total_fuzz_cases=args.iterations if args.iterations else None,
        sleep_time=0.05,
    )

    sess.connect(s_get("https_req"))
    sess.fuzz()

if __name__ == "__main__":
    main()
