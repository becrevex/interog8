#!/usr/bin/env python3
"""
Boofuzz Network Buffer Fuzzer
=============================
- Slowly increases buffer size (classic A*size style)
- Takes IP + port from CLI
- Tracks every payload sent (console + sent.log)
- Special handling + logging when a crash is detected
- Uses boofuzz for connection handling and logging
"""

import argparse
import time
from datetime import datetime
from boofuzz import *


def main():
    parser = argparse.ArgumentParser(
        description="Simple boofuzz buffer-size fuzzer (slowly increases A*size)",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    parser.add_argument("ip", help="Target IP address")
    parser.add_argument("port", type=int, help="Target TCP port")

    parser.add_argument(
        "--start", type=int, default=100,
        help="Starting buffer size in bytes"
    )
    parser.add_argument(
        "--step", type=int, default=200,
        help="Buffer size increment per test"
    )
    parser.add_argument(
        "--max", type=int, default=30000,
        help="Maximum buffer size"
    )
    parser.add_argument(
        "--prefix", default="",
        help="Optional prefix (e.g. 'TRUN /.:/' for VulnServer)"
    )
    parser.add_argument(
        "--suffix", default="",
        help="Optional suffix (e.g. '\\r\\n')"
    )
    parser.add_argument(
        "--sleep", type=float, default=0.8,
        help="Seconds to sleep between tests (be nice to the target)"
    )
    parser.add_argument(
        "--proto", choices=["tcp", "udp"], default="tcp",
        help="Protocol to use"
    )

    args = parser.parse_args()

    # Build the boofuzz session
    session = Session(
        target=Target(
            connection=SocketConnection(
                host=args.ip,
                port=args.port,
                proto=args.proto,
                recv_timeout=3.0
            )
        ),
        sleep_time=args.sleep,
        crash_threshold=1,
        # web_port=26000,  # Uncomment to enable web UI
        console_log_level=1,
    )

    print(f"[*] Boofuzz buffer fuzzer started → {args.ip}:{args.port} ({args.proto.upper()})")
    print(f"[*] Range: {args.start} → {args.max} bytes (step {args.step})")
    print(f"[*] Prefix: '{args.prefix}' | Suffix: '{args.suffix}'")
    print("[*] Logging every send to sent.log | Crashes go to crashes.log")

    if hasattr(session, "web_port") and session.web_port:
        print(f"[*] Web UI available at http://127.0.0.1:{session.web_port}")

    print("-" * 80)

    size = args.start
    test_num = 1

    while size <= args.max:
        # Build payload
        payload = (
            args.prefix.encode("utf-8", errors="ignore") +
            b"A" * size +
            args.suffix.encode("utf-8", errors="ignore")
        )

        timestamp = datetime.now().strftime("%H:%M:%S")

        print(
            f"[{timestamp}] Test #{test_num:04d} | "
            f"Size = {size:,} bytes | Total payload = {len(payload):,} bytes"
        )

        # Log every payload
        with open("sent.log", "a") as f:
            f.write(
                f"[{timestamp}] Test #{test_num} | Size={size} | "
                f"Total={len(payload)} | Prefix='{args.prefix}'\n"
            )

        try:
            session.target.open()
            session.target.send(payload)
            response = session.target.recv(4096)

            if response:
                print(f" [+] Received {len(response)} bytes response")
            else:
                print(" (no response)")

        except Exception as e:
            print(f"\n[!!!] CRASH / ERROR DETECTED at buffer size {size:,} bytes!")
            print(f" Exception : {type(e).__name__} → {e}")
            print(f" Time : {datetime.now()}")
            print(f" Payload : {args.prefix} + {'A' * size} + {args.suffix}")
            print(" This is the crashing input — reproduce with the exact size above.\n")

            # Crash log
            with open("crashes.log", "a") as f:
                f.write(
                    f"[{timestamp}] CRASH at size {size} | Test #{test_num} | "
                    f"Total payload {len(payload)} bytes | Prefix='{args.prefix}'\n"
                )
                f.write(f" Exception: {type(e).__name__} - {e}\n\n")

            time.sleep(3)
            break  # stop on first crash

        finally:
            try:
                session.target.close()
            except:
                pass

        size += args.step
        test_num += 1

    print("\n[+] Fuzzing finished.")


if __name__ == "__main__":
    main()
