#!/usr/bin/env python3
# crashmon_simple.py - Simple & reliable crash monitor (visible launch + auto restart)
# Usage: python crashmon_simple.py "C:\path\to\vulnserver.exe"

import sys
import time
import os
from datetime import datetime
import subprocess

def main():
    if len(sys.argv) < 2:
        print("Usage: python crashmon_simple.py <full_path_to_exe>")
        sys.exit(1)

    exe_path = " ".join(sys.argv[1:])
    crash_dir = "crashes"
    os.makedirs(crash_dir, exist_ok=True)
    crash_count = 0

    print("=== Simple CrashMon Started ===")
    print(f"Target: {exe_path}")
    print("Process will be visible. Ctrl+C to stop.\n")

    while True:
        try:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] Launching process...")
            
            # Launch visibly with its own console window
            proc = subprocess.Popen(
                exe_path,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                creationflags=subprocess.CREATE_NEW_CONSOLE  # This makes it pop up visibly
            )

            print(f"Process started (PID {proc.pid}) - monitoring...")

            # Wait until process dies
            stdout, stderr = proc.communicate()
            returncode = proc.returncode

            crash_count += 1
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            crash_file = os.path.join(crash_dir, f"crash_{crash_count:03d}_{ts}.txt")

            print(f"\n!!! CRASH #{crash_count} DETECTED !!! (exit code {returncode})")

            report = [
                f"=== Crash Report #{crash_count} - {ts} ===",
                f"Target: {exe_path}",
                f"Exit code: {returncode}",
                f"PID: {proc.pid}",
                "\n=== STDOUT ===",
                stdout.decode("utf-8", errors="replace"),
                "\n=== STDERR ===",
                stderr.decode("utf-8", errors="replace")
            ]

            with open(crash_file, "w", encoding="utf-8") as f:
                f.write("\n".join(report))

            print(f"Crash log saved → {crash_file}")

            # Optional: you can add a minidump here later if you want

            print("Restarting in 2 seconds...\n")
            time.sleep(2)

        except KeyboardInterrupt:
            print("\nStopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)

if __name__ == "__main__":
    main()
