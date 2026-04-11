#!/usr/bin/env python3
# crashmon.py - Pure Python crash monitor (winappdbg)
# Usage: python crashmon.py "C:\full\path\to\program.exe"
#        python crashmon.py -p 1234

import sys
import time
import os
from datetime import datetime
from winappdbg import Debug, EventHandler, CrashDump

class CrashHandler(EventHandler):
    def __init__(self, crash_dir="crashes"):
        super(CrashHandler, self).__init__()
        self.crash_dir = crash_dir
        self.crash_count = 0
        if not os.path.exists(crash_dir):
            os.makedirs(crash_dir)

    def event(self, event):
        if event.is_crash():
            self.crash_count += 1
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            crash_file = os.path.join(self.crash_dir, f"crash_{self.crash_count:03d}_{ts}.txt")

            print(f"\n!!! CRASH #{self.crash_count} DETECTED !!!")
            crash = CrashDump.Crash(event)
            crash.fetch_extra_data(event, takeMemorySnapshot=0)

            report = []
            report.append(f"=== Crash Report #{self.crash_count} - {ts} ===")
            report.append(f"Exception: {crash.exception}")
            report.append(f"Process ID: {event.get_pid()}")

            # Registers
            regs = crash.registers
            report.append("\nRegisters:")
            for r in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]:
                if hasattr(regs, r):
                    val = getattr(regs, r)
                    report.append(f"{r:4} = 0x{val:08X}")

            # Call stack
            report.append("\nCall Stack (top 20 frames):")
            for i, frame in enumerate(crash.stack_trace[:20]):
                addr = frame.address
                module = frame.module or ""
                symbol = frame.function or ""
                report.append(f"  {i:02d}: 0x{addr:08X}  {module}!{symbol}")

            # Stack dump around ESP
            if hasattr(regs, "ESP"):
                esp = regs.ESP
                report.append(f"\nStack dump around ESP (0x{esp:08X}):")
                for i in range(-32, 64, 4):
                    addr = esp + i
                    try:
                        val = event.get_process().read_uint(addr)
                        report.append(f"  0x{addr:08X} : 0x{val:08X}")
                    except:
                        report.append(f"  0x{addr:08X} : [unreadable]")

            # Save report
            with open(crash_file, "w", encoding="utf-8") as f:
                f.write("\n".join(report))

            print(f"Crash details saved → {crash_file}")

            # Tell the debugger to restart after this handler
            event.continue_debug_event = False
            return True  # We handled it

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python crashmon.py <full_path_to_exe>")
        print("  python crashmon.py -p <PID>")
        sys.exit(1)

    pid = None
    exe_path = None
    if sys.argv[1] == "-p" and len(sys.argv) > 2:
        pid = int(sys.argv[2])
    else:
        exe_path = " ".join(sys.argv[1:])

    handler = CrashHandler()
    debug = Debug(handler)

    try:
        if pid:
            print(f"Attaching to PID {pid}...")
            debug.attach(pid)
        else:
            print(f"Launching {exe_path}...")
            debug.execv([exe_path], bFollow=True)

        print("Monitoring for crashes... (Ctrl+C to stop)\n")

        while True:
            try:
                debug.wait(1000)   # 1 second timeout
            except Exception:
                break

            # If process died, restart it
            if not debug.is_active():
                print("Process terminated — restarting...")
                time.sleep(1)
                if exe_path:
                    debug.execv([exe_path], bFollow=True)
                else:
                    break  # Can't re-attach without PID

    except KeyboardInterrupt:
        print("\nStopped by user.")
    finally:
        debug.stop()
        print("CrashMon stopped.")

if __name__ == "__main__":
    main()
