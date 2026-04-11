#!/usr/bin/env python
# crashmon.py - Immunity Debugger Crash Monitor
# Usage: !crashmon C:\path\to\app.exe
#        !crashmon -p 1234

from immlib import *
import time
import os
from datetime import datetime

DESC = "Crash Monitor: launch/attach + auto-dump registers/stack + restart"

def main(args):
    imm = Debugger()

    if not args:
        return "Usage:\n  !crashmon <full_path_to_exe>\n  !crashmon -p <PID>"

    # Parse arguments
    pid = None
    exe_path = None
    if args[0] == "-p" and len(args) > 1:
        try:
            pid = int(args[1])
        except:
            return "Invalid PID"
    else:
        exe_path = " ".join(args)

    # Create crash log directory
    crash_dir = os.path.join(os.getcwd(), "crashes")
    if not os.path.exists(crash_dir):
        os.makedirs(crash_dir)

    crash_count = 0
    imm.Log("=== CrashMon Started ===", LOG_ALWAYS)

    while True:
        try:
            # Attach or launch
            if pid:
                imm.Log("Attaching to PID %d..." % pid, LOG_ALWAYS)
                if not imm.attach(pid):
                    imm.Log("Attach failed!", LOG_ERROR)
                    time.sleep(3)
                    continue
            elif exe_path:
                imm.Log("Launching %s..." % exe_path, LOG_ALWAYS)
                # Start the process under the debugger
                imm.run(exe_path)   # This is the Immunity way to start a new debuggee
                time.sleep(2)       # Give it time to initialize

            imm.Log("Process running - monitoring for crashes...", LOG_ALWAYS)

            # Main monitoring loop
            while True:
                imm.go()                    # Let the process run
                time.sleep(0.1)

                # Check for exception (crash)
                exc = imm.getException()
                if exc:
                    crash_count += 1
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    crash_file = os.path.join(crash_dir, "crash_%03d_%s.txt" % (crash_count, ts))

                    imm.Log("!!! CRASH #%d DETECTED !!!" % crash_count, LOG_ERROR)

                    report = []
                    report.append("=== Crash Report #%d - %s ===" % (crash_count, ts))
                    report.append("Exception: %s" % str(exc))

                    # Registers
                    regs = imm.getRegs()
                    report.append("\nRegisters:")
                    for r in ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP", "EIP"]:
                        if r in regs:
                            report.append("%s = 0x%08X" % (r, regs[r]))

                    # Call stack trace
                    stack = imm.getCallStack()
                    report.append("\nCall Stack (top 20 frames):")
                    for i, frame in enumerate(stack[:20]):
                        report.append("  %02d: 0x%08X  %s" % (i, frame.getAddress(), frame.getSymbol() or ""))

                    # Stack dump around ESP
                    if "ESP" in regs:
                        esp = regs["ESP"]
                        report.append("\nStack dump around ESP (0x%08X):" % esp)
                        for i in range(-32, 64, 4):
                            addr = esp + i
                            try:
                                val = imm.readLong(addr)
                                report.append("  0x%08X : 0x%08X" % (addr, val))
                            except:
                                report.append("  0x%08X : [unreadable]" % addr)

                    # Write report to file
                    with open(crash_file, "w") as f:
                        f.write("\n".join(report))

                    imm.Log("Crash details saved → %s" % crash_file, LOG_ALWAYS)

                    # Restart the process
                    imm.Log("Restarting process...", LOG_ALWAYS)
                    imm.restartProcess()   # Built-in Immunity restart
                    time.sleep(3)
                    break   # Break inner loop to re-launch/attach

        except Exception as e:
            imm.Log("Error in monitor: %s" % str(e), LOG_ERROR)
            time.sleep(3)

    return "CrashMon stopped"
