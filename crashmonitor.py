from immlib import *
import time
import os
from datetime import datetime

DESC = "Crash Monitor - launch/attach + dump registers/stack + auto restart"

def main(args):
    imm = Debugger()

    if not args:
        return "Usage:\n  !crashmon <full_path_to_exe>\n  !crashmon -p <PID>"

    # Parse arguments
    pid = None
    exe_path = None
    if len(args) == 2 and args[0] == "-p":
        try:
            pid = int(args[1])
        except:
            return "Invalid PID"
    else:
        exe_path = " ".join(args)

    # Create crash folder
    crash_dir = os.path.join(os.getcwd(), "crashes")
    if not os.path.exists(crash_dir):
        os.makedirs(crash_dir)

    crash_count = 0
    imm.log("=== CrashMon Started ===")

    while True:
        try:
            # Launch or attach
            if pid:
                imm.log("Attaching to PID %d..." % pid)
                if not imm.attach(pid):
                    imm.log("Attach failed!", 1)
                    time.sleep(3)
                    continue
            elif exe_path:
                imm.log("Launching %s..." % exe_path)
                imm.execute(exe_path)          # Most reliable launch method
                time.sleep(3)

            imm.log("Monitoring for crashes...")

            while True:
                imm.go()
                time.sleep(0.2)

                # Check for crash
                exc = imm.getException()
                if exc:
                    crash_count += 1
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    crash_file = os.path.join(crash_dir, "crash_%03d_%s.txt" % (crash_count, ts))

                    imm.log("!!! CRASH #%d DETECTED !!!" % crash_count, 1)

                    report = []
                    report.append("=== Crash Report #%d - %s ===" % (crash_count, ts))
                    report.append("Exception: %s" % str(exc))

                    # Registers
                    regs = imm.getRegs()
                    report.append("\nRegisters:")
                    for r in ["EAX","EBX","ECX","EDX","ESI","EDI","EBP","ESP","EIP"]:
                        if r in regs:
                            report.append("%s = 0x%08X" % (r, regs[r]))

                    # Call stack
                    stack = imm.getCallStack()
                    report.append("\nCall Stack (top 20):")
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

                    # Save report
                    with open(crash_file, "w") as f:
                        f.write("\n".join(report))

                    imm.log("Crash saved: %s" % crash_file)

                    # Restart process
                    imm.log("Restarting process...")
                    imm.restartProcess()
                    time.sleep(3)
                    break

        except Exception as e:
            imm.log("Monitor error: %s" % str(e), 1)
            time.sleep(3)

    return "CrashMon stopped"
