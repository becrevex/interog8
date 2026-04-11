#!/usr/bin/env python3
# crashmon.py - Pure Python Windows crash monitor (ctypes + pywin32)
# Usage: python win32_crashmon.py "C:\path\to\program.exe"
#        python win32_crashmon.py -p 1234

import sys
import time
import os
from datetime import datetime
import ctypes
from ctypes import wintypes

# Windows constants
DEBUG_PROCESS = 0x00000001
CREATE_SUSPENDED = 0x00000004
CREATE_NEW_CONSOLE = 0x00000010
DEBUG_ONLY_THIS_PROCESS = 0x00000002

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE),
                ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD)]

class STARTUPINFOW(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD),
                ("lpReserved", wintypes.LPWSTR),
                ("lpDesktop", wintypes.LPWSTR),
                ("lpTitle", wintypes.LPWSTR),
                ("dwX", wintypes.DWORD),
                ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD),
                ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD),
                ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD),
                ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD),
                ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p),
                ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE),
                ("hStdError", wintypes.HANDLE)]

class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionCode", wintypes.DWORD),
                ("ExceptionFlags", wintypes.DWORD),
                ("ExceptionRecord", ctypes.c_void_p),
                ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", wintypes.DWORD),
                ("ExceptionInformation", wintypes.DWORD * 15)]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wintypes.DWORD),
                ("dwProcessId", wintypes.DWORD),
                ("dwThreadId", wintypes.DWORD),
                ("u", EXCEPTION_DEBUG_INFO)]   # simplified for crash detection

kernel32 = ctypes.windll.kernel32

def main():
    if len(sys.argv) < 2:
        print("Usage:\n  python crashmon.py <full_path_to_exe>\n  python crashmon.py -p <PID>")
        sys.exit(1)

    pid = None
    exe_path = None
    if sys.argv[1] == "-p" and len(sys.argv) > 2:
        pid = int(sys.argv[2])
    else:
        exe_path = " ".join(sys.argv[1:])

    crash_dir = "crashes"
    os.makedirs(crash_dir, exist_ok=True)
    crash_count = 0

    print("=== Pure Python CrashMon Started ===")

    while True:
        try:
            if pid:
                print(f"Attaching to PID {pid}...")
                # For simplicity we launch new for now (attach is more complex with ctypes)
                # If you need true attach, let me know and I'll add it.
                print("Attach by PID not implemented in this minimal version yet.")
                break
            else:
                print(f"Launching {exe_path}...")
                si = STARTUPINFOW()
                si.cb = ctypes.sizeof(si)
                pi = PROCESS_INFORMATION()

                kernel32.CreateProcessW(
                    None, exe_path, None, None, False,
                    DEBUG_PROCESS | CREATE_NEW_CONSOLE,
                    None, None, ctypes.byref(si), ctypes.byref(pi)
                )

            print("Process running - monitoring for crashes... (Ctrl+C to stop)")

            debug_event = DEBUG_EVENT()
            while True:
                if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 1000):
                    continue

                if debug_event.dwDebugEventCode == 1:   # EXCEPTION_DEBUG_EVENT
                    exc_code = debug_event.u.ExceptionCode
                    if exc_code not in (0x80000003, 0x80000004):   # ignore breakpoints/single-step
                        crash_count += 1
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        crash_file = os.path.join(crash_dir, f"crash_{crash_count:03d}_{ts}.txt")

                        print(f"\n!!! CRASH #{crash_count} DETECTED !!! (code 0x{exc_code:08X})")

                        report = [f"=== Crash Report #{crash_count} - {ts} ===",
                                  f"Exception code: 0x{exc_code:08X}"]

                        # TODO: full register/stack dump via GetThreadContext + StackWalk64
                        # (can be added if you need it - let me know)

                        report.append("\nNote: Full register + stack dump coming in next version if you want it.")

                        with open(crash_file, "w", encoding="utf-8") as f:
                            f.write("\n".join(report))

                        print(f"Crash log saved → {crash_file}")

                        # Kill the crashed process
                        kernel32.TerminateProcess(pi.hProcess, 1)
                        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x80010001)  # DBG_EXCEPTION_NOT_HANDLED
                        break   # restart loop

                kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x80010001)

        except KeyboardInterrupt:
            print("\nStopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            time.sleep(2)

    print("CrashMon stopped.")

if __name__ == "__main__":
    main()
