#!/usr/bin/env python3
# crashmon.py - Pure Python Windows Crash Monitor (100% robust version)
# Usage: python crashmon.py "C:\full\path\to\vulnserver.exe"
#        python crashmon.py -p 1234

import sys
import time
import os
from datetime import datetime
import ctypes
from ctypes import wintypes
import traceback

kernel32 = ctypes.windll.kernel32

# Fix for missing ULONG_PTR on some Python installs
if not hasattr(wintypes, 'ULONG_PTR'):
    wintypes.ULONG_PTR = ctypes.c_ulong if ctypes.sizeof(ctypes.c_void_p) == 4 else ctypes.c_ulonglong

# ====================== MANUAL STRUCTURE DEFINITIONS ======================
class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
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
        ("hStdError", wintypes.HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD)
    ]

# Minimal DEBUG_EVENT using byte buffer (no abstract class issues)
class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", ctypes.c_byte * 160)
    ]

# 32-bit CONTEXT
class CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),
        ("Dr0", wintypes.DWORD), ("Dr1", wintypes.DWORD), ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD), ("Dr6", wintypes.DWORD), ("Dr7", wintypes.DWORD),
        ("FloatSave", ctypes.c_byte * 112),
        ("SegGs", wintypes.DWORD), ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD), ("SegDs", wintypes.DWORD),
        ("Edi", wintypes.DWORD), ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD), ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD), ("Eax", wintypes.DWORD),
        ("Ebp", wintypes.DWORD), ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD), ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD), ("SegSs", wintypes.DWORD),
        ("ExtendedRegisters", ctypes.c_byte * 512)
    ]

# Constants
DEBUG_PROCESS = 0x00000001
CREATE_NEW_CONSOLE = 0x00000010
EXCEPTION_DEBUG_EVENT = 1
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

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

    print("=== Pure Python CrashMon Started (100% robust) ===")

    while True:
        hProcess = None
        try:
            if pid:
                print(f"Attaching to PID {pid}...")
                if not kernel32.DebugActiveProcess(pid):
                    print("Attach failed!")
                    time.sleep(3)
                    continue
                hProcess = kernel32.OpenProcess(0x1F0FFF, False, pid)
            else:
                print(f"Launching {exe_path}...")
                si = STARTUPINFOW()
                si.cb = ctypes.sizeof(si)
                pi = PROCESS_INFORMATION()

                if not kernel32.CreateProcessW(
                    None, exe_path, None, None, False,
                    DEBUG_PROCESS | CREATE_NEW_CONSOLE,
                    None, None, ctypes.byref(si), ctypes.byref(pi)
                ):
                    print(f"Launch failed! Windows error code: {kernel32.GetLastError()}")
                    time.sleep(3)
                    continue
                hProcess = pi.hProcess

            print("Monitoring for crashes... (Ctrl+C to stop)")

            debug_event = DEBUG_EVENT()
            while True:
                if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 1000):
                    continue

                if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
                    exc_code = int.from_bytes(debug_event.u[0:4], "little")

                    if exc_code not in (EXCEPTION_BREAKPOINT, EXCEPTION_SINGLE_STEP):
                        crash_count += 1
                        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                        crash_file = os.path.join(crash_dir, f"crash_{crash_count:03d}_{ts}.txt")

                        print(f"\n!!! CRASH #{crash_count} DETECTED !!! (0x{exc_code:08X})")

                        report = [f"=== Crash Report #{crash_count} - {ts} ===",
                                  f"Exception code: 0x{exc_code:08X}"]

                        # Full registers + stack dump + call stack
                        ctx = CONTEXT()
                        ctx.ContextFlags = 0x10007
                        hThread = kernel32.OpenThread(0x1F03FF, False, debug_event.dwThreadId)

                        if kernel32.GetThreadContext(hThread, ctypes.byref(ctx)):
                            report.append("\nRegisters:")
                            for name, val in [
                                ("EAX", ctx.Eax), ("EBX", ctx.Ebx), ("ECX", ctx.Ecx),
                                ("EDX", ctx.Edx), ("ESI", ctx.Esi), ("EDI", ctx.Edi),
                                ("EBP", ctx.Ebp), ("ESP", ctx.Esp), ("EIP", ctx.Eip)
                            ]:
                                report.append(f"{name:4} = 0x{val:08X}")

                            # Stack dump around ESP
                            esp = ctx.Esp
                            report.append(f"\nStack dump around ESP (0x{esp:08X}):")
                            buf = (ctypes.c_byte * 384)()
                            if kernel32.ReadProcessMemory(hProcess, esp - 64, buf, 384, None):
                                for i in range(0, 384, 4):
                                    val = int.from_bytes(buf[i:i+4], "little")
                                    addr = esp - 64 + i
                                    report.append(f"  0x{addr:08X} : 0x{val:08X}")

                            # Call stack (EBP chain walk)
                            report.append("\nCall Stack (EBP chain, top 20):")
                            ebp = ctx.Ebp
                            for i in range(20):
                                try:
                                    ret_addr = ctypes.c_uint(0)
                                    kernel32.ReadProcessMemory(hProcess, ebp + 4, ctypes.byref(ret_addr), 4, None)
                                    report.append(f"  {i:02d}: 0x{ret_addr.value:08X}")
                                    kernel32.ReadProcessMemory(hProcess, ebp, ctypes.byref(ret_addr), 4, None)
                                    ebp = ret_addr.value
                                    if ebp == 0 or ebp == 0xFFFFFFFF:
                                        break
                                except:
                                    break

                        with open(crash_file, "w", encoding="utf-8") as f:
                            f.write("\n".join(report))

                        print(f"Crash saved → {crash_file}")

                        kernel32.TerminateProcess(hProcess, 1)
                        break

                kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, 0x80010001)

        except KeyboardInterrupt:
            print("\nStopped by user.")
            break
        except Exception as e:
            print(f"Error: {e}")
            traceback.print_exc()
            time.sleep(2)
        finally:
            if exe_path:
                print("Restarting process in 2 seconds...")
                time.sleep(2)

    print("CrashMon stopped.")

if __name__ == "__main__":
    main()
