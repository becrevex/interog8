#!/usr/bin/env python3
# crashmon_full.py - Visible launch + FULL registers/stack/callstack + NO WinDbg popup
# Usage: python crashmon_full.py "C:\full\path\to\vulnserver.exe"

import sys
import time
import os
from datetime import datetime
import subprocess
import ctypes
from ctypes import wintypes
import traceback
import winreg

kernel32 = ctypes.windll.kernel32

# ====================== TEMPORARILY DISABLE WinDbg JIT DEBUGGER ======================
def disable_jit_debugger():
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                             0, winreg.KEY_SET_VALUE)
        # Backup original values
        try:
            original_auto = winreg.QueryValueEx(key, "Auto")[0]
            original_debugger = winreg.QueryValueEx(key, "Debugger")[0]
        except FileNotFoundError:
            original_auto = 1
            original_debugger = ""

        winreg.SetValueEx(key, "Auto", 0, winreg.REG_DWORD, 0)          # Disable auto debugger
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, "")       # Clear debugger path
        winreg.CloseKey(key)
        print("✅ JIT debugger (WinDbg) temporarily disabled")
        return (original_auto, original_debugger)
    except Exception as e:
        print(f"Warning: Could not disable JIT debugger: {e}")
        return None

def restore_jit_debugger(original):
    if original is None:
        return
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug",
                             0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "Auto", 0, winreg.REG_DWORD, original[0])
        winreg.SetValueEx(key, "Debugger", 0, winreg.REG_SZ, original[1])
        winreg.CloseKey(key)
        print("✅ JIT debugger restored to original settings")
    except Exception as e:
        print(f"Warning: Could not restore JIT debugger: {e}")

# ====================== STRUCTURES ======================
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

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", wintypes.DWORD),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
        ("u", ctypes.c_byte * 160)
    ]

# Constants
EXCEPTION_DEBUG_EVENT = 1
EXCEPTION_BREAKPOINT = 0x80000003
EXCEPTION_SINGLE_STEP = 0x80000004

def main():
    if len(sys.argv) < 2:
        print("Usage: python crashmon_full.py <full_path_to_exe>")
        sys.exit(1)

    exe_path = " ".join(sys.argv[1:])
    crash_dir = "crashes"
    os.makedirs(crash_dir, exist_ok=True)
    crash_count = 0

    # Disable WinDbg JIT debugger before we start
    original_jit = disable_jit_debugger()

    print("=== Full CrashMon Started (visible + registers + stack + NO WinDbg) ===")
    print(f"Target: {exe_path}\n")

    try:
        while True:
            proc = None
            hProcess = None
            try:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Launching visible process...")
                
                proc = subprocess.Popen(
                    exe_path,
                    creationflags=subprocess.CREATE_NEW_CONSOLE,
                    shell=False
                )

                time.sleep(1.5)  # let it start

                if not kernel32.DebugActiveProcess(proc.pid):
                    print("Attach failed!")
                    time.sleep(2)
                    continue

                hProcess = kernel32.OpenProcess(0x1F0FFF, False, proc.pid)
                print(f"Monitoring (PID {proc.pid})...")

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
                                      f"Exception code: 0x{exc_code:08X}",
                                      f"PID: {proc.pid}"]

                            # === FULL REGISTERS + STACK DUMP + CALL STACK ===
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

                                # Stack dump
                                esp = ctx.Esp
                                report.append(f"\nStack dump around ESP (0x{esp:08X}):")
                                buf = (ctypes.c_byte * 384)()
                                if kernel32.ReadProcessMemory(hProcess, esp - 64, buf, 384, None):
                                    for i in range(0, 384, 4):
                                        val = int.from_bytes(buf[i:i+4], "little")
                                        addr = esp - 64 + i
                                        report.append(f"  0x{addr:08X} : 0x{val:08X}")

                                # Call stack
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

                            print(f"Full crash report saved → {crash_file}")

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
                if proc:
                    try:
                        proc.kill()
                    except:
                        pass
                print("Restarting in 2 seconds...\n")
                time.sleep(2)

    finally:
        # Restore original JIT debugger setting when script exits
        restore_jit_debugger(original_jit)

if __name__ == "__main__":
    main()
