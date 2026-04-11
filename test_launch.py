import sys
import ctypes
from ctypes import wintypes

kernel32 = ctypes.windll.kernel32

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

def main():
    if len(sys.argv) > 1:
        exe = sys.argv[1]
    else:
        exe = r"C:\Windows\System32\calc.exe"

    print(f"Attempting to launch: {exe}")
    print("Running as Administrator?")

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    flags = 0x00000001 | 0x00000010   # DEBUG_PROCESS | CREATE_NEW_CONSOLE

    success = kernel32.CreateProcessW(
        None, exe, None, None, False,
        flags, None, None,
        ctypes.byref(si), ctypes.byref(pi)
    )

    if success:
        print("✅ LAUNCH SUCCEEDED!")
        print(f"Process ID: {pi.dwProcessId}")
        input("Close calc.exe then press Enter to exit test...")
    else:
        err = kernel32.GetLastError()
        print("❌ LAUNCH FAILED")
        print(f"Windows error code: {err} (0x{err:X})")
        print("Look up the error code here: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes")

if __name__ == "__main__":
    main()
