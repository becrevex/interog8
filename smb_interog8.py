#!/usr/bin/env python3
"""smb_fuzzer.py – Comprehensive SMBv2 fuzzer using boofuzz

   * Fuzzes SMB2 NEGOTIATE, SESSION_SETUP, and TREE_CONNECT requests
   * Argparse for target specification
   * Suitable for lab or authorized red‑team environments only

   Example:
        python smb_fuzzer.py -i 192.168.1.20 -p 445 --iterations 5000
"""

import argparse
from boofuzz import (
    Session,
    Target,
    TCPSocketConnection,
    s_initialize,
    s_static,
    s_byte,
    s_word,
    s_dword,
    s_qword,
    s_string,
    s_block_start,
    s_block_end,
    s_size,
)


def parse_args():
    parser = argparse.ArgumentParser(description="SMBv2 fuzzer with boofuzz")
    parser.add_argument("-i", "--ip", required=True, help="Target IP address")
    parser.add_argument("-p", "--port", type=int, default=445, help="Target port (default 445)")
    parser.add_argument("--iterations", type=int, default=0, help="Limit fuzz cases (0 = unlimited)")
    parser.add_argument("--srcport", type=int, default=50000, help="Source port for TCP (default 50000)")
    return parser.parse_args()

SMB2_PROTOCOL_ID = 0xFE534D42  # "\xFE SMB"


def smb2_header(command: int, flags: int = 0):
    """Creates a fuzzable SMB2 common header block."""
    s_block_start(f"hdr_cmd_{command}")
    s_dword(SMB2_PROTOCOL_ID, name="ProtocolID", fuzzable=False)
    s_word(64, name="StructureSize", fuzzable=False)
    s_word(command, name="Command", fuzzable=True)
    s_dword(flags, name="Flags", fuzzable=True)
    s_dword(0, name="NextCommand", fuzzable=True)
    s_qword(0, name="MessageID", fuzzable=True)
    s_qword(0, name="Reserved", fuzzable=True)
    s_qword(0, name="TreeID", fuzzable=True)
    s_qword(0, name="SessionID", fuzzable=True)
    s_qword(0, name="Signature", fuzzable=False)
    s_block_end(f"hdr_cmd_{command}")

def build_negotiate_request():
    if not s_initialize("smb2_negotiate"):
        return

    # NetBIOS Session Service header (length prefix)
    s_byte(value=0, name="NBSS_Type", fuzzable=False)  # 0 = session message
    s_dword(value=0, name="NBSS_Length", fuzzable=False, endian="big", full_range=False)

    smb2_header(command=0x0000)  # SMB2 NEGOTIATE

    # SMB2 NEGOTIATE payload
    s_word(36, name="NegStructSize", fuzzable=False)
    s_word(0, name="DialectsCount", fuzzable=True)
    s_word(0x0001, name="SecurityMode", fuzzable=True)
    s_word(0, name="DialectRevision", fuzzable=True)
    s_dword(0, name="Reserved2")

    # Client GUID
    s_qword(0x1122334455667788, name="ClientGuid1", fuzzable=True)
    s_qword(0x99AABBCCDDEEFF00, name="ClientGuid2", fuzzable=True)

    # Negotiate contexts length + offset / optional – keep 0
    s_dword(0, name="NegCtxOffset", fuzzable=True)
    s_dword(0, name="NegCtxCount", fuzzable=True)

    # Dialect list (fuzz)
    s_block_start("dialects")
    for d in [0x0202, 0x0210, 0x0222, 0x0244, 0x0311]:
        s_word(d, name=f"dialect_{hex(d)}", fuzzable=True)
    s_block_end("dialects")

def build_session_setup():
    if not s_initialize("smb2_sesssetup"):
        return
    s_byte(value=0, name="NBSS_Type", fuzzable=False)
    s_dword(value=0, name="NBSS_Length", endian="big", fuzzable=False)

    smb2_header(command=0x0001)  # SESSION_SETUP

    s_word(25, name="StructSize", fuzzable=False)
    s_byte(0, name="Flags", fuzzable=True)
    s_byte(0, name="SecurityMode", fuzzable=True)
    s_dword(0, name="Capabilities", fuzzable=True)
    s_dword(0, name="Channel", fuzzable=True)

    # Security blob length & offset
    s_word(0, name="SecBufOffset", fuzzable=True)
    s_word(0, name="SecBufLen", fuzzable=True)
    s_qword(0, name="PrevSessionID", fuzzable=True)

    # Security blob (here we fuzz raw bytes)
    s_string("NTLMSSP", name="SecBlob", max_len=256, fuzzable=True)

def build_tree_connect():
    if not s_initialize("smb2_treeconnect"):
        return
    s_byte(0, name="NBSS_Type", fuzzable=False)
    s_dword(0, name="NBSS_Length", endian="big", fuzzable=False)

    smb2_header(command=0x0003)  # TREE_CONNECT

    s_word(9, name="StructSize", fuzzable=False)
    s_word(0, name="Flags", fuzzable=True)
    s_word(0, name="PathOffset", fuzzable=True)
    s_word(0, name="PathLength", fuzzable=True)

    # UNC Path (fuzzable string)
    s_string(r"\\SERVER\SHARE", name="UNC", max_len=512, fuzzable=True)

def main():
    args = parse_args()

    build_negotiate_request()
    build_session_setup()
    build_tree_connect()

    sess = Session(
        target=Target(
            connection=TCPSocketConnection(dst_host=args.ip, dst_port=args.port, src_port=args.srcport)
        ),
        total_fuzz_cases=args.iterations if args.iterations > 0 else None,
        sleep_time=0.05,
    )

    for req_name in ["smb2_negotiate", "smb2_sesssetup", "smb2_treeconnect"]:
        sess.connect(s_get(req_name))

    sess.fuzz()

if __name__ == "__main__":
    main()
