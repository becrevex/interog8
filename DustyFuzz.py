#!/usr/bin/env python3
"""
DustyFuzzer + Microservice
- Multi-threaded (Flask runs in background)
- Pause on crash from external debugger
- Saves payload + registers for exploit dev
"""

import threading
import time
import json
from datetime import datetime
from pathlib import Path
from queue import Queue

from flask import Flask, request, jsonify
import requests  # for debugger to call us

from boofuzz import (
    Session, Target, TCPSocketConnection,
    s_initialize, s_string, s_delim, s_static, s_byte, s_word,
    FuzzLoggerText, FuzzLoggerCsv
)

# ====================== SHARED STATE ======================
pause_event = threading.Event()
crash_queue = Queue()          # debugger → fuzzer
current_payload = None
fuzzer_running = True

# ====================== MICRO SERVICE ======================
app = Flask(__name__)

@app.route("/pause", methods=["POST"])
def pause_fuzzer():
    """Called by your debugger when a crash is detected"""
    global current_payload
    data = request.get_json()
    
    payload = data.get("payload", b"")
    registers = data.get("registers", {})
    crash_file = data.get("crash_file", "")
    
    crash_queue.put({
        "timestamp": datetime.now().isoformat(),
        "payload": payload,
        "registers": registers,
        "crash_file": crash_file
    })
    
    pause_event.set()   # tell fuzzer to pause
    print(f"\n🚨 MICRO SERVICE: PAUSE REQUESTED (crash #{len(list(Path('crashes').glob('*.json')))+1})")
    print(f"   Payload length: {len(payload)} bytes")
    
    return jsonify({"status": "paused", "saved": True})

@app.route("/resume", methods=["POST"])
def resume_fuzzer():
    pause_event.clear()
    print("✅ MICRO SERVICE: Fuzzer resumed")
    return jsonify({"status": "resumed"})

@app.route("/status", methods=["GET"])
def status():
    return jsonify({
        "paused": pause_event.is_set(),
        "pending_crashes": crash_queue.qsize()
    })

def run_microservice():
    """Run Flask in background thread"""
    app.run(host="0.0.0.0", port=5000, threaded=True, use_reloader=False)

# ====================== BOOFUZZ FUZZER ======================
def post_test_case_callback(target, fuzz_data_logger, session, *args, **kwargs):
    """Called after every test case — checks for pause request"""
    global current_payload
    current_payload = session.last_send  # save the exact bytes we just sent
    
    if pause_event.is_set():
        print(f"\n⏸️  FUZZER PAUSED after test case {session.test_case_index}")
        # Wait until debugger tells us to resume
        while pause_event.is_set() and fuzzer_running:
            time.sleep(0.5)
        print("▶️  FUZZER RESUMED")

def crash_callback(target, fuzz_data_logger, session, *args, **kwargs):
    """Optional extra safety net (called by Boofuzz on detected failures)"""
    print("Boofuzz detected failure — waiting for debugger confirmation...")

def main():
    global fuzzer_running

    # Start microservice in background thread
    ms_thread = threading.Thread(target=run_microservice, daemon=True)
    ms_thread.start()
    time.sleep(1)  # give Flask time to start
    print("🚀 Microservice running on http://localhost:5000")
    print("   → Debugger should POST to /pause with payload + registers")

    # Create crashes folder
    crash_dir = Path("crashes")
    crash_dir.mkdir(exist_ok=True)

    # ====================== PROTOCOL DEFINITION (vulnserver example) ======================
    s_initialize("TRUN")
    s_string("TRUN", fuzzable=False)
    s_delim(" ", fuzzable=False)
    s_string("FUZZ", name="command_data", fuzzable=True)   # ← this is what gets mutated

    # You can add more commands here (e.g. GMON, KSTET, etc.)

    # ====================== SESSION ======================
    session = Session(
        target=Target(connection=TCPSocketConnection("127.0.0.1", 2121)),
        fuzz_loggers=[FuzzLoggerText(), FuzzLoggerCsv()],
        post_test_case_callbacks=[post_test_case_callback],
        # crash_threshold=1,          # stop after 1 crash if you want
        # restart_interval=0,         # we control restarts via debugger
        sleep_time=0.1,
    )

    print("🎯 Starting collaborative fuzzing on vulnserver:2121")
    print("   Press Ctrl+C to stop\n")

    try:
        session.connect(s_get("TRUN"))
        session.fuzz()
    except KeyboardInterrupt:
        print("\n🛑 Fuzzer stopped by user")
    finally:
        fuzzer_running = False
        print("Shutdown complete.")

if __name__ == "__main__":
    main()
