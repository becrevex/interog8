// crashpeep.js - WinDbg JS extension for vuln research
// Load with: .scriptload C:\path\to\crashpeep.js

"use strict";

function dumpCrashInfo() {
    host.diagnostics.debugLog("!!! CRASH DETECTED !!!\n");

    let report = [];
    let ts = new Date().toISOString().replace(/[:.]/g, "-");

    report.push(`=== Crash Report - ${ts} ===`);
    report.push(`Exception: ${host.getModuleSymbolName(host.namespace.Debugger.State.Scripts[0].CurrentThread.Context.Eip)}`);

    // Registers
    report.push("\nRegisters:");
    let ctx = host.namespace.Debugger.State.Scripts[0].CurrentThread.Context;
    ["Eax","Ebx","Ecx","Edx","Esi","Edi","Ebp","Esp","Eip"].forEach(reg => {
        report.push(`${reg.padEnd(4)} = 0x${ctx[reg].toString(16).padStart(8, "0")}`);
    });

    // Stack dump around ESP
    report.push(`\nStack dump around ESP (0x${ctx.Esp.toString(16).padStart(8, "0")}):`);
    let esp = ctx.Esp;
    for (let i = -64; i < 128; i += 4) {
        try {
            let addr = esp + i;
            let val = host.memory.readMemoryValues(addr, 1, 4)[0];
            report.push(`  0x${addr.toString(16).padStart(8, "0")} : 0x${val.toString(16).padStart(8, "0")}`);
        } catch (e) {}
    }

    // Call stack
    report.push("\nCall Stack:");
    host.namespace.Debugger.State.Scripts[0].CurrentThread.Stack.Frames.forEach((frame, i) => {
        if (i < 20) {
            let addr = frame.Address.toString(16).padStart(8, "0");
            let sym = frame.Symbol || "";
            report.push(`  ${i.toString().padStart(2, "0")}: 0x${addr}  ${sym}`);
        }
    });

    // Save to file
    let crashDir = "crashes";
    host.executeCommand(`!py -c "import os; os.makedirs('${crashDir}', exist_ok=True)"`);
    let filename = `${crashDir}\\crash_${ts}.txt`;
    host.executeCommand(`.writefile "${filename}" "${report.join("\\n")}"`);

    host.diagnostics.debugLog(`Full report saved → ${filename}\n`);

    // Auto-restart
    host.diagnostics.debugLog("Restarting process...\n");
    host.executeCommand(".restart");
}

function initializeScript() {
    return {
        // Custom command: !crashpeep
        getCommand: function() {
            return {
                "crashpeep": {
                    exec: function() {
                        dumpCrashInfo();
                    },
                    help: "Dump registers/stack on current crash and restart"
                }
            };
        },

        // Auto-hook on exceptions
        onException: function(exception) {
            if (exception.ExceptionCode !== 0x80000003 &&   // breakpoint
                exception.ExceptionCode !== 0x80000004) {   // single step
                dumpCrashInfo();
            }
            return true; // continue
        }
    };
}
