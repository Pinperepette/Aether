//
//  FridaScriptGenerator.swift
//  Aether
//
//  Frida script generator for iOS and macOS dynamic instrumentation
//

import Foundation

// MARK: - Enums

enum FridaPlatform: String, CaseIterable, Identifiable {
    case iOS = "iOS"
    case macOS = "macOS"

    var id: String { rawValue }
}

enum FridaHookType: String, CaseIterable, Identifiable {
    case trace = "Trace"
    case bypass = "Bypass"
    case intercept = "Intercept"
    case dump = "Memory Dump"
    case stringPatch = "String Patch"
    case antiDebug = "Anti-Debug"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .trace: return "eye"
        case .bypass: return "shield.slash"
        case .intercept: return "arrow.left.arrow.right"
        case .dump: return "memorychip"
        case .stringPatch: return "textformat"
        case .antiDebug: return "ladybug"
        }
    }
}

// MARK: - Result Structures

struct FridaScriptResult: Identifiable {
    let id = UUID()
    let script: String
    let platform: FridaPlatform
    let hookType: FridaHookType
    let targetFunctions: [String]
    let description: String
    let moduleName: String
    let offsets: [UInt64]
}

struct AIFridaScriptResult: Identifiable {
    let id = UUID()
    let script: String
    let explanation: String
    let hookPoints: [String]
    let bypassImplemented: [String]
    let warnings: [String]
}

// MARK: - Generator

class FridaScriptGenerator {

    // MARK: - Public Methods

    func generateHookScript(
        function: Function,
        binary: BinaryFile,
        platform: FridaPlatform,
        hookType: FridaHookType,
        bypassTechniques: [String] = [],
        patchPoints: [String] = []
    ) -> FridaScriptResult {
        let moduleName = binary.url.deletingPathExtension().lastPathComponent
        let offset = function.startAddress - binary.baseAddress

        let script: String
        let description: String

        switch hookType {
        case .trace:
            script = generateTraceScript(
                function: function,
                moduleName: moduleName,
                offset: offset,
                platform: platform
            )
            description = "Traces calls to \(function.displayName), logging arguments and return values"

        case .bypass:
            script = generateBypassScript(
                function: function,
                moduleName: moduleName,
                offset: offset,
                platform: platform,
                bypassTechniques: bypassTechniques
            )
            description = "Bypasses \(function.displayName) by modifying return value"

        case .intercept:
            script = generateInterceptScript(
                function: function,
                moduleName: moduleName,
                offset: offset,
                platform: platform
            )
            description = "Advanced intercept with argument/return modification for \(function.displayName)"

        case .dump:
            script = generateDumpScript(
                function: function,
                moduleName: moduleName,
                offset: offset,
                size: function.size
            )
            description = "Dumps memory at \(function.displayName) (\(function.size) bytes)"

        case .stringPatch:
            script = generateStringPatchScript(
                moduleName: moduleName,
                platform: platform
            )
            description = "Template for patching strings in memory"

        case .antiDebug:
            script = generateAntiDebugScript(platform: platform)
            description = "Bypasses common anti-debugging techniques (ptrace, sysctl, getppid)"
        }

        return FridaScriptResult(
            script: script,
            platform: platform,
            hookType: hookType,
            targetFunctions: [function.displayName],
            description: description,
            moduleName: moduleName,
            offsets: [offset]
        )
    }

    func generateMultiHookScript(
        functions: [Function],
        binary: BinaryFile,
        platform: FridaPlatform
    ) -> FridaScriptResult {
        let moduleName = binary.url.deletingPathExtension().lastPathComponent
        var offsets: [UInt64] = []
        var hookCode = ""

        for function in functions {
            let offset = function.startAddress - binary.baseAddress
            offsets.append(offset)
            hookCode += generateSingleHookBlock(
                functionName: function.displayName,
                offset: offset
            )
        }

        let script = generateMultiHookWrapper(
            moduleName: moduleName,
            hookCode: hookCode,
            platform: platform
        )

        return FridaScriptResult(
            script: script,
            platform: platform,
            hookType: .trace,
            targetFunctions: functions.map { $0.displayName },
            description: "Traces \(functions.count) functions",
            moduleName: moduleName,
            offsets: offsets
        )
    }

    func generateBypassFromSecurityAnalysis(
        securityResult: SecurityAnalysisResult,
        function: Function,
        binary: BinaryFile,
        platform: FridaPlatform
    ) -> FridaScriptResult {
        return generateHookScript(
            function: function,
            binary: binary,
            platform: platform,
            hookType: .bypass,
            bypassTechniques: securityResult.bypassTechniques,
            patchPoints: securityResult.patchPoints
        )
    }

    // MARK: - Private Template Methods

    private func generateTraceScript(
        function: Function,
        moduleName: String,
        offset: UInt64,
        platform: FridaPlatform
    ) -> String {
        let offsetHex = String(format: "0x%llx", offset)

        if platform == .iOS {
            return """
            // Frida Trace Script for iOS
            // Binary: \(moduleName)
            // Function: \(function.displayName)
            // Generated by Aether Disassembler

            if (ObjC.available) {
                var moduleName = "\(moduleName)";
                var module = Process.findModuleByName(moduleName);

                if (module) {
                    var baseAddr = module.base;
                    var funcOffset = \(offsetHex);
                    var targetAddr = baseAddr.add(funcOffset);

                    console.log("[*] Module base: " + baseAddr);
                    console.log("[*] Hooking \(function.displayName) at: " + targetAddr);

                    Interceptor.attach(targetAddr, {
                        onEnter: function(args) {
                            console.log("\\n[+] \(function.displayName) called");
                            console.log("    arg0: " + args[0]);
                            console.log("    arg1: " + args[1]);
                            console.log("    arg2: " + args[2]);
                            console.log("    arg3: " + args[3]);

                            // Backtrace
                            console.log("    Backtrace:\\n" +
                                Thread.backtrace(this.context, Backtracer.ACCURATE)
                                .map(DebugSymbol.fromAddress).join("\\n"));
                        },
                        onLeave: function(retval) {
                            console.log("[+] \(function.displayName) returned: " + retval);
                        }
                    });

                    console.log("[*] Hook installed successfully");
                } else {
                    console.log("[-] Module not found: " + moduleName);
                }
            } else {
                console.log("[-] Objective-C runtime not available");
            }
            """
        } else {
            return """
            // Frida Trace Script for macOS
            // Binary: \(moduleName)
            // Function: \(function.displayName)
            // Generated by Aether Disassembler

            var moduleName = "\(moduleName)";
            var module = Process.findModuleByName(moduleName);

            if (module) {
                var baseAddr = module.base;
                var funcOffset = \(offsetHex);
                var targetAddr = baseAddr.add(funcOffset);

                console.log("[*] Module base: " + baseAddr);
                console.log("[*] Hooking \(function.displayName) at: " + targetAddr);

                Interceptor.attach(targetAddr, {
                    onEnter: function(args) {
                        console.log("\\n[+] \(function.displayName) called");
                        console.log("    arg0: " + args[0]);
                        console.log("    arg1: " + args[1]);
                        console.log("    arg2: " + args[2]);
                        console.log("    arg3: " + args[3]);

                        // Backtrace
                        console.log("    Backtrace:\\n" +
                            Thread.backtrace(this.context, Backtracer.ACCURATE)
                            .map(DebugSymbol.fromAddress).join("\\n"));
                    },
                    onLeave: function(retval) {
                        console.log("[+] \(function.displayName) returned: " + retval);
                    }
                });

                console.log("[*] Hook installed successfully");
            } else {
                console.log("[-] Module not found: " + moduleName);
            }
            """
        }
    }

    private func generateBypassScript(
        function: Function,
        moduleName: String,
        offset: UInt64,
        platform: FridaPlatform,
        bypassTechniques: [String]
    ) -> String {
        let offsetHex = String(format: "0x%llx", offset)
        let bypassComment = bypassTechniques.isEmpty ? "" : """

        // Bypass techniques to implement:
        \(bypassTechniques.map { "// - \($0)" }.joined(separator: "\n"))
        """

        let platformCheck = platform == .iOS ? """
        if (ObjC.available) {
        """ : ""

        let platformEnd = platform == .iOS ? """
        } else {
            console.log("[-] Objective-C runtime not available");
        }
        """ : ""

        return """
        // Frida Bypass Script
        // Binary: \(moduleName)
        // Function: \(function.displayName)
        // Platform: \(platform.rawValue)
        // Generated by Aether Disassembler
        \(bypassComment)

        \(platformCheck)
        var moduleName = "\(moduleName)";
        var module = Process.findModuleByName(moduleName);

        if (module) {
            var baseAddr = module.base;
            var funcOffset = \(offsetHex);
            var targetAddr = baseAddr.add(funcOffset);

            console.log("[*] Bypassing \(function.displayName) at: " + targetAddr);

            Interceptor.attach(targetAddr, {
                onEnter: function(args) {
                    console.log("[+] \(function.displayName) called - will bypass");
                    // Save original args if needed
                    this.arg0 = args[0];
                    this.arg1 = args[1];
                },
                onLeave: function(retval) {
                    // Force return value to bypass check
                    // Common bypass patterns:
                    // - Return 1 (true) to pass validation
                    // - Return 0 (false) to skip check
                    // - Return original arg to passthrough

                    var originalReturn = retval.toInt32();
                    retval.replace(ptr(1)); // Force success
                    console.log("[+] \(function.displayName) bypassed");
                    console.log("    Original return: " + originalReturn);
                    console.log("    Modified return: 1");
                }
            });

            console.log("[*] Bypass hook installed");
        } else {
            console.log("[-] Module not found: " + moduleName);
        }
        \(platformEnd)
        """
    }

    private func generateInterceptScript(
        function: Function,
        moduleName: String,
        offset: UInt64,
        platform: FridaPlatform
    ) -> String {
        let offsetHex = String(format: "0x%llx", offset)

        return """
        // Frida Advanced Intercept Script
        // Binary: \(moduleName)
        // Function: \(function.displayName)
        // Platform: \(platform.rawValue)
        // Generated by Aether Disassembler

        var moduleName = "\(moduleName)";
        var module = Process.findModuleByName(moduleName);

        if (module) {
            var baseAddr = module.base;
            var funcOffset = \(offsetHex);
            var targetAddr = baseAddr.add(funcOffset);

            console.log("[*] Installing advanced intercept on \(function.displayName)");

            Interceptor.attach(targetAddr, {
                onEnter: function(args) {
                    console.log("\\n[+] \(function.displayName) called");

                    // Save original arguments for modification
                    this.arg0 = args[0];
                    this.arg1 = args[1];
                    this.arg2 = args[2];
                    this.arg3 = args[3];

                    // Log argument types and values
                    for (var i = 0; i < 4; i++) {
                        try {
                            var arg = args[i];
                            console.log("    arg" + i + " (ptr): " + arg);

                            // Try to read as string
                            try {
                                var str = arg.readCString();
                                if (str && str.length > 0 && str.length < 256) {
                                    console.log("    arg" + i + " (string): " + str);
                                }
                            } catch(e) {}

                            // Try to read as int
                            try {
                                console.log("    arg" + i + " (int): " + arg.toInt32());
                            } catch(e) {}
                        } catch(e) {}
                    }

                    // Modify arguments if needed
                    // args[0] = ptr("0x1234");
                    // args[1] = Memory.allocUtf8String("modified");

                    // Context dump
                    console.log("    Context:");
                    console.log("      PC: " + this.context.pc);
                    console.log("      SP: " + this.context.sp);
                    \(platform == .iOS ? "console.log(\"      LR: \" + this.context.lr);" : "")
                },
                onLeave: function(retval) {
                    console.log("[+] \(function.displayName) returned: " + retval);

                    // Modify return value examples:
                    // retval.replace(ptr(1));           // Force true
                    // retval.replace(ptr(0));           // Force false
                    // retval.replace(this.arg0);        // Return first arg
                    // retval.replace(ptr("0x41414141")); // Custom value

                    // Conditional modification
                    // if (retval.toInt32() == 0) {
                    //     retval.replace(ptr(1));
                    //     console.log("[!] Modified return value to 1");
                    // }
                }
            });

            console.log("[*] Advanced intercept installed");
        } else {
            console.log("[-] Module not found: " + moduleName);
        }
        """
    }

    private func generateDumpScript(
        function: Function,
        moduleName: String,
        offset: UInt64,
        size: UInt64
    ) -> String {
        let offsetHex = String(format: "0x%llx", offset)
        let dumpSize = min(size, 4096) // Limit dump size

        return """
        // Frida Memory Dump Script
        // Binary: \(moduleName)
        // Function: \(function.displayName)
        // Generated by Aether Disassembler

        var moduleName = "\(moduleName)";
        var module = Process.findModuleByName(moduleName);

        if (module) {
            console.log("[*] Module: " + module.name);
            console.log("[*] Base: " + module.base);
            console.log("[*] Size: " + module.size);

            // Dump function memory
            var startAddr = module.base.add(\(offsetHex));
            var dumpSize = \(dumpSize);

            console.log("\\n[*] Dumping \(function.displayName) (" + dumpSize + " bytes) from " + startAddr);
            console.log(hexdump(startAddr, {
                offset: 0,
                length: dumpSize,
                header: true,
                ansi: true
            }));

            // Save to file (optional)
            // var file = new File("/tmp/\(moduleName)_\(function.displayName).bin", "wb");
            // file.write(startAddr.readByteArray(dumpSize));
            // file.close();
            // console.log("[*] Saved dump to /tmp/\(moduleName)_\(function.displayName).bin");

        } else {
            console.log("[-] Module not found: " + moduleName);
        }

        // Dump on function call (dynamic dump)
        /*
        Interceptor.attach(module.base.add(\(offsetHex)), {
            onEnter: function(args) {
                console.log("\\n[*] Dynamic dump at call time:");
                // Dump stack
                console.log(hexdump(this.context.sp, { length: 256 }));
                // Dump first argument if pointer
                if (args[0] && !args[0].isNull()) {
                    console.log("\\n[*] arg0 memory:");
                    console.log(hexdump(args[0], { length: 64 }));
                }
            }
        });
        */
        """
    }

    private func generateStringPatchScript(
        moduleName: String,
        platform: FridaPlatform
    ) -> String {
        return """
        // Frida String Patch Script
        // Binary: \(moduleName)
        // Platform: \(platform.rawValue)
        // Generated by Aether Disassembler

        var moduleName = "\(moduleName)";
        var module = Process.findModuleByName(moduleName);

        if (module) {
            console.log("[*] Module: " + module.name);
            console.log("[*] Base: " + module.base);
            console.log("[*] Size: " + module.size);

            // ==== CONFIGURE THESE ====
            var originalString = "ENTER_ORIGINAL_STRING";
            var newString = "ENTER_NEW_STRING";
            // ==========================

            // Convert to bytes for scanning
            var pattern = "";
            for (var i = 0; i < originalString.length; i++) {
                pattern += originalString.charCodeAt(i).toString(16) + " ";
            }
            pattern = pattern.trim();

            console.log("[*] Searching for: " + originalString);
            console.log("[*] Pattern: " + pattern);

            // Scan memory for string
            Memory.scan(module.base, module.size, pattern, {
                onMatch: function(address, size) {
                    console.log("[+] Found string at: " + address);
                    console.log("    Current value: " + address.readCString());

                    // Make memory writable
                    Memory.protect(address, size + 1, 'rwx');

                    // Write new string (must be same length or shorter)
                    if (newString.length <= originalString.length) {
                        address.writeUtf8String(newString);
                        console.log("[+] Patched string to: " + newString);
                    } else {
                        console.log("[-] New string too long, allocating new memory");
                        var newAddr = Memory.allocUtf8String(newString);
                        // Note: You'll need to patch the reference to this string
                        console.log("[*] New string at: " + newAddr);
                    }
                },
                onError: function(reason) {
                    console.log("[-] Scan error: " + reason);
                },
                onComplete: function() {
                    console.log("[*] String scan complete");
                }
            });

        } else {
            console.log("[-] Module not found: " + moduleName);
        }

        // Alternative: Patch string reference in code
        /*
        var stringRefAddr = module.base.add(0x1234); // Address of string reference
        Memory.protect(stringRefAddr, 8, 'rwx');
        var newStringAddr = Memory.allocUtf8String("new patched string");
        stringRefAddr.writePointer(newStringAddr);
        */
        """
    }

    private func generateAntiDebugScript(platform: FridaPlatform) -> String {
        return """
        // Frida Anti-Debug Bypass Script
        // Platform: \(platform.rawValue)
        // Generated by Aether Disassembler
        //
        // Bypasses common anti-debugging techniques:
        // - ptrace (PT_DENY_ATTACH)
        // - sysctl (P_TRACED flag)
        // - getppid (parent process check)
        // - task_get_exception_ports (debugger detection)

        console.log("[*] Installing anti-debug bypasses...");

        // ==== BYPASS PTRACE ====
        var ptrace = Module.findExportByName(null, "ptrace");
        if (ptrace) {
            Interceptor.attach(ptrace, {
                onEnter: function(args) {
                    this.request = args[0].toInt32();
                    console.log("[*] ptrace called with request: " + this.request);
                },
                onLeave: function(retval) {
                    if (this.request == 31) { // PT_DENY_ATTACH
                        retval.replace(0);
                        console.log("[+] Bypassed PT_DENY_ATTACH");
                    }
                }
            });
            console.log("[+] ptrace hook installed");
        } else {
            console.log("[-] ptrace not found");
        }

        // ==== BYPASS SYSCTL ====
        var sysctl = Module.findExportByName(null, "sysctl");
        if (sysctl) {
            Interceptor.attach(sysctl, {
                onEnter: function(args) {
                    this.mib = args[0];
                    this.oldp = args[2];
                },
                onLeave: function(retval) {
                    try {
                        var mib0 = this.mib.readInt();
                        var mib1 = this.mib.add(4).readInt();
                        var mib2 = this.mib.add(8).readInt();

                        // CTL_KERN = 1, KERN_PROC = 14, KERN_PROC_PID = 1
                        if (mib0 == 1 && mib1 == 14) {
                            var info = this.oldp;
                            if (info && !info.isNull()) {
                                // kp_proc.p_flag offset varies by OS version
                                // Try common offsets: 32, 16
                                var flagsOffset = \(platform == .iOS ? 16 : 32);
                                var flags = info.add(flagsOffset).readInt();

                                if (flags & 0x800) { // P_TRACED = 0x800
                                    info.add(flagsOffset).writeInt(flags & ~0x800);
                                    console.log("[+] Cleared P_TRACED flag");
                                }
                            }
                        }
                    } catch(e) {
                        // Ignore errors
                    }
                }
            });
            console.log("[+] sysctl hook installed");
        } else {
            console.log("[-] sysctl not found");
        }

        // ==== BYPASS GETPPID ====
        var getppid = Module.findExportByName(null, "getppid");
        if (getppid) {
            Interceptor.attach(getppid, {
                onLeave: function(retval) {
                    var originalPpid = retval.toInt32();
                    retval.replace(1); // Return 1 (launchd/init)
                    console.log("[+] getppid bypassed: " + originalPpid + " -> 1");
                }
            });
            console.log("[+] getppid hook installed");
        } else {
            console.log("[-] getppid not found");
        }

        // ==== BYPASS TASK_GET_EXCEPTION_PORTS ====
        var task_get_exception_ports = Module.findExportByName(null, "task_get_exception_ports");
        if (task_get_exception_ports) {
            Interceptor.attach(task_get_exception_ports, {
                onLeave: function(retval) {
                    retval.replace(0); // KERN_SUCCESS but no ports
                    console.log("[+] task_get_exception_ports bypassed");
                }
            });
            console.log("[+] task_get_exception_ports hook installed");
        }

        \(platform == .iOS ? """
        // ==== iOS SPECIFIC: BYPASS SYSCTL DEBUGGER CHECK ====
        var sysctlbyname = Module.findExportByName(null, "sysctlbyname");
        if (sysctlbyname) {
            Interceptor.attach(sysctlbyname, {
                onEnter: function(args) {
                    this.name = args[0].readCString();
                    this.oldp = args[2];
                },
                onLeave: function(retval) {
                    if (this.name && this.name.indexOf("security.mac") !== -1) {
                        // Some jailbreak detection uses these
                        console.log("[*] sysctlbyname: " + this.name);
                    }
                }
            });
            console.log("[+] sysctlbyname hook installed");
        }

        // ==== iOS: BYPASS ISATTY (Terminal detection) ====
        var isatty = Module.findExportByName(null, "isatty");
        if (isatty) {
            Interceptor.attach(isatty, {
                onLeave: function(retval) {
                    retval.replace(0);
                }
            });
            console.log("[+] isatty hook installed");
        }
        """ : "")

        console.log("[*] Anti-debug bypasses installed successfully");
        """
    }

    private func generateSingleHookBlock(functionName: String, offset: UInt64) -> String {
        let offsetHex = String(format: "0x%llx", offset)
        return """

            // Hook: \(functionName)
            hookFunction("\(functionName)", \(offsetHex));
        """
    }

    private func generateMultiHookWrapper(
        moduleName: String,
        hookCode: String,
        platform: FridaPlatform
    ) -> String {
        let platformCheck = platform == .iOS ? "if (ObjC.available) {\n" : ""
        let platformEnd = platform == .iOS ? "\n} else {\n    console.log(\"[-] Objective-C runtime not available\");\n}" : ""

        return """
        // Frida Multi-Hook Script
        // Binary: \(moduleName)
        // Platform: \(platform.rawValue)
        // Generated by Aether Disassembler

        \(platformCheck)
        var moduleName = "\(moduleName)";
        var module = Process.findModuleByName(moduleName);

        if (module) {
            var baseAddr = module.base;
            console.log("[*] Module base: " + baseAddr);

            function hookFunction(name, offset) {
                var targetAddr = baseAddr.add(offset);
                console.log("[*] Hooking " + name + " at: " + targetAddr);

                Interceptor.attach(targetAddr, {
                    onEnter: function(args) {
                        console.log("\\n[+] " + name + " called");
                        console.log("    args: " + args[0] + ", " + args[1] + ", " + args[2]);
                    },
                    onLeave: function(retval) {
                        console.log("[+] " + name + " returned: " + retval);
                    }
                });
            }
        \(hookCode)

            console.log("[*] All hooks installed");
        } else {
            console.log("[-] Module not found: " + moduleName);
        }
        \(platformEnd)
        """
    }
}
