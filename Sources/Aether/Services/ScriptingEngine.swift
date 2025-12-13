import Foundation
import JavaScriptCore

// MARK: - Scripting Engine

/// Multi-language scripting engine for automation
@MainActor
class ScriptingEngine: ObservableObject {

    enum ScriptLanguage: String, CaseIterable {
        case javascript = "JavaScript"
        case lua = "Lua"
        case python = "Python"
    }

    @Published var output: String = ""
    @Published var isRunning = false

    private var jsContext: JSContext?
    private weak var appState: AppState?

    init(appState: AppState? = nil) {
        self.appState = appState
        setupJavaScript()
    }

    // MARK: - JavaScript Setup

    private func setupJavaScript() {
        jsContext = JSContext()

        guard let context = jsContext else { return }

        // Error handling
        context.exceptionHandler = { [weak self] _, exception in
            self?.output += "Error: \(exception?.toString() ?? "Unknown error")\n"
        }

        // Logging
        let log: @convention(block) (String) -> Void = { [weak self] message in
            Task { @MainActor in
                self?.output += message + "\n"
            }
        }
        context.setObject(log, forKeyedSubscript: "print" as NSString)
        context.setObject(log, forKeyedSubscript: "console_log" as NSString)

        // Expose console object
        context.evaluateScript("""
            var console = {
                log: function() {
                    var args = Array.prototype.slice.call(arguments);
                    console_log(args.map(String).join(' '));
                }
            };
        """)

        // Expose disassembler API
        exposeDisassemblerAPI(to: context)
    }

    private func exposeDisassemblerAPI(to context: JSContext) {
        // Create Disassembler object
        context.evaluateScript("""
            var Disassembler = {};
        """)

        // Get current binary info
        let getCurrentBinary: @convention(block) () -> [String: Any]? = { [weak self] in
            guard let binary = self?.appState?.currentFile else { return nil }
            return [
                "name": binary.name,
                "format": binary.format.rawValue,
                "architecture": binary.architecture.rawValue,
                "entryPoint": String(format: "0x%llX", binary.entryPoint),
                "baseAddress": String(format: "0x%llX", binary.baseAddress),
                "fileSize": binary.fileSize
            ]
        }
        context.setObject(getCurrentBinary, forKeyedSubscript: "getCurrentBinary" as NSString)

        // Get functions
        let getFunctions: @convention(block) () -> [[String: Any]] = { [weak self] in
            guard let functions = self?.appState?.functions else { return [] }
            return functions.map { func_ in
                [
                    "name": func_.displayName,
                    "startAddress": String(format: "0x%llX", func_.startAddress),
                    "endAddress": String(format: "0x%llX", func_.endAddress),
                    "size": func_.size,
                    "isLeaf": func_.isLeaf
                ]
            }
        }
        context.setObject(getFunctions, forKeyedSubscript: "getFunctions" as NSString)

        // Get strings
        let getStrings: @convention(block) () -> [[String: Any]] = { [weak self] in
            guard let strings = self?.appState?.strings else { return [] }
            return strings.map { str in
                [
                    "address": String(format: "0x%llX", str.address),
                    "value": str.value,
                    "encoding": str.encoding.rawValue
                ]
            }
        }
        context.setObject(getStrings, forKeyedSubscript: "getStrings" as NSString)

        // Get symbols
        let getSymbols: @convention(block) () -> [[String: Any]] = { [weak self] in
            guard let symbols = self?.appState?.symbols else { return [] }
            return symbols.map { sym in
                [
                    "name": sym.displayName,
                    "address": String(format: "0x%llX", sym.address),
                    "type": sym.type.rawValue,
                    "isImport": sym.isImport,
                    "isExport": sym.isExport
                ]
            }
        }
        context.setObject(getSymbols, forKeyedSubscript: "getSymbols" as NSString)

        // Read bytes at address
        let readBytes: @convention(block) (String, Int) -> [UInt8]? = { [weak self] addressStr, count in
            guard let binary = self?.appState?.currentFile else { return nil }
            let address = UInt64(addressStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
            guard let data = binary.read(at: address, count: count) else { return nil }
            return Array(data)
        }
        context.setObject(readBytes, forKeyedSubscript: "readBytes" as NSString)

        // Read string at address
        let readString: @convention(block) (String) -> String? = { [weak self] addressStr in
            guard let binary = self?.appState?.currentFile else { return nil }
            let address = UInt64(addressStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
            return binary.readString(at: address)
        }
        context.setObject(readString, forKeyedSubscript: "readString" as NSString)

        // Navigate to address
        let goToAddress: @convention(block) (String) -> Void = { [weak self] addressStr in
            let address = UInt64(addressStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
            Task { @MainActor in
                self?.appState?.goToAddress(address)
            }
        }
        context.setObject(goToAddress, forKeyedSubscript: "goToAddress" as NSString)

        // Rename function
        let renameFunction: @convention(block) (String, String) -> Bool = { [weak self] addressStr, newName in
            let address = UInt64(addressStr.replacingOccurrences(of: "0x", with: ""), radix: 16) ?? 0
            if let index = self?.appState?.functions.firstIndex(where: { $0.startAddress == address }) {
                Task { @MainActor in
                    self?.appState?.functions[index].name = newName
                }
                return true
            }
            return false
        }
        context.setObject(renameFunction, forKeyedSubscript: "renameFunction" as NSString)

        // Set up Disassembler namespace
        context.evaluateScript("""
            Disassembler.getCurrentBinary = getCurrentBinary;
            Disassembler.getFunctions = getFunctions;
            Disassembler.getStrings = getStrings;
            Disassembler.getSymbols = getSymbols;
            Disassembler.readBytes = readBytes;
            Disassembler.readString = readString;
            Disassembler.goToAddress = goToAddress;
            Disassembler.renameFunction = renameFunction;

            // Utility functions
            Disassembler.hexToInt = function(hex) {
                return parseInt(hex.replace('0x', ''), 16);
            };

            Disassembler.intToHex = function(num) {
                return '0x' + num.toString(16).toUpperCase();
            };

            // Search functions by name pattern
            Disassembler.findFunctions = function(pattern) {
                var regex = new RegExp(pattern, 'i');
                return Disassembler.getFunctions().filter(function(f) {
                    return regex.test(f.name);
                });
            };

            // Search strings by pattern
            Disassembler.findStrings = function(pattern) {
                var regex = new RegExp(pattern, 'i');
                return Disassembler.getStrings().filter(function(s) {
                    return regex.test(s.value);
                });
            };
        """)
    }

    // MARK: - Script Execution

    func runScript(_ script: String, language: ScriptLanguage) async throws -> String {
        isRunning = true
        output = ""

        defer { isRunning = false }

        switch language {
        case .javascript:
            return await runJavaScript(script)
        case .lua:
            return runLua(script)
        case .python:
            return runPython(script)
        }
    }

    private func runJavaScript(_ script: String) async -> String {
        guard let context = jsContext else {
            return "Error: JavaScript context not initialized"
        }

        let result = context.evaluateScript(script)

        if let resultString = result?.toString(), resultString != "undefined" {
            output += resultString + "\n"
        }

        return output
    }

    private func runLua(_ script: String) -> String {
        // Lua integration would require LuaC library
        return "Lua scripting not yet implemented. Use JavaScript for now."
    }

    private func runPython(_ script: String) -> String {
        // Python integration via PythonKit or subprocess
        // For now, we'll use a subprocess approach

        let tempFile = FileManager.default.temporaryDirectory.appendingPathComponent("script.py")

        // Create Python wrapper script
        let wrapperScript = """
        import json
        import sys

        # Disassembler API stub (would be replaced with actual IPC)
        class Disassembler:
            @staticmethod
            def print(msg):
                print(msg)

        # User script
        \(script)
        """

        do {
            try wrapperScript.write(to: tempFile, atomically: true, encoding: .utf8)

            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
            process.arguments = [tempFile.path]

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = pipe

            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8) ?? ""
        } catch {
            return "Error running Python script: \(error.localizedDescription)"
        }
    }

    // MARK: - Script Library

    static let scriptExamples: [(name: String, description: String, code: String)] = [
        (
            "List Functions",
            "Print all functions in the binary",
            """
            var funcs = Disassembler.getFunctions();
            console.log("Found " + funcs.length + " functions:");
            funcs.forEach(function(f) {
                console.log("  " + f.startAddress + ": " + f.name + " (" + f.size + " bytes)");
            });
            """
        ),
        (
            "Find Strings Containing",
            "Search for strings containing a pattern",
            """
            var pattern = "password";
            var results = Disassembler.findStrings(pattern);
            console.log("Found " + results.length + " strings containing '" + pattern + "':");
            results.forEach(function(s) {
                console.log("  " + s.address + ": " + s.value);
            });
            """
        ),
        (
            "Find Crypto Functions",
            "Look for cryptographic function names",
            """
            var cryptoPatterns = ["crypt", "aes", "sha", "md5", "rsa", "encrypt", "decrypt", "hash"];
            var found = [];

            cryptoPatterns.forEach(function(pattern) {
                var matches = Disassembler.findFunctions(pattern);
                found = found.concat(matches);
            });

            console.log("Found " + found.length + " crypto-related functions:");
            found.forEach(function(f) {
                console.log("  " + f.startAddress + ": " + f.name);
            });
            """
        ),
        (
            "Export Function List",
            "Generate a CSV of all functions",
            """
            var funcs = Disassembler.getFunctions();
            console.log("Address,Name,Size,IsLeaf");
            funcs.forEach(function(f) {
                console.log(f.startAddress + "," + f.name + "," + f.size + "," + f.isLeaf);
            });
            """
        ),
        (
            "Rename Functions by Pattern",
            "Batch rename functions matching a pattern",
            """
            var funcs = Disassembler.findFunctions("^sub_");
            console.log("Found " + funcs.length + " unnamed functions");

            // Example: prefix with module name
            var prefix = "mymodule_";
            funcs.slice(0, 5).forEach(function(f, i) {
                var newName = prefix + "func_" + i;
                if (Disassembler.renameFunction(f.startAddress, newName)) {
                    console.log("Renamed " + f.startAddress + " to " + newName);
                }
            });
            """
        ),
        (
            "Analyze Binary Info",
            "Display detailed binary information",
            """
            var binary = Disassembler.getCurrentBinary();
            if (!binary) {
                console.log("No binary loaded");
            } else {
                console.log("Binary Analysis Report");
                console.log("======================");
                console.log("Name: " + binary.name);
                console.log("Format: " + binary.format);
                console.log("Architecture: " + binary.architecture);
                console.log("Entry Point: " + binary.entryPoint);
                console.log("Base Address: " + binary.baseAddress);
                console.log("File Size: " + binary.fileSize + " bytes");
                console.log("");

                var funcs = Disassembler.getFunctions();
                var strings = Disassembler.getStrings();
                var symbols = Disassembler.getSymbols();

                console.log("Statistics:");
                console.log("  Functions: " + funcs.length);
                console.log("  Strings: " + strings.length);
                console.log("  Symbols: " + symbols.length);

                var imports = symbols.filter(function(s) { return s.isImport; });
                var exports = symbols.filter(function(s) { return s.isExport; });
                console.log("  Imports: " + imports.length);
                console.log("  Exports: " + exports.length);
            }
            """
        )
    ]
}

// MARK: - Script Console View

import SwiftUI

struct ScriptConsoleView: View {
    @StateObject private var engine: ScriptingEngine
    @State private var scriptText = ""
    @State private var selectedLanguage: ScriptingEngine.ScriptLanguage = .javascript
    @State private var showExamples = false

    init(appState: AppState) {
        _engine = StateObject(wrappedValue: ScriptingEngine(appState: appState))
    }

    var body: some View {
        VStack(spacing: 0) {
            // Toolbar
            HStack {
                Picker("Language", selection: $selectedLanguage) {
                    ForEach(ScriptingEngine.ScriptLanguage.allCases, id: \.self) { lang in
                        Text(lang.rawValue).tag(lang)
                    }
                }
                .pickerStyle(.segmented)
                .frame(width: 250)

                Spacer()

                Button("Examples") {
                    showExamples = true
                }

                Button("Run") {
                    runScript()
                }
                .keyboardShortcut(.return, modifiers: .command)
                .disabled(engine.isRunning || scriptText.isEmpty)

                Button("Clear") {
                    engine.output = ""
                }
            }
            .padding(8)
            .background(Color.sidebar)

            Divider()

            // Editor and output
            HSplitView {
                // Script editor
                VStack(alignment: .leading, spacing: 0) {
                    Text("Script")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.top, 4)

                    TextEditor(text: $scriptText)
                        .font(.system(.body, design: .monospaced))
                        .scrollContentBackground(.hidden)
                        .background(Color.background)
                }
                .frame(minWidth: 300)

                // Output
                VStack(alignment: .leading, spacing: 0) {
                    Text("Output")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .padding(.horizontal, 8)
                        .padding(.top, 4)

                    ScrollView {
                        Text(engine.output)
                            .font(.system(.caption, design: .monospaced))
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .padding(8)
                            .textSelection(.enabled)
                    }
                    .background(Color.background)
                }
                .frame(minWidth: 200)
            }
        }
        .sheet(isPresented: $showExamples) {
            ScriptExamplesView(selectedScript: $scriptText, isPresented: $showExamples)
        }
    }

    private func runScript() {
        Task {
            _ = try? await engine.runScript(scriptText, language: selectedLanguage)
        }
    }
}

struct ScriptExamplesView: View {
    @Binding var selectedScript: String
    @Binding var isPresented: Bool

    var body: some View {
        VStack(spacing: 0) {
            Text("Script Examples")
                .font(.headline)
                .padding()

            List(ScriptingEngine.scriptExamples, id: \.name) { example in
                VStack(alignment: .leading, spacing: 4) {
                    Text(example.name)
                        .font(.headline)
                    Text(example.description)
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .contentShape(Rectangle())
                .onTapGesture {
                    selectedScript = example.code
                    isPresented = false
                }
            }

            Button("Cancel") {
                isPresented = false
            }
            .padding()
        }
        .frame(width: 400, height: 500)
    }
}
