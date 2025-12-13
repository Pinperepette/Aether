import SwiftUI
import Combine

func debug(_ message: String) {
    fputs(">>> \(message)\n", stderr)
}

@MainActor
class AppState: ObservableObject {
    // MARK: - File State
    @Published var currentFile: BinaryFile?
    @Published var isLoading = false
    @Published var loadingProgress: Double = 0
    @Published var loadingMessage = ""
    @Published var errorMessage: String?
    @Published var showError = false

    // MARK: - Navigation State
    @Published var selectedAddress: UInt64 = 0
    @Published var selectedFunction: Function?
    @Published var selectedSection: Section?

    // MARK: - UI State
    @Published var showCFG = false
    @Published var showDecompiler = true
    @Published var showHexView = true
    @Published var showGoToAddress = false
    @Published var showSearch = false
    @Published var sidebarSelection: SidebarItem = .functions

    // MARK: - Advanced Analysis UI State
    @Published var showCallGraph = false
    @Published var showCryptoDetection = false
    @Published var showDeobfuscation = false
    @Published var showTypeRecovery = false
    @Published var showIdiomRecognition = false
    @Published var showExportSheet = false
    @Published var showPseudoCode = false
    @Published var showJumpTable = false

    // MARK: - Advanced Analysis Results
    @Published var cryptoFindings: [AdvancedCryptoDetector.CryptoFinding] = []
    @Published var deobfuscationReport: DeobfuscationReportWrapper?
    @Published var recoveredTypes: [RecoveredTypeWrapper] = []
    @Published var recognizedIdioms: [IdiomRecognizer.Idiom] = []
    @Published var structuredCode: String = ""

    // MARK: - Analysis Results
    @Published var functions: [Function] = []
    @Published var strings: [StringReference] = []
    @Published var imports: [Symbol] = []
    @Published var exports: [Symbol] = []
    @Published var symbols: [Symbol] = []
    @Published var xrefs: [CrossReference] = []

    // MARK: - Lookup Caches (for O(1) access)
    var symbolsByAddress: [UInt64: Symbol] = [:]
    var symbolsByName: [String: Symbol] = [:]
    var functionsByAddress: [UInt64: Function] = [:]

    // MARK: - Disassembly Cache
    @Published var disassemblyCache: [UInt64: [Instruction]] = [:]
    @Published var decompilerOutput: String = ""

    // MARK: - Patching State
    @Published var patcher: BinaryPatcher?
    @Published var patches: [BinaryPatcher.Patch] = []
    @Published var hasUnsavedChanges = false

    // MARK: - User Annotations
    @Published var renamedFunctions: [UInt64: String] = [:]
    @Published var renamedSymbols: [UInt64: String] = [:]
    @Published var comments: [UInt64: String] = [:]
    @Published var bookmarks: [Bookmark] = []

    // MARK: - Search State
    @Published var searchResults: [SearchResult] = []
    @Published var isSearching = false

    // MARK: - Undo/Redo
    private var undoStack: [UndoAction] = []
    private var redoStack: [UndoAction] = []
    @Published var canUndo = false
    @Published var canRedo = false

    // MARK: - Services
    private let binaryLoader = BinaryLoader()
    private let disassembler = DisassemblerEngine()
    private let functionAnalyzer = FunctionAnalyzer()
    private let stringAnalyzer = StringAnalyzer()
    private let xrefAnalyzer = XRefAnalyzer()
    private let decompiler = Decompiler()

    // MARK: - File Operations

    func openFile() {
        print(">>> openFile() called!")
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false
        panel.canChooseDirectories = false
        panel.canChooseFiles = true
        panel.message = "Select a binary file to analyze"

        let result = panel.runModal()
        print(">>> Panel result: \(result == .OK ? "OK" : "Cancel")")

        if result == .OK, let url = panel.url {
            print(">>> Selected file: \(url.path)")
            Task {
                await loadFile(url: url)
            }
        }
    }

    func closeFile() {
        currentFile = nil
        selectedSection = nil
        selectedFunction = nil
        selectedAddress = 0
        functions = []
        strings = []
        decompilerOutput = ""
        errorMessage = nil

        // Clear caches
        symbolsByAddress = [:]
        symbolsByName = [:]
        functionsByAddress = [:]

        // Clear user annotations
        renamedFunctions = [:]
        renamedSymbols = [:]
        comments = [:]
        bookmarks = []

        // Clear undo/redo
        undoStack = []
        redoStack = []
    }

    func loadFile(url: URL) async {
        debug("loadFile called for: \(url.path)")
        isLoading = true
        loadingProgress = 0
        loadingMessage = "Loading file..."
        errorMessage = nil

        do {
            // Load binary
            loadingMessage = "Parsing binary format..."
            loadingProgress = 0.1
            debug("Parsing binary...")

            let binary = try await binaryLoader.load(from: url)
            debug("Binary loaded: \(binary.name)")
            debug("Format: \(binary.format), Arch: \(binary.architecture)")
            debug("Sections: \(binary.sections.count), Symbols: \(binary.symbols.count)")

            // Set the current file first
            self.currentFile = binary
            debug("currentFile set")

            // Get first code section
            self.selectedSection = binary.sections.first { $0.containsCode }
            debug("Selected section: \(selectedSection?.name ?? "none") (flags: \(String(format: "0x%X", selectedSection?.flags ?? 0)))")

            // Extract symbols
            loadingMessage = "Processing symbols..."
            loadingProgress = 0.5
            self.imports = binary.symbols.filter { $0.isImport }
            self.exports = binary.symbols.filter { $0.isExport }
            self.symbols = binary.symbols
            debug("Symbols processed: \(symbols.count)")

            // Get functions from symbols
            loadingMessage = "Extracting functions..."
            loadingProgress = 0.7
            self.functions = binary.symbols
                .filter { $0.type == .function && $0.address != 0 }
                .map { Function(name: $0.name, startAddress: $0.address, endAddress: $0.address + max($0.size, 4)) }
                .sorted { $0.startAddress < $1.startAddress }
            debug("Functions: \(functions.count)")

            // Build lookup caches for O(1) access (keep first occurrence for duplicates)
            loadingMessage = "Building lookup caches..."
            self.symbolsByAddress = symbols.reduce(into: [:]) { dict, symbol in
                if symbol.address != 0 && dict[symbol.address] == nil {
                    dict[symbol.address] = symbol
                }
            }
            self.symbolsByName = symbols.reduce(into: [:]) { dict, symbol in
                if dict[symbol.name] == nil {
                    dict[symbol.name] = symbol
                }
            }
            self.functionsByAddress = functions.reduce(into: [:]) { dict, func_ in
                if dict[func_.startAddress] == nil {
                    dict[func_.startAddress] = func_
                }
            }

            // Extract strings
            loadingMessage = "Extracting strings..."
            loadingProgress = 0.9
            self.strings = stringAnalyzer.analyze(binary: binary)
            debug("Strings: \(strings.count)")

            // Initialize patcher
            self.patcher = BinaryPatcher(binary: binary)
            self.patches = []
            self.hasUnsavedChanges = false

            // Done!
            loadingProgress = 1.0
            loadingMessage = "Ready"
            isLoading = false
            debug("Loading complete! isLoading=\(isLoading)")

        } catch {
            debug("ERROR: \(error)")
            errorMessage = error.localizedDescription
            showError = true
            loadingMessage = "Error: \(error.localizedDescription)"
            isLoading = false
        }
    }

    // MARK: - Analysis

    func analyzeAll() {
        guard currentFile != nil else { return }
        Task {
            await performAnalysis()
        }
    }

    private func performAnalysis() async {
        guard let binary = currentFile else { return }

        isLoading = true

        // Find functions
        loadingMessage = "Analyzing functions..."
        loadingProgress = 0.4
        self.functions = await functionAnalyzer.analyze(binary: binary, disassembler: disassembler)

        // Find strings
        loadingMessage = "Extracting strings..."
        loadingProgress = 0.6
        self.strings = stringAnalyzer.analyze(binary: binary)

        // Build cross-references
        loadingMessage = "Building cross-references..."
        loadingProgress = 0.8
        self.xrefs = await xrefAnalyzer.analyze(binary: binary, functions: functions, disassembler: disassembler)

        // Extract imports/exports
        loadingMessage = "Processing symbols..."
        loadingProgress = 0.9
        self.imports = binary.symbols.filter { $0.isImport }
        self.exports = binary.symbols.filter { $0.isExport }
        self.symbols = binary.symbols

        loadingProgress = 1.0
        loadingMessage = "Analysis complete"
        isLoading = false
    }

    func findFunctions() {
        guard let binary = currentFile else { return }
        Task {
            isLoading = true
            loadingMessage = "Finding functions..."
            self.functions = await functionAnalyzer.analyze(binary: binary, disassembler: disassembler)
            isLoading = false
        }
    }

    // MARK: - Advanced Analysis

    func runCryptoDetection() {
        guard let binary = currentFile else { return }
        Task {
            isLoading = true
            loadingMessage = "Detecting cryptographic patterns..."
            let detector = AdvancedCryptoDetector()
            self.cryptoFindings = detector.scan(binary: binary)
            isLoading = false
            showCryptoDetection = true
        }
    }

    func runDeobfuscation() {
        guard let binary = currentFile, let function = selectedFunction else { return }
        Task {
            isLoading = true
            loadingMessage = "Analyzing obfuscation..."
            let deobfuscator = Deobfuscator()
            let instructions = await disassembleFunction(function)

            // Build basic blocks for analysis
            var basicBlocks: [BasicBlock] = []
            if !instructions.isEmpty {
                let bb = BasicBlock(startAddress: function.startAddress, endAddress: function.endAddress, instructions: instructions)
                basicBlocks.append(bb)
            }

            var func_ = function
            func_.basicBlocks = basicBlocks
            let findings = deobfuscator.analyze(function: func_, binary: binary)
            let result = deobfuscator.deobfuscate(function: func_, binary: binary)

            self.deobfuscationReport = DeobfuscationReportWrapper.from(result, findings: findings)
            isLoading = false
            showDeobfuscation = true
        }
    }

    func runTypeRecovery() {
        guard let binary = currentFile, let function = selectedFunction else { return }
        Task {
            isLoading = true
            loadingMessage = "Recovering types..."
            let recovery = TypeRecovery()
            let instructions = await disassembleFunction(function)

            var basicBlocks: [BasicBlock] = []
            if !instructions.isEmpty {
                let bb = BasicBlock(startAddress: function.startAddress, endAddress: function.endAddress, instructions: instructions)
                basicBlocks.append(bb)
            }

            self.recoveredTypes = recovery.recoverTypes(function: function, blocks: basicBlocks, binary: binary)
            isLoading = false
            showTypeRecovery = true
        }
    }

    func runIdiomRecognition() {
        guard let function = selectedFunction else { return }
        Task {
            isLoading = true
            loadingMessage = "Recognizing code idioms..."
            let recognizer = IdiomRecognizer()
            let instructions = await disassembleFunction(function)

            var basicBlocks: [BasicBlock] = []
            if !instructions.isEmpty {
                let bb = BasicBlock(startAddress: function.startAddress, endAddress: function.endAddress, instructions: instructions)
                basicBlocks.append(bb)
            }

            var func_ = function
            func_.basicBlocks = basicBlocks
            self.recognizedIdioms = recognizer.recognize(function: func_)
            isLoading = false
            showIdiomRecognition = true
        }
    }

    func generateStructuredCode() {
        guard let binary = currentFile, let function = selectedFunction else { return }
        Task {
            isLoading = true
            loadingMessage = "Generating structured code..."
            let instructions = await disassembleFunction(function)

            guard !instructions.isEmpty else {
                self.structuredCode = "// No instructions found for function"
                isLoading = false
                showPseudoCode = true
                return
            }

            // Build proper basic blocks by splitting at control flow instructions
            let basicBlocks = buildBasicBlocks(from: instructions, function: function)

            var func_ = function
            func_.basicBlocks = basicBlocks

            // Generate pseudo-code directly from instructions
            self.structuredCode = generatePseudoCodeFromInstructions(instructions, function: func_, binary: binary)
            isLoading = false
            showPseudoCode = true
        }
    }

    private func buildBasicBlocks(from instructions: [Instruction], function: Function) -> [BasicBlock] {
        guard !instructions.isEmpty else { return [] }

        var blocks: [BasicBlock] = []
        var currentBlockStart = 0
        var leaders: Set<UInt64> = [instructions[0].address]

        // Find all leaders (start of basic blocks)
        for (index, insn) in instructions.enumerated() {
            // After a branch/jump, the next instruction is a leader
            if insn.type == .jump || insn.type == .conditionalJump || insn.type == .call || insn.type == .return {
                if index + 1 < instructions.count {
                    leaders.insert(instructions[index + 1].address)
                }
                // Target of jump is also a leader
                if let target = insn.branchTarget {
                    leaders.insert(target)
                }
            }
        }

        // Create basic blocks
        let sortedLeaders = leaders.sorted()
        for (i, leaderAddr) in sortedLeaders.enumerated() {
            guard let startIdx = instructions.firstIndex(where: { $0.address == leaderAddr }) else { continue }

            let endIdx: Int
            if i + 1 < sortedLeaders.count {
                let nextLeader = sortedLeaders[i + 1]
                endIdx = instructions.firstIndex(where: { $0.address >= nextLeader }) ?? instructions.count
            } else {
                endIdx = instructions.count
            }

            if startIdx < endIdx {
                let blockInsns = Array(instructions[startIdx..<endIdx])
                let endAddr = blockInsns.last.map { $0.address + UInt64($0.size) } ?? leaderAddr
                let bb = BasicBlock(startAddress: leaderAddr, endAddress: endAddr, instructions: blockInsns)
                blocks.append(bb)
            }
        }

        return blocks
    }

    private func generatePseudoCodeFromInstructions(_ instructions: [Instruction], function: Function, binary: BinaryFile) -> String {
        var output = "// Function: \(function.displayName)\n"
        output += "// Address: 0x\(String(format: "%llX", function.startAddress))\n"
        output += "// Size: \(function.size) bytes\n\n"

        // Generate function signature
        output += "void \(function.displayName.replacingOccurrences(of: "-", with: "_").replacingOccurrences(of: "[", with: "").replacingOccurrences(of: "]", with: "").replacingOccurrences(of: " ", with: "_"))() {\n"

        var indent = "    "
        var pendingElse = false
        var loopStack: [UInt64] = []

        for (index, insn) in instructions.enumerated() {
            let addr = String(format: "0x%llX", insn.address)

            switch insn.type {
            case .conditionalJump:
                // Generate if statement
                let condition = extractCondition(from: insn)
                if let target = insn.branchTarget, target < insn.address {
                    // Backward jump = loop
                    output += "\(indent)// Loop back to \(String(format: "0x%llX", target))\n"
                    output += "\(indent)} // end loop\n"
                } else {
                    output += "\(indent)if (\(condition)) {\n"
                    indent += "    "
                    pendingElse = true
                }

            case .jump:
                if let target = insn.branchTarget {
                    if target < insn.address {
                        // Backward jump = loop
                        output += "\(indent)// Continue loop\n"
                    } else if pendingElse {
                        indent = String(indent.dropLast(4))
                        output += "\(indent)} else {\n"
                        indent += "    "
                        pendingElse = false
                    } else {
                        output += "\(indent)goto loc_\(String(format: "%llX", target));\n"
                    }
                }

            case .call:
                let target = insn.operands
                output += "\(indent)\(target)();  // call\n"

            case .return:
                if indent.count > 4 {
                    indent = String(indent.dropLast(4))
                    output += "\(indent)}\n"
                }
                output += "\(indent)return;\n"

            case .move:
                let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count >= 2 {
                    output += "\(indent)\(parts[0]) = \(parts[1]);\n"
                }

            case .arithmetic:
                output += "\(indent)// \(insn.mnemonic) \(insn.operands)\n"
                let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                if parts.count >= 2 {
                    let op = arithmeticOp(insn.mnemonic)
                    output += "\(indent)\(parts[0]) \(op)= \(parts[1]);\n"
                }

            case .compare:
                // Just a comment, the condition will be used by the next branch
                output += "\(indent)// compare \(insn.operands)\n"

            case .push:
                output += "\(indent)push(\(insn.operands));\n"

            case .pop:
                output += "\(indent)\(insn.operands) = pop();\n"

            default:
                // Generic instruction as comment
                if !insn.mnemonic.isEmpty {
                    output += "\(indent)// \(insn.mnemonic) \(insn.operands)\n"
                }
            }
        }

        // Close any remaining blocks
        while indent.count > 4 {
            indent = String(indent.dropLast(4))
            output += "\(indent)}\n"
        }

        output += "}\n"
        return output
    }

    private func extractCondition(from insn: Instruction) -> String {
        let mnemonic = insn.mnemonic.lowercased()

        switch mnemonic {
        case "je", "jz": return "zero_flag"
        case "jne", "jnz": return "!zero_flag"
        case "jg", "jnle": return "greater"
        case "jge", "jnl": return "greater_or_equal"
        case "jl", "jnge": return "less"
        case "jle", "jng": return "less_or_equal"
        case "ja", "jnbe": return "above"  // unsigned
        case "jae", "jnb", "jnc": return "above_or_equal"
        case "jb", "jnae", "jc": return "below"
        case "jbe", "jna": return "below_or_equal"
        case "js": return "sign_flag"
        case "jns": return "!sign_flag"
        case "jo": return "overflow_flag"
        case "jno": return "!overflow_flag"
        default: return "condition"
        }
    }

    private func arithmeticOp(_ mnemonic: String) -> String {
        switch mnemonic.lowercased() {
        case "add": return "+"
        case "sub": return "-"
        case "imul", "mul": return "*"
        case "idiv", "div": return "/"
        case "and": return "&"
        case "or": return "|"
        case "xor": return "^"
        case "shl", "sal": return "<<"
        case "shr", "sar": return ">>"
        default: return "?"
        }
    }

    func exportTo(format: ExportManager.ExportFormat, url: URL) {
        guard let binary = currentFile else { return }
        Task {
            isLoading = true
            loadingMessage = "Exporting to \(format.rawValue)..."
            let exporter = ExportManager()
            do {
                try exporter.export(binary: binary, functions: functions, symbols: symbols, to: url, format: format)
                loadingMessage = "Export complete!"
            } catch {
                errorMessage = "Export failed: \(error.localizedDescription)"
                showError = true
            }
            isLoading = false
        }
    }

    // MARK: - Navigation

    func goToAddress(_ address: UInt64) {
        selectedAddress = address

        // Find function containing this address
        if let func_ = functions.first(where: { $0.contains(address: address) }) {
            selectedFunction = func_
        }
    }

    func selectFunction(_ function: Function) {
        selectedFunction = function
        selectedAddress = function.startAddress

        // Decompile if decompiler view is visible
        if showDecompiler {
            decompileCurrentFunction()
        }
    }

    // MARK: - Decompilation

    func decompileCurrentFunction() {
        guard let function = selectedFunction,
              let binary = currentFile else { return }

        Task {
            let instructions = await disassembleFunction(function)
            decompilerOutput = decompiler.decompile(
                function: function,
                instructions: instructions,
                binary: binary
            )
        }
    }

    // MARK: - Patching

    func patchBytes(at address: UInt64, newBytes: [UInt8], description: String) {
        guard let patcher = patcher else { return }

        do {
            let patch = try patcher.createPatch(at: address, newBytes: newBytes, description: description)
            try patcher.applyPatch(patch)
            patches = patcher.getAllPatches()
            hasUnsavedChanges = true

            // Clear cache for affected section
            disassemblyCache.removeAll()
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }

    func nopInstruction(at address: UInt64, size: Int) {
        guard let patcher = patcher else { return }

        do {
            let patch = try patcher.createNOPPatch(at: address, size: size, description: "NOP at \(String(format: "0x%llX", address))")
            try patcher.applyPatch(patch)
            patches = patcher.getAllPatches()
            hasUnsavedChanges = true
            disassemblyCache.removeAll()
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }

    func revertPatch(_ patch: BinaryPatcher.Patch) {
        guard let patcher = patcher else { return }

        do {
            try patcher.revertPatch(patch)
            patches = patcher.getAllPatches()
            hasUnsavedChanges = patches.contains { $0.isApplied }
            disassemblyCache.removeAll()
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
    }

    func saveFile() {
        guard let binary = currentFile else { return }
        saveFile(to: binary.url)
    }

    func saveFileAs() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = currentFile?.name ?? "patched_binary"
        panel.message = "Save patched binary"

        if panel.runModal() == .OK, let url = panel.url {
            saveFile(to: url)
        }
    }

    func saveFile(to url: URL) {
        guard let patcher = patcher else { return }

        do {
            try patcher.save(to: url)
            hasUnsavedChanges = false
            loadingMessage = "Saved to \(url.lastPathComponent)"
        } catch {
            errorMessage = "Failed to save: \(error.localizedDescription)"
            showError = true
        }
    }

    // MARK: - Disassembly

    func disassemble(section: Section) async -> [Instruction] {
        guard let binary = currentFile else { return [] }

        if let cached = disassemblyCache[section.address] {
            return cached
        }

        let instructions = await disassembler.disassemble(
            data: section.data,
            address: section.address,
            architecture: binary.architecture
        )

        disassemblyCache[section.address] = instructions
        return instructions
    }

    func disassembleFunction(_ function: Function) async -> [Instruction] {
        guard let binary = currentFile,
              let section = binary.sections.first(where: { $0.contains(address: function.startAddress) }) else {
            return []
        }

        let offset = Int(function.startAddress - section.address)
        let size = Int(function.size)

        guard offset >= 0, offset + size <= section.data.count else {
            return []
        }

        let data = section.data[offset..<(offset + size)]

        return await disassembler.disassemble(
            data: Data(data),
            address: function.startAddress,
            architecture: binary.architecture
        )
    }

    func disassembleRange(start: UInt64, end: UInt64) async -> [Instruction] {
        guard let binary = currentFile,
              let section = binary.sections.first(where: { $0.contains(address: start) }) else {
            return []
        }

        let offset = Int(start - section.address)
        let size = Int(end - start)

        guard offset >= 0, offset + size <= section.data.count else {
            return []
        }

        let data = section.data[offset..<(offset + size)]

        return await disassembler.disassemble(
            data: Data(data),
            address: start,
            architecture: binary.architecture
        )
    }

    // MARK: - Rename Functions/Symbols

    func renameFunction(at address: UInt64, to newName: String) {
        let oldName = renamedFunctions[address]
        pushUndo(.renameFunction(address: address, oldName: oldName, newName: newName))
        renamedFunctions[address] = newName.isEmpty ? nil : newName
        hasUnsavedChanges = true
    }

    func renameSymbol(at address: UInt64, to newName: String) {
        let oldName = renamedSymbols[address]
        pushUndo(.renameSymbol(address: address, oldName: oldName, newName: newName))
        renamedSymbols[address] = newName.isEmpty ? nil : newName
        hasUnsavedChanges = true
    }

    func getDisplayName(forFunctionAt address: UInt64) -> String {
        if let renamed = renamedFunctions[address] {
            return renamed
        }
        if let func_ = functionsByAddress[address] {
            return func_.name
        }
        return String(format: "sub_%llX", address)
    }

    func getDisplayName(forSymbolAt address: UInt64) -> String {
        if let renamed = renamedSymbols[address] {
            return renamed
        }
        if let symbol = symbolsByAddress[address] {
            return symbol.displayName
        }
        return String(format: "loc_%llX", address)
    }

    // MARK: - Comments

    func setComment(at address: UInt64, comment: String) {
        let oldComment = comments[address]
        pushUndo(.setComment(address: address, oldComment: oldComment, newComment: comment))
        comments[address] = comment.isEmpty ? nil : comment
        hasUnsavedChanges = true
    }

    func getComment(at address: UInt64) -> String? {
        return comments[address]
    }

    // MARK: - Bookmarks

    func addBookmark(at address: UInt64, name: String, description: String = "") {
        let bookmark = Bookmark(address: address, name: name, description: description)
        bookmarks.append(bookmark)
        pushUndo(.addBookmark(bookmark: bookmark))
        hasUnsavedChanges = true
    }

    func removeBookmark(at address: UInt64) {
        if let index = bookmarks.firstIndex(where: { $0.address == address }) {
            let bookmark = bookmarks[index]
            bookmarks.remove(at: index)
            pushUndo(.removeBookmark(bookmark: bookmark))
            hasUnsavedChanges = true
        }
    }

    // MARK: - Search

    func search(query: String, type: SearchType) async {
        guard let binary = currentFile else { return }

        isSearching = true
        searchResults = []

        switch type {
        case .all:
            await searchAll(query: query, binary: binary)
        case .functions:
            searchResults = searchFunctions(query: query)
        case .strings:
            searchResults = searchStrings(query: query)
        case .symbols:
            searchResults = searchSymbols(query: query)
        case .bytes:
            searchResults = await searchBytes(query: query, binary: binary)
        case .address:
            if let address = parseAddress(query) {
                searchResults = [SearchResult(name: String(format: "0x%llX", address), address: address, type: .address)]
            }
        }

        isSearching = false
    }

    private func searchAll(query: String, binary: BinaryFile) async {
        var results: [SearchResult] = []

        // Search functions
        results.append(contentsOf: searchFunctions(query: query))

        // Search strings
        results.append(contentsOf: searchStrings(query: query))

        // Search symbols
        results.append(contentsOf: searchSymbols(query: query))

        // Check if it's an address
        if let address = parseAddress(query) {
            results.insert(SearchResult(name: String(format: "0x%llX", address), address: address, type: .address), at: 0)
        }

        searchResults = results
    }

    private func searchFunctions(query: String) -> [SearchResult] {
        let lowercaseQuery = query.lowercased()
        return functions.filter {
            $0.displayName.lowercased().contains(lowercaseQuery) ||
            getDisplayName(forFunctionAt: $0.startAddress).lowercased().contains(lowercaseQuery)
        }.map {
            SearchResult(name: getDisplayName(forFunctionAt: $0.startAddress), address: $0.startAddress, type: .function)
        }
    }

    private func searchStrings(query: String) -> [SearchResult] {
        let lowercaseQuery = query.lowercased()
        return strings.filter {
            $0.value.lowercased().contains(lowercaseQuery)
        }.map {
            SearchResult(name: $0.value, address: $0.address, type: .string)
        }
    }

    private func searchSymbols(query: String) -> [SearchResult] {
        let lowercaseQuery = query.lowercased()
        return symbols.filter {
            $0.displayName.lowercased().contains(lowercaseQuery)
        }.map {
            SearchResult(name: $0.displayName, address: $0.address, type: .symbol)
        }
    }

    private func searchBytes(query: String, binary: BinaryFile) async -> [SearchResult] {
        // Parse hex bytes
        let hexParts = query.uppercased().components(separatedBy: .whitespaces).filter { !$0.isEmpty }
        var bytes: [UInt8] = []

        for hex in hexParts {
            if let byte = UInt8(hex, radix: 16) {
                bytes.append(byte)
            }
        }

        guard !bytes.isEmpty else { return [] }

        var results: [SearchResult] = []

        for section in binary.sections {
            let data = section.data
            let bytesData = Data(bytes)

            var searchRange = data.startIndex..<data.endIndex
            while let range = data.range(of: bytesData, options: [], in: searchRange) {
                let offset = data.distance(from: data.startIndex, to: range.lowerBound)
                let address = section.address + UInt64(offset)
                results.append(SearchResult(
                    name: bytes.map { String(format: "%02X", $0) }.joined(separator: " "),
                    address: address,
                    type: .bytes
                ))
                searchRange = range.upperBound..<data.endIndex

                if results.count >= 100 { break } // Limit results
            }
            if results.count >= 100 { break }
        }

        return results
    }

    private func parseAddress(_ string: String) -> UInt64? {
        let clean = string.trimmingCharacters(in: .whitespaces)
        if clean.hasPrefix("0x") || clean.hasPrefix("0X") {
            return UInt64(clean.dropFirst(2), radix: 16)
        }
        return UInt64(clean, radix: 16)
    }

    // MARK: - Cross References

    func getXRefsTo(address: UInt64) -> [CrossReference] {
        return xrefs.filter { $0.toAddress == address }
    }

    func getXRefsFrom(address: UInt64) -> [CrossReference] {
        return xrefs.filter { $0.fromAddress == address }
    }

    // MARK: - Undo/Redo

    private func pushUndo(_ action: UndoAction) {
        undoStack.append(action)
        redoStack.removeAll()
        canUndo = true
        canRedo = false
    }

    func undo() {
        guard let action = undoStack.popLast() else { return }

        switch action {
        case .renameFunction(let address, let oldName, _):
            renamedFunctions[address] = oldName
        case .renameSymbol(let address, let oldName, _):
            renamedSymbols[address] = oldName
        case .setComment(let address, let oldComment, _):
            comments[address] = oldComment
        case .addBookmark(let bookmark):
            bookmarks.removeAll { $0.id == bookmark.id }
        case .removeBookmark(let bookmark):
            bookmarks.append(bookmark)
        case .patchBytes(let address, let oldBytes, _):
            // Would need patcher integration
            break
        }

        redoStack.append(action)
        canUndo = !undoStack.isEmpty
        canRedo = true
    }

    func redo() {
        guard let action = redoStack.popLast() else { return }

        switch action {
        case .renameFunction(let address, _, let newName):
            renamedFunctions[address] = newName
        case .renameSymbol(let address, _, let newName):
            renamedSymbols[address] = newName
        case .setComment(let address, _, let newComment):
            comments[address] = newComment
        case .addBookmark(let bookmark):
            bookmarks.append(bookmark)
        case .removeBookmark(let bookmark):
            bookmarks.removeAll { $0.id == bookmark.id }
        case .patchBytes(let address, _, let newBytes):
            // Would need patcher integration
            break
        }

        undoStack.append(action)
        canUndo = true
        canRedo = !redoStack.isEmpty
    }

    // MARK: - Project Save/Load

    func saveProject(to url: URL) throws {
        let project = ProjectData(
            binaryPath: currentFile?.url.path ?? "",
            renamedFunctions: renamedFunctions,
            renamedSymbols: renamedSymbols,
            comments: comments,
            bookmarks: bookmarks,
            patches: patches.map { PatchData(address: $0.address, bytes: $0.newBytes, description: $0.description) }
        )

        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        let data = try encoder.encode(project)
        try data.write(to: url)
        hasUnsavedChanges = false
    }

    func loadProject(from url: URL) async throws {
        let data = try Data(contentsOf: url)
        let decoder = JSONDecoder()
        let project = try decoder.decode(ProjectData.self, from: data)

        // Load the binary first
        if !project.binaryPath.isEmpty {
            let binaryURL = URL(fileURLWithPath: project.binaryPath)
            if FileManager.default.fileExists(atPath: binaryURL.path) {
                await loadFile(url: binaryURL)
            }
        }

        // Restore annotations
        renamedFunctions = project.renamedFunctions
        renamedSymbols = project.renamedSymbols
        comments = project.comments
        bookmarks = project.bookmarks

        // Re-apply patches
        for patchData in project.patches {
            patchBytes(at: patchData.address, newBytes: patchData.bytes, description: patchData.description)
        }

        hasUnsavedChanges = false
    }

    func openProject() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.json]
        panel.message = "Open Aether Project"

        if panel.runModal() == .OK, let url = panel.url {
            Task {
                try? await loadProject(from: url)
            }
        }
    }

    func saveProjectAs() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.json]
        panel.nameFieldStringValue = "\(currentFile?.name ?? "project").dproj"
        panel.message = "Save Aether Project"

        if panel.runModal() == .OK, let url = panel.url {
            try? saveProject(to: url)
        }
    }
}

// MARK: - Supporting Types

// Using Bookmark from Project.swift

struct SearchResult: Identifiable {
    let id = UUID()
    let name: String
    let address: UInt64
    let type: SearchResultType
}

enum SearchResultType {
    case function
    case string
    case symbol
    case bytes
    case address
}

enum SearchType: String, CaseIterable {
    case all = "All"
    case functions = "Functions"
    case strings = "Strings"
    case symbols = "Symbols"
    case bytes = "Bytes"
    case address = "Address"
}

enum UndoAction {
    case renameFunction(address: UInt64, oldName: String?, newName: String?)
    case renameSymbol(address: UInt64, oldName: String?, newName: String?)
    case setComment(address: UInt64, oldComment: String?, newComment: String?)
    case addBookmark(bookmark: Bookmark)
    case removeBookmark(bookmark: Bookmark)
    case patchBytes(address: UInt64, oldBytes: [UInt8], newBytes: [UInt8])
}

struct ProjectData: Codable {
    let binaryPath: String
    let renamedFunctions: [UInt64: String]
    let renamedSymbols: [UInt64: String]
    let comments: [UInt64: String]
    let bookmarks: [Bookmark]
    let patches: [PatchData]
}

struct PatchData: Codable {
    let address: UInt64
    let bytes: [UInt8]
    let description: String
}

// MARK: - Sidebar Item

enum SidebarItem: String, CaseIterable, Identifiable {
    case functions = "Functions"
    case strings = "Strings"
    case imports = "Imports"
    case exports = "Exports"
    case symbols = "Symbols"
    case sections = "Sections"

    var id: String { rawValue }

    var icon: String {
        switch self {
        case .functions: return "function"
        case .strings: return "text.quote"
        case .imports: return "arrow.down.square"
        case .exports: return "arrow.up.square"
        case .symbols: return "tag"
        case .sections: return "square.stack.3d.up"
        }
    }
}
