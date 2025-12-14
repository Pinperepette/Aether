import SwiftUI

struct DisassemblyView: View {
    @EnvironmentObject var appState: AppState
    @State private var instructions: [Instruction] = []
    @State private var branches: [BranchInfo] = []
    @State private var isLoading = false
    @State private var maxInstructions = 500  // Limit to prevent freezing
    @State private var showBranchArrows = true
    @State private var showJumpTable = false
    @State private var showConditionalJumps = false

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "chevron.left.forwardslash.chevron.right")
                    .foregroundColor(.accent)
                Text("Disassembly")
                    .font(.headline)

                Spacer()

                // Branch stats
                if !branches.isEmpty {
                    HStack(spacing: 8) {
                        Label("\(branches.filter { $0.type == .conditionalForward || $0.type == .conditionalBackward }.count)", systemImage: "arrow.triangle.branch")
                            .font(.caption)
                            .foregroundColor(.green)

                        Label("\(branches.filter { $0.type == .conditionalBackward || $0.type == .unconditionalBackward }.count)", systemImage: "arrow.counterclockwise")
                            .font(.caption)
                            .foregroundColor(.red)
                    }
                }

                // Toggle branch arrows
                Button {
                    showBranchArrows.toggle()
                } label: {
                    Image(systemName: showBranchArrows ? "arrow.triangle.branch" : "arrow.triangle.branch")
                        .foregroundColor(showBranchArrows ? .accent : .secondary)
                }
                .buttonStyle(.plain)
                .help("Toggle branch arrows")

                // Show jump table
                Button {
                    showJumpTable = true
                } label: {
                    Image(systemName: "tablecells")
                        .foregroundColor(.secondary)
                }
                .buttonStyle(.plain)
                .help("Show jump table")
                .disabled(branches.isEmpty)

                // Conditional jumps patcher
                Button {
                    showConditionalJumps = true
                } label: {
                    Image(systemName: "arrow.triangle.swap")
                        .foregroundColor(.orange)
                }
                .buttonStyle(.plain)
                .help("Patch conditional jumps")
                .disabled(instructions.isEmpty)

            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Color.sidebar)

            Divider()

            // Legend
            if showBranchArrows && !branches.isEmpty {
                BranchLegend()
                Divider()
            }

            // Content
            if appState.currentFile == nil {
                EmptyStateView(
                    icon: "doc.badge.plus",
                    title: "No Binary Loaded",
                    message: "Open a binary file or drag and drop one here"
                )
            } else if isLoading {
                ProgressView()
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else if instructions.isEmpty {
                EmptyStateView(
                    icon: "cpu",
                    title: "No Instructions",
                    message: "Select a function or section to view disassembly"
                )
            } else {
                ScrollViewReader { proxy in
                    ScrollView {
                        LazyVStack(alignment: .leading, spacing: 0) {
                            ForEach(instructions) { insn in
                                let branchInfo = branches.first { $0.sourceAddress == insn.address }
                                EnhancedInstructionRow(
                                    instruction: insn,
                                    isSelected: insn.address == appState.selectedAddress,
                                    branchInfo: branchInfo,
                                    allInstructions: instructions
                                )
                                .id(insn.address)
                                .onTapGesture {
                                    appState.selectedAddress = insn.address
                                }
                            }
                        }
                        .padding(.vertical, 4)
                    }
                    .onChange(of: appState.selectedAddress) { _, newAddress in
                        withAnimation {
                            proxy.scrollTo(newAddress, anchor: .center)
                        }
                    }
                }
            }
        }
        .background(Color.background)
        .onChange(of: appState.currentFile?.id) { _, _ in
            loadInstructions()
        }
        .onChange(of: appState.selectedFunction?.id) { _, _ in
            loadInstructions()
        }
        .onChange(of: appState.selectedSection?.id) { _, _ in
            loadInstructions()
        }
        .onAppear {
            loadInstructions()
        }
        .sheet(isPresented: $showJumpTable) {
            JumpTableView(branches: branches)
                .environmentObject(appState)
        }
        .sheet(isPresented: $showConditionalJumps) {
            ConditionalJumpsView(instructions: instructions)
                .environmentObject(appState)
        }
    }

    private func loadInstructions() {
        guard appState.currentFile != nil else {
            instructions = []
            branches = []
            return
        }

        isLoading = true

        Task {
            var result: [Instruction] = []

            if let function = appState.selectedFunction {
                result = await appState.disassembleFunction(function)
            } else if let section = appState.selectedSection, section.containsCode {
                result = await appState.disassemble(section: section)
            }

            // Limit instructions to prevent UI freeze
            if result.count > maxInstructions {
                instructions = Array(result.prefix(maxInstructions))
            } else {
                instructions = result
            }

            // Analyze branches
            branches = BranchAnalyzer.analyzeBranches(instructions: instructions)

            isLoading = false
        }
    }
}

// MARK: - Branch Legend

struct BranchLegend: View {
    var body: some View {
        HStack(spacing: 16) {
            LegendItem(color: .green, icon: "arrow.down.right", text: "Conditional (skip)")
            LegendItem(color: .red, icon: "arrow.up.left", text: "Loop")
            LegendItem(color: .blue, icon: "arrow.down", text: "Jump")
            LegendItem(color: .purple, icon: "arrow.right.circle", text: "Call")

            Spacer()

            HStack(spacing: 8) {
                ProbabilityLegendItem(color: .green, text: "Likely")
                ProbabilityLegendItem(color: .red, text: "Unlikely")
                ProbabilityLegendItem(color: .yellow, text: "50/50")
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 4)
        .background(Color.sidebar.opacity(0.5))
        .font(.caption2)
    }
}

struct LegendItem: View {
    let color: Color
    let icon: String
    let text: String

    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: icon)
                .foregroundColor(color)
                .font(.caption2)
            Text(text)
                .foregroundColor(.secondary)
        }
    }
}

struct ProbabilityLegendItem: View {
    let color: Color
    let text: String

    var body: some View {
        HStack(spacing: 2) {
            Circle()
                .fill(color)
                .frame(width: 6, height: 6)
            Text(text)
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Instruction Row

struct InstructionRow: View {
    let instruction: Instruction
    let isSelected: Bool
    @EnvironmentObject var appState: AppState
    @State private var showEditSheet = false
    @State private var showCommentSheet = false
    @State private var editBytes = ""
    @State private var commentText = ""

    var body: some View {
        HStack(spacing: 0) {
            // Address column
            Text(String(format: "%08llX", instruction.address))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.addressColor)
                .frame(width: 80, alignment: .leading)

            // Bytes column
            Text(instruction.hexString)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 120, alignment: .leading)
                .lineLimit(1)

            // Mnemonic
            Text(instruction.mnemonic)
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(mnemonicColor)
                .frame(width: 60, alignment: .leading)

            // Operands
            OperandsView(instruction: instruction)
                .frame(maxWidth: .infinity, alignment: .leading)

            // Comment (user or auto)
            if let userComment = appState.comments[instruction.address] {
                Text("; \(userComment)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.yellow)
            } else if let comment = instruction.comment {
                Text("; \(comment)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.commentColor)
            }

            // Branch target indicator
            if instruction.branchTarget != nil {
                Image(systemName: "arrow.right")
                    .font(.caption2)
                    .foregroundColor(.accent)
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 2)
        .background(isSelected ? Color.accent.opacity(0.2) : Color.clear)
        .contentShape(Rectangle())
        .contextMenu {
            // Patching
            Button("NOP this instruction") {
                appState.nopInstruction(at: instruction.address, size: instruction.size)
            }

            Button("Edit bytes...") {
                editBytes = instruction.bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
                showEditSheet = true
            }

            Divider()

            // Comments
            Button("Add comment...") {
                commentText = appState.comments[instruction.address] ?? ""
                showCommentSheet = true
            }

            if appState.comments[instruction.address] != nil {
                Button("Remove comment") {
                    appState.setComment(at: instruction.address, comment: "")
                }
            }

            Divider()

            // Bookmarks
            if appState.bookmarks.contains(where: { $0.address == instruction.address }) {
                Button("Remove bookmark") {
                    appState.removeBookmark(at: instruction.address)
                }
            } else {
                Button("Add bookmark") {
                    appState.addBookmark(at: instruction.address, name: String(format: "0x%llX", instruction.address))
                }
            }

            Divider()

            // Copy
            Button("Copy address") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(String(format: "0x%llX", instruction.address), forType: .string)
            }

            Button("Copy instruction") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(instruction.mnemonic) \(instruction.operands)", forType: .string)
            }

            Button("Copy bytes") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(instruction.hexString, forType: .string)
            }
        }
        .sheet(isPresented: $showEditSheet) {
            EditBytesSheet(
                address: instruction.address,
                originalBytes: instruction.bytes,
                bytesString: $editBytes,
                onSave: { newBytes in
                    appState.patchBytes(at: instruction.address, newBytes: newBytes, description: "Edit at \(String(format: "0x%llX", instruction.address))")
                }
            )
        }
        .sheet(isPresented: $showCommentSheet) {
            CommentSheet(
                address: instruction.address,
                commentText: $commentText,
                onSave: { comment in
                    appState.setComment(at: instruction.address, comment: comment)
                }
            )
        }
    }

    private var mnemonicColor: Color {
        switch instruction.type {
        case .call:
            return .callColor
        case .jump, .conditionalJump:
            return .jumpColor
        case .return:
            return .returnColor
        case .move:
            return .moveColor
        case .arithmetic, .logic:
            return .mathColor
        case .compare:
            return .compareColor
        case .push, .pop:
            return .stackColor
        case .load, .store:
            return .memoryColor
        case .nop:
            return .secondary
        default:
            return .primary
        }
    }
}

// MARK: - Operands View

struct OperandsView: View {
    let instruction: Instruction
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(parseOperands().enumerated()), id: \.offset) { index, operand in
                if index > 0 {
                    Text(", ")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                OperandText(operand: operand)
            }
        }
    }

    private func parseOperands() -> [Operand] {
        var operands: [Operand] = []

        let parts = instruction.operands.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }

        for part in parts {
            operands.append(classifyOperand(part))
        }

        return operands
    }

    private func classifyOperand(_ text: String) -> Operand {
        // Register
        if isRegister(text) {
            return Operand(text: text, type: .register)
        }

        // Memory reference
        if text.hasPrefix("[") && text.hasSuffix("]") {
            return Operand(text: text, type: .memory)
        }

        // Immediate/Address
        if text.hasPrefix("0x") || text.hasPrefix("#") || text.first?.isNumber == true {
            // Check if it's a branch target
            if let target = instruction.branchTarget {
                // Use cached O(1) lookups instead of O(n) searches
                if let symbol = appState.symbolsByAddress[target] {
                    return Operand(text: symbol.displayName, type: .symbol, address: target)
                }
                if let func_ = appState.functionsByAddress[target] {
                    return Operand(text: func_.displayName, type: .function, address: target)
                }
            }
            return Operand(text: text, type: .immediate)
        }

        // Symbol reference - use cached O(1) lookup
        if let symbol = appState.symbolsByName[text] {
            return Operand(text: symbol.displayName, type: .symbol, address: symbol.address)
        }

        return Operand(text: text, type: .other)
    }

    private func isRegister(_ text: String) -> Bool {
        let registers = Set([
            // x86_64
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
            "rip", "eip", "ip",
            // ARM64
            "sp", "lr", "pc", "xzr", "wzr",
        ])

        let lowerText = text.lowercased()

        if registers.contains(lowerText) {
            return true
        }

        // ARM64 numbered registers
        if lowerText.hasPrefix("x") || lowerText.hasPrefix("w") || lowerText.hasPrefix("q") ||
           lowerText.hasPrefix("d") || lowerText.hasPrefix("s") || lowerText.hasPrefix("h") ||
           lowerText.hasPrefix("b") || lowerText.hasPrefix("v") {
            let rest = lowerText.dropFirst()
            if let num = Int(rest), num >= 0 && num <= 31 {
                return true
            }
        }

        return false
    }
}

// MARK: - Operand

struct Operand {
    let text: String
    let type: OperandType
    var address: UInt64?

    enum OperandType {
        case register
        case immediate
        case memory
        case symbol
        case function
        case other
    }
}

struct OperandText: View {
    let operand: Operand
    @EnvironmentObject var appState: AppState
    @State private var isHovered = false

    var body: some View {
        Group {
            if operand.type == .symbol || operand.type == .function {
                Button {
                    if let addr = operand.address {
                        appState.goToAddress(addr)
                    }
                } label: {
                    Text(operand.text)
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(operandColor)
                        .underline(isHovered)
                }
                .buttonStyle(.plain)
                .onHover { hovering in
                    isHovered = hovering
                }
            } else {
                Text(operand.text)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(operandColor)
            }
        }
    }

    private var operandColor: Color {
        switch operand.type {
        case .register:
            return .registerColor
        case .immediate:
            return .immediateColor
        case .memory:
            return .memoryColor
        case .symbol, .function:
            return .accent
        case .other:
            return .primary
        }
    }
}

// MARK: - Empty State View

struct EmptyStateView: View {
    let icon: String
    let title: String
    let message: String

    var body: some View {
        VStack(spacing: 12) {
            Image(systemName: icon)
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text(title)
                .font(.headline)
                .foregroundColor(.primary)

            Text(message)
                .font(.caption)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding()
    }
}

// MARK: - Edit Bytes Sheet

struct EditBytesSheet: View {
    let address: UInt64
    let originalBytes: [UInt8]
    @Binding var bytesString: String
    let onSave: ([UInt8]) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var errorMessage: String?

    var body: some View {
        VStack(spacing: 16) {
            Text("Edit Bytes")
                .font(.headline)

            Text(String(format: "Address: 0x%llX", address))
                .font(.caption)
                .foregroundColor(.secondary)

            VStack(alignment: .leading, spacing: 4) {
                Text("Original:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Text(originalBytes.map { String(format: "%02X", $0) }.joined(separator: " "))
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.secondary)
            }

            VStack(alignment: .leading, spacing: 4) {
                Text("New bytes (hex, space separated):")
                    .font(.caption)
                    .foregroundColor(.secondary)

                TextField("e.g. 90 90 90", text: $bytesString)
                    .font(.system(.body, design: .monospaced))
                    .textFieldStyle(.roundedBorder)
            }

            if let error = errorMessage {
                Text(error)
                    .font(.caption)
                    .foregroundColor(.red)
            }

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.escape)

                Spacer()

                Button("Apply") {
                    applyChanges()
                }
                .keyboardShortcut(.return)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 400)
    }

    private func applyChanges() {
        let hexParts = bytesString
            .uppercased()
            .components(separatedBy: .whitespaces)
            .filter { !$0.isEmpty }

        var newBytes: [UInt8] = []

        for hex in hexParts {
            guard hex.count == 2, let byte = UInt8(hex, radix: 16) else {
                errorMessage = "Invalid hex byte: \(hex)"
                return
            }
            newBytes.append(byte)
        }

        if newBytes.isEmpty {
            errorMessage = "No bytes entered"
            return
        }

        onSave(newBytes)
        dismiss()
    }
}

// MARK: - Comment Sheet

struct CommentSheet: View {
    let address: UInt64
    @Binding var commentText: String
    let onSave: (String) -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 16) {
            Text("Add Comment")
                .font(.headline)

            Text(String(format: "Address: 0x%llX", address))
                .font(.caption)
                .foregroundColor(.secondary)

            TextField("Enter comment...", text: $commentText)
                .textFieldStyle(.roundedBorder)

            HStack {
                Button("Cancel") {
                    dismiss()
                }
                .keyboardShortcut(.escape)

                Spacer()

                Button("Save") {
                    onSave(commentText)
                    dismiss()
                }
                .keyboardShortcut(.return)
                .buttonStyle(.borderedProminent)
            }
        }
        .padding(20)
        .frame(width: 350)
    }
}
