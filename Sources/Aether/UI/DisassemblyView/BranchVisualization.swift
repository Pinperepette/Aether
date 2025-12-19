import SwiftUI

// MARK: - Branch Info

struct BranchInfo: Identifiable {
    let id = UUID()
    let sourceAddress: UInt64
    let targetAddress: UInt64
    let type: BranchType
    let mnemonic: String
    let distance: Int64
    let probability: BranchProbability

    enum BranchType {
        case conditionalForward   // je, jne, etc. going forward (skip code)
        case conditionalBackward  // je, jne, etc. going backward (loop)
        case unconditionalForward // jmp forward
        case unconditionalBackward // jmp backward (loop)
        case call
        case `return`

        var color: Color {
            switch self {
            case .conditionalForward: return .green
            case .conditionalBackward: return .red
            case .unconditionalForward: return .blue
            case .unconditionalBackward: return .orange
            case .call: return .purple
            case .return: return .gray
            }
        }

        var icon: String {
            switch self {
            case .conditionalForward: return "arrow.down.right"
            case .conditionalBackward: return "arrow.up.left"
            case .unconditionalForward: return "arrow.down"
            case .unconditionalBackward: return "arrow.up"
            case .call: return "arrow.right.circle"
            case .return: return "arrow.left.circle"
            }
        }

        var description: String {
            switch self {
            case .conditionalForward: return "Conditional (skip)"
            case .conditionalBackward: return "Conditional (loop)"
            case .unconditionalForward: return "Unconditional (skip)"
            case .unconditionalBackward: return "Unconditional (loop)"
            case .call: return "Function call"
            case .return: return "Return"
            }
        }
    }

    enum BranchProbability {
        case likely
        case unlikely
        case equal
        case unknown

        var description: String {
            switch self {
            case .likely: return "Likely taken"
            case .unlikely: return "Unlikely taken"
            case .equal: return "50/50"
            case .unknown: return "Unknown"
            }
        }

        var color: Color {
            switch self {
            case .likely: return .green
            case .unlikely: return .red
            case .equal: return .yellow
            case .unknown: return .gray
            }
        }
    }
}

// MARK: - Branch Analyzer

class BranchAnalyzer {
    static func analyzeBranches(instructions: [Instruction]) -> [BranchInfo] {
        var branches: [BranchInfo] = []

        for insn in instructions {
            guard insn.isControlFlow else { continue }

            let type = determineBranchType(insn)
            let probability = estimateProbability(insn, type: type)
            let distance = Int64(insn.branchTarget ?? 0) - Int64(insn.address)

            branches.append(BranchInfo(
                sourceAddress: insn.address,
                targetAddress: insn.branchTarget ?? 0,
                type: type,
                mnemonic: insn.mnemonic,
                distance: distance,
                probability: probability
            ))
        }

        return branches
    }

    private static func determineBranchType(_ insn: Instruction) -> BranchInfo.BranchType {
        switch insn.type {
        case .call:
            return .call
        case .return:
            return .return
        case .conditionalJump:
            if let target = insn.branchTarget, target < insn.address {
                return .conditionalBackward
            }
            return .conditionalForward
        case .jump:
            if let target = insn.branchTarget, target < insn.address {
                return .unconditionalBackward
            }
            return .unconditionalForward
        default:
            return .unconditionalForward
        }
    }

    private static func estimateProbability(_ insn: Instruction, type: BranchInfo.BranchType) -> BranchInfo.BranchProbability {
        let mnemonic = insn.mnemonic.lowercased()

        // Loop back edges are usually taken (loop continues)
        if type == .conditionalBackward {
            return .likely
        }

        // Error checking patterns - usually not taken
        if mnemonic == "je" || mnemonic == "jz" {
            // Often used for error checks: if (ptr == NULL) goto error
            return .unlikely
        }

        // Bounds checking - usually not taken
        if mnemonic == "jae" || mnemonic == "jb" || mnemonic == "ja" || mnemonic == "jbe" {
            return .unlikely
        }

        // Exit conditions in loops - usually not taken until end
        if type == .conditionalForward {
            return .unlikely
        }

        return .unknown
    }
}

// MARK: - Branch Arrow View

struct BranchArrowColumn: View {
    let instructions: [Instruction]
    let branches: [BranchInfo]
    let visibleRange: Range<Int>

    private let columnWidth: CGFloat = 60
    private let rowHeight: CGFloat = 18

    var body: some View {
        Canvas { context, size in
            let addressToY = buildAddressMap()

            for branch in branches {
                guard branch.type != .call && branch.type != .return else { continue }
                guard let sourceY = addressToY[branch.sourceAddress],
                      let targetY = addressToY[branch.targetAddress] else { continue }

                drawBranchArrow(
                    context: context,
                    from: sourceY,
                    to: targetY,
                    color: branch.type.color,
                    isBackward: branch.targetAddress < branch.sourceAddress
                )
            }
        }
        .frame(width: columnWidth)
    }

    private func buildAddressMap() -> [UInt64: CGFloat] {
        var map: [UInt64: CGFloat] = [:]
        for (index, insn) in instructions.enumerated() {
            map[insn.address] = CGFloat(index) * rowHeight + rowHeight / 2
        }
        return map
    }

    private func drawBranchArrow(context: GraphicsContext, from sourceY: CGFloat, to targetY: CGFloat, color: Color, isBackward: Bool) {
        let xOffset: CGFloat = isBackward ? 10 : 30
        let arrowSize: CGFloat = 4

        var path = Path()

        // Start point (source)
        path.move(to: CGPoint(x: columnWidth - 5, y: sourceY))

        // Horizontal line to the side
        path.addLine(to: CGPoint(x: xOffset, y: sourceY))

        // Vertical line
        path.addLine(to: CGPoint(x: xOffset, y: targetY))

        // Horizontal line to target
        path.addLine(to: CGPoint(x: columnWidth - 5, y: targetY))

        context.stroke(path, with: .color(color.opacity(0.7)), lineWidth: 1)

        // Arrow head at target
        var arrowPath = Path()
        arrowPath.move(to: CGPoint(x: columnWidth - 5, y: targetY))
        arrowPath.addLine(to: CGPoint(x: columnWidth - 5 - arrowSize, y: targetY - arrowSize))
        arrowPath.addLine(to: CGPoint(x: columnWidth - 5 - arrowSize, y: targetY + arrowSize))
        arrowPath.closeSubpath()

        context.fill(arrowPath, with: .color(color))
    }
}

// MARK: - Jump Table View

struct JumpTableView: View {
    @EnvironmentObject var appState: AppState
    let branches: [BranchInfo]
    @Environment(\.dismiss) var dismiss
    @State private var sortOrder: SortOrder = .address
    @State private var filterType: FilterType = .all
    @State private var searchText: String = ""

    enum SortOrder: String, CaseIterable {
        case address = "Address"
        case distance = "Distance"
        case type = "Type"
    }

    enum FilterType: String, CaseIterable {
        case all = "All"
        case conditional = "Conditional"
        case unconditional = "Unconditional"
        case loops = "Loops"
        case calls = "Calls"
    }

    var filteredBranches: [BranchInfo] {
        var result = branches

        // Filter by type
        switch filterType {
        case .all:
            break
        case .conditional:
            result = result.filter { $0.type == .conditionalForward || $0.type == .conditionalBackward }
        case .unconditional:
            result = result.filter { $0.type == .unconditionalForward || $0.type == .unconditionalBackward }
        case .loops:
            result = result.filter { $0.type == .conditionalBackward || $0.type == .unconditionalBackward }
        case .calls:
            result = result.filter { $0.type == .call }
        }

        // Filter by search
        if !searchText.isEmpty {
            result = result.filter {
                $0.mnemonic.lowercased().contains(searchText.lowercased()) ||
                String(format: "%llX", $0.sourceAddress).lowercased().contains(searchText.lowercased())
            }
        }

        // Sort
        switch sortOrder {
        case .address:
            result.sort { $0.sourceAddress < $1.sourceAddress }
        case .distance:
            result.sort { abs($0.distance) > abs($1.distance) }
        case .type:
            result.sort { $0.type.description < $1.type.description }
        }

        return result
    }

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "arrow.triangle.branch")
                    .foregroundColor(.accent)
                Text("Jump Table")
                    .font(.headline)

                Spacer()

                Text("\(filteredBranches.count) branches")
                    .font(.caption)
                    .foregroundColor(.secondary)

                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            // Filters
            HStack {
                // Search
                HStack {
                    Image(systemName: "magnifyingglass")
                        .foregroundColor(.secondary)
                    TextField("Search...", text: $searchText)
                        .textFieldStyle(.plain)
                }
                .padding(6)
                .background(Color.background)
                .cornerRadius(6)
                .frame(width: 150)

                Picker("Filter", selection: $filterType) {
                    ForEach(FilterType.allCases, id: \.self) { type in
                        Text(type.rawValue).tag(type)
                    }
                }
                .pickerStyle(.segmented)

                Spacer()

                Picker("Sort", selection: $sortOrder) {
                    ForEach(SortOrder.allCases, id: \.self) { order in
                        Text(order.rawValue).tag(order)
                    }
                }
                .frame(width: 120)
            }
            .padding(.horizontal)
            .padding(.vertical, 8)

            Divider()

            // Table
            List(filteredBranches) { branch in
                JumpTableRow(branch: branch)
                    .contentShape(Rectangle())
                    .onTapGesture {
                        appState.goToAddress(branch.sourceAddress)
                    }
            }
            .listStyle(.plain)
        }
        .frame(width: 700, height: 500)
    }
}

struct JumpTableRow: View {
    let branch: BranchInfo

    var body: some View {
        HStack(spacing: 12) {
            // Type icon
            Image(systemName: branch.type.icon)
                .foregroundColor(branch.type.color)
                .frame(width: 20)

            // Source address
            VStack(alignment: .leading, spacing: 2) {
                Text(String(format: "0x%08llX", branch.sourceAddress))
                    .font(.system(.caption, design: .monospaced))
                Text(branch.mnemonic)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .frame(width: 100, alignment: .leading)

            // Arrow
            Image(systemName: branch.targetAddress > branch.sourceAddress ? "arrow.down" : "arrow.up")
                .foregroundColor(.secondary)
                .font(.caption2)

            // Target address
            Text(String(format: "0x%08llX", branch.targetAddress))
                .font(.system(.caption, design: .monospaced))
                .frame(width: 100, alignment: .leading)

            // Distance
            Text(formatDistance(branch.distance))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(branch.distance > 0 ? .green : .red)
                .frame(width: 80, alignment: .trailing)

            // Type
            Text(branch.type.description)
                .font(.caption)
                .foregroundColor(.secondary)
                .frame(width: 120, alignment: .leading)

            // Probability
            HStack(spacing: 4) {
                Circle()
                    .fill(branch.probability.color)
                    .frame(width: 8, height: 8)
                Text(branch.probability.description)
                    .font(.caption2)
                    .foregroundColor(.secondary)
            }
            .frame(width: 100, alignment: .leading)
        }
        .padding(.vertical, 4)
    }

    private func formatDistance(_ distance: Int64) -> String {
        if distance >= 0 {
            return "+\(distance)"
        }
        return "\(distance)"
    }
}

// MARK: - Branch Tooltip

struct BranchTooltip: View {
    let branch: BranchInfo
    let targetInstructions: [Instruction]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            // Header
            HStack {
                Image(systemName: branch.type.icon)
                    .foregroundColor(branch.type.color)
                Text(branch.type.description)
                    .font(.headline)
            }

            Divider()

            // Info
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 4) {
                GridRow {
                    Text("From:")
                        .foregroundColor(.secondary)
                    Text(String(format: "0x%llX", branch.sourceAddress))
                        .font(.system(.body, design: .monospaced))
                }
                GridRow {
                    Text("To:")
                        .foregroundColor(.secondary)
                    Text(String(format: "0x%llX", branch.targetAddress))
                        .font(.system(.body, design: .monospaced))
                }
                GridRow {
                    Text("Distance:")
                        .foregroundColor(.secondary)
                    Text("\(branch.distance) bytes")
                }
                GridRow {
                    Text("Probability:")
                        .foregroundColor(.secondary)
                    HStack {
                        Circle()
                            .fill(branch.probability.color)
                            .frame(width: 8, height: 8)
                        Text(branch.probability.description)
                    }
                }
            }

            if !targetInstructions.isEmpty {
                Divider()

                Text("Target Code:")
                    .font(.caption)
                    .foregroundColor(.secondary)

                VStack(alignment: .leading, spacing: 2) {
                    ForEach(targetInstructions.prefix(5)) { insn in
                        HStack {
                            Text(String(format: "%08llX", insn.address))
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.secondary)
                            Text(insn.mnemonic)
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.accent)
                            Text(insn.operands)
                                .font(.system(.caption, design: .monospaced))
                        }
                    }
                    if targetInstructions.count > 5 {
                        Text("...")
                            .foregroundColor(.secondary)
                    }
                }
                .padding(8)
                .background(Color.black.opacity(0.3))
                .cornerRadius(4)
            }
        }
        .padding()
        .background(Color.sidebar)
        .cornerRadius(8)
        .shadow(radius: 5)
    }
}

// MARK: - Enhanced Instruction Row with Branch Info

struct EnhancedInstructionRow: View {
    let instruction: Instruction
    let isSelected: Bool
    let branchInfo: BranchInfo?
    let allInstructions: [Instruction]
    @EnvironmentObject var appState: AppState
    @State private var showTooltip = false
    @State private var showEditSheet = false
    @State private var showCommentSheet = false
    @State private var editBytes = ""
    @State private var commentText = ""

    var body: some View {
        HStack(spacing: 0) {
            // Branch indicator
            if let branch = branchInfo {
                BranchIndicator(branch: branch)
                    .frame(width: 24)
                    .onHover { hovering in
                        showTooltip = hovering
                    }
                    .popover(isPresented: $showTooltip) {
                        BranchTooltip(
                            branch: branch,
                            targetInstructions: getTargetInstructions(branch)
                        )
                    }
            } else {
                Color.clear.frame(width: 24)
            }

            // Address column
            Text(String(format: "%08llX", instruction.address))
                .font(.system(.caption, design: .monospaced))
                .foregroundColor(.addressColor)
                .frame(width: 80, alignment: .leading)

            // Bytes column
            Text(instruction.hexString)
                .font(.system(.caption2, design: .monospaced))
                .foregroundColor(.secondary)
                .frame(width: 100, alignment: .leading)
                .lineLimit(1)

            // Mnemonic with enhanced coloring
            Text(instruction.mnemonic)
                .font(.system(.caption, design: .monospaced))
                .fontWeight(instruction.isControlFlow ? .bold : .regular)
                .foregroundColor(enhancedMnemonicColor)
                .frame(width: 60, alignment: .leading)

            // Operands
            EnhancedOperandsView(instruction: instruction, branchInfo: branchInfo)
                .frame(maxWidth: .infinity, alignment: .leading)

            // Branch probability badge
            if let branch = branchInfo, instruction.type == .conditionalJump {
                ProbabilityBadge(probability: branch.probability)
                    .padding(.horizontal, 4)
            }

            // Comment
            if let userComment = appState.comments[instruction.address] {
                Text("; \(userComment)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.yellow)
            } else if let comment = instruction.comment {
                Text("; \(comment)")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.commentColor)
            }
        }
        .padding(.horizontal, 8)
        .padding(.vertical, 2)
        .background(rowBackground)
        .contentShape(Rectangle())
        .contextMenu {
            if let branch = branchInfo {
                Button("Go to target (0x\(String(format: "%llX", branch.targetAddress)))") {
                    appState.goToAddress(branch.targetAddress)
                }
                Divider()
            }

            Button("Copy address") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString(String(format: "0x%llX", instruction.address), forType: .string)
            }

            Button("Copy instruction") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("\(instruction.mnemonic) \(instruction.operands)", forType: .string)
            }
        }
    }

    private var rowBackground: Color {
        if isSelected {
            return Color.accent.opacity(0.2)
        }
        if let branch = branchInfo {
            switch branch.type {
            case .conditionalBackward, .unconditionalBackward:
                return Color.red.opacity(0.05)
            default:
                return Color.clear
            }
        }
        return Color.clear
    }

    private var enhancedMnemonicColor: Color {
        if let branch = branchInfo {
            return branch.type.color
        }

        switch instruction.type {
        case .call: return .purple
        case .jump: return .blue
        case .conditionalJump: return .green
        case .return: return .gray
        case .move: return .moveColor
        case .arithmetic, .logic: return .mathColor
        case .compare: return .compareColor
        case .push, .pop: return .stackColor
        default: return .primary
        }
    }

    private func getTargetInstructions(_ branch: BranchInfo) -> [Instruction] {
        guard let startIdx = allInstructions.firstIndex(where: { $0.address == branch.targetAddress }) else {
            return []
        }
        let endIdx = min(startIdx + 5, allInstructions.count)
        return Array(allInstructions[startIdx..<endIdx])
    }
}

// MARK: - Branch Indicator

struct BranchIndicator: View {
    let branch: BranchInfo

    var body: some View {
        ZStack {
            Circle()
                .fill(branch.type.color.opacity(0.2))
                .frame(width: 18, height: 18)

            Image(systemName: branch.type.icon)
                .font(.system(size: 10))
                .foregroundColor(branch.type.color)
        }
    }
}

// MARK: - Probability Badge

struct ProbabilityBadge: View {
    let probability: BranchInfo.BranchProbability

    var body: some View {
        HStack(spacing: 2) {
            Circle()
                .fill(probability.color)
                .frame(width: 6, height: 6)

            Text(shortDescription)
                .font(.system(size: 9))
                .foregroundColor(.secondary)
        }
        .padding(.horizontal, 4)
        .padding(.vertical, 2)
        .background(probability.color.opacity(0.1))
        .cornerRadius(4)
    }

    private var shortDescription: String {
        switch probability {
        case .likely: return "L"
        case .unlikely: return "U"
        case .equal: return "="
        case .unknown: return "?"
        }
    }
}

// MARK: - Enhanced Operands View

struct EnhancedOperandsView: View {
    let instruction: Instruction
    let branchInfo: BranchInfo?
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 0) {
            ForEach(Array(parseOperands().enumerated()), id: \.offset) { index, operand in
                if index > 0 {
                    Text(", ")
                        .font(.system(.caption, design: .monospaced))
                        .foregroundColor(.secondary)
                }

                EnhancedOperandText(operand: operand, branchInfo: branchInfo)
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
        if isRegister(text) {
            return Operand(text: text, type: .register)
        }
        if text.hasPrefix("[") && text.hasSuffix("]") {
            return Operand(text: text, type: .memory)
        }
        if text.hasPrefix("0x") || text.hasPrefix("#") || text.first?.isNumber == true {
            if let target = instruction.branchTarget {
                if let symbol = appState.symbolsByAddress[target] {
                    return Operand(text: symbol.displayName, type: .symbol, address: target)
                }
                if let func_ = appState.functionsByAddress[target] {
                    return Operand(text: func_.displayName, type: .function, address: target)
                }
            }
            return Operand(text: text, type: .immediate)
        }
        if let symbol = appState.symbolsByName[text] {
            return Operand(text: symbol.displayName, type: .symbol, address: symbol.address)
        }
        return Operand(text: text, type: .other)
    }

    private func isRegister(_ text: String) -> Bool {
        let registers = Set([
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
            "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
            "rip", "eip", "ip", "sp", "lr", "pc", "xzr", "wzr",
        ])

        let lower = text.lowercased()
        if registers.contains(lower) { return true }

        if lower.hasPrefix("x") || lower.hasPrefix("w") || lower.hasPrefix("q") ||
           lower.hasPrefix("d") || lower.hasPrefix("s") || lower.hasPrefix("h") ||
           lower.hasPrefix("b") || lower.hasPrefix("v") {
            if let num = Int(lower.dropFirst()), num >= 0 && num <= 31 {
                return true
            }
        }
        return false
    }
}

struct EnhancedOperandText: View {
    let operand: Operand
    let branchInfo: BranchInfo?
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
                .onHover { isHovered = $0 }
            } else if operand.type == .immediate, let branch = branchInfo {
                Button {
                    appState.goToAddress(branch.targetAddress)
                } label: {
                    HStack(spacing: 2) {
                        Text(operand.text)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(branch.type.color)
                        Image(systemName: branch.type.icon)
                            .font(.system(size: 8))
                            .foregroundColor(branch.type.color.opacity(0.7))
                    }
                    .underline(isHovered)
                }
                .buttonStyle(.plain)
                .onHover { isHovered = $0 }
            } else {
                Text(operand.text)
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(operandColor)
            }
        }
    }

    private var operandColor: Color {
        switch operand.type {
        case .register: return .registerColor
        case .immediate: return .immediateColor
        case .memory: return .memoryColor
        case .symbol, .function: return .accent
        case .other: return .primary
        }
    }
}
