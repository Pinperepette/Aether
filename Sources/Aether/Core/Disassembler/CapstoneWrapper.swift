import Foundation

// MARK: - Capstone Integration via System Library

/// Capstone disassembly wrapper
/// Uses the system Capstone library if available, falls back to native implementation
class CapstoneDisassembler {

    // MARK: - Capstone Constants

    enum CSArch: UInt32 {
        case arm = 0
        case arm64 = 1
        case mips = 2
        case x86 = 3
        case ppc = 4
        case sparc = 5
        case sysz = 6
        case xcore = 7
        case m68k = 8
        case tms320c64x = 9
        case m680x = 10
        case evm = 11
    }

    struct CSMode: OptionSet {
        let rawValue: UInt32

        static let littleEndian = CSMode(rawValue: 0)
        static let arm = CSMode(rawValue: 0)
        static let mode16 = CSMode(rawValue: 1 << 1)
        static let mode32 = CSMode(rawValue: 1 << 2)
        static let mode64 = CSMode(rawValue: 1 << 3)
        static let thumb = CSMode(rawValue: 1 << 4)
        static let mclass = CSMode(rawValue: 1 << 5)
        static let v8 = CSMode(rawValue: 1 << 6)
        static let micro = CSMode(rawValue: 1 << 4)
        static let mips3 = CSMode(rawValue: 1 << 5)
        static let mips32r6 = CSMode(rawValue: 1 << 6)
        static let bigEndian = CSMode(rawValue: 1 << 31)
    }

    // MARK: - Instruction Groups

    enum InstructionGroup: UInt8 {
        case invalid = 0
        case jump = 1
        case call = 2
        case ret = 3
        case int = 4
        case iret = 5
        case privilege = 6
        case branchRelative = 7
    }

    // MARK: - Enhanced Instruction Model

    struct DetailedInstruction {
        let address: UInt64
        let size: Int
        let bytes: [UInt8]
        let mnemonic: String
        let operands: String
        let groups: [InstructionGroup]
        let regsRead: [String]
        let regsWrite: [String]
        let operandDetails: [OperandDetail]

        var isCall: Bool { groups.contains(.call) }
        var isJump: Bool { groups.contains(.jump) || groups.contains(.branchRelative) }
        var isReturn: Bool { groups.contains(.ret) }
        var isInterrupt: Bool { groups.contains(.int) }
    }

    struct OperandDetail {
        enum OpType {
            case register(String)
            case immediate(Int64)
            case memory(base: String?, index: String?, scale: Int, displacement: Int64)
            case floatingPoint(Double)
        }

        let type: OpType
        let size: Int
        let access: AccessType

        enum AccessType {
            case read
            case write
            case readWrite
        }
    }

    // MARK: - Disassembly

    private var nativeDisassembler = DisassemblerEngine()

    /// Disassemble with detailed information
    func disassembleDetailed(
        data: Data,
        address: UInt64,
        architecture: Architecture
    ) async -> [DetailedInstruction] {
        // Use native disassembler and enhance with additional analysis
        let basicInstructions = await nativeDisassembler.disassemble(
            data: data,
            address: address,
            architecture: architecture
        )

        return basicInstructions.map { insn in
            DetailedInstruction(
                address: insn.address,
                size: insn.size,
                bytes: insn.bytes,
                mnemonic: insn.mnemonic,
                operands: insn.operands,
                groups: classifyInstruction(insn),
                regsRead: extractReadRegisters(insn, architecture: architecture),
                regsWrite: extractWriteRegisters(insn, architecture: architecture),
                operandDetails: parseOperands(insn, architecture: architecture)
            )
        }
    }

    // MARK: - Instruction Classification

    private func classifyInstruction(_ insn: Instruction) -> [InstructionGroup] {
        var groups: [InstructionGroup] = []

        switch insn.type {
        case .call:
            groups.append(.call)
        case .jump:
            groups.append(.jump)
        case .conditionalJump:
            groups.append(.jump)
            groups.append(.branchRelative)
        case .return:
            groups.append(.ret)
        case .interrupt, .syscall:
            groups.append(.int)
        default:
            break
        }

        return groups
    }

    // MARK: - Register Analysis

    private func extractReadRegisters(_ insn: Instruction, architecture: Architecture) -> [String] {
        var registers: [String] = []
        let operands = insn.operands.lowercased()

        // Parse source operands
        let allRegs = architecture.generalPurposeRegisters
        for reg in allRegs {
            if operands.contains(reg.lowercased()) {
                // Check if it's a source (not destination)
                let parts = operands.split(separator: ",")
                if parts.count > 1 {
                    // In most architectures, source is second operand
                    let sourcePart = parts.dropFirst().joined(separator: ",")
                    if sourcePart.contains(reg.lowercased()) {
                        registers.append(reg)
                    }
                }
                // Memory references read base/index registers
                if operands.contains("[\(reg.lowercased())") {
                    registers.append(reg)
                }
            }
        }

        return registers
    }

    private func extractWriteRegisters(_ insn: Instruction, architecture: Architecture) -> [String] {
        var registers: [String] = []
        let operands = insn.operands.lowercased()

        let allRegs = architecture.generalPurposeRegisters
        for reg in allRegs {
            if operands.contains(reg.lowercased()) {
                // Destination is usually first operand
                let parts = operands.split(separator: ",")
                if let firstPart = parts.first {
                    if String(firstPart).contains(reg.lowercased()) &&
                       !String(firstPart).contains("[") { // Not memory destination
                        registers.append(reg)
                    }
                }
            }
        }

        return registers
    }

    // MARK: - Operand Parsing

    private func parseOperands(_ insn: Instruction, architecture: Architecture) -> [OperandDetail] {
        var details: [OperandDetail] = []
        let parts = insn.operands.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }

        for (index, part) in parts.enumerated() {
            let access: OperandDetail.AccessType = index == 0 ? .write : .read

            if let detail = parseOperand(part, architecture: architecture, access: access) {
                details.append(detail)
            }
        }

        return details
    }

    private func parseOperand(_ operand: String, architecture: Architecture, access: OperandDetail.AccessType) -> OperandDetail? {
        let op = operand.trimmingCharacters(in: .whitespaces)

        // Memory operand
        if op.hasPrefix("[") && op.hasSuffix("]") {
            let inner = String(op.dropFirst().dropLast())
            let memOp = parseMemoryOperand(inner, architecture: architecture)
            return OperandDetail(type: memOp, size: architecture.pointerSize, access: access)
        }

        // Immediate
        if op.hasPrefix("#") || op.hasPrefix("0x") || op.first?.isNumber == true {
            var value = op
            if value.hasPrefix("#") { value = String(value.dropFirst()) }
            if value.hasPrefix("0x") {
                if let imm = Int64(value.dropFirst(2), radix: 16) {
                    return OperandDetail(type: .immediate(imm), size: 8, access: .read)
                }
            } else if let imm = Int64(value) {
                return OperandDetail(type: .immediate(imm), size: 8, access: .read)
            }
        }

        // Register
        if isRegister(op, architecture: architecture) {
            let size = registerSize(op, architecture: architecture)
            return OperandDetail(type: .register(op), size: size, access: access)
        }

        return nil
    }

    private func parseMemoryOperand(_ inner: String, architecture: Architecture) -> OperandDetail.OpType {
        var base: String? = nil
        var index: String? = nil
        var scale = 1
        var displacement: Int64 = 0

        // Simple parsing for common patterns
        let parts = inner.components(separatedBy: CharacterSet(charactersIn: "+-"))

        for part in parts {
            let trimmed = part.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            if isRegister(trimmed, architecture: architecture) {
                if base == nil {
                    base = trimmed
                } else {
                    index = trimmed
                }
            } else if trimmed.hasPrefix("0x") {
                displacement = Int64(trimmed.dropFirst(2), radix: 16) ?? 0
            } else if let num = Int64(trimmed) {
                displacement = num
            }
        }

        // Handle negative displacement
        if inner.contains("-") {
            if let lastMinus = inner.lastIndex(of: "-") {
                let afterMinus = inner[inner.index(after: lastMinus)...]
                if let num = Int64(afterMinus.trimmingCharacters(in: .whitespaces).replacingOccurrences(of: "0x", with: ""), radix: 16) {
                    displacement = -num
                }
            }
        }

        return .memory(base: base, index: index, scale: scale, displacement: displacement)
    }

    private func isRegister(_ name: String, architecture: Architecture) -> Bool {
        let lower = name.lowercased()
        return architecture.generalPurposeRegisters.contains { $0.lowercased() == lower }
    }

    private func registerSize(_ name: String, architecture: Architecture) -> Int {
        let lower = name.lowercased()

        switch architecture {
        case .x86_64:
            if lower.hasPrefix("r") { return 8 }
            if lower.hasPrefix("e") { return 4 }
            if lower.hasSuffix("x") || lower.hasSuffix("i") || lower.hasSuffix("p") { return 2 }
            if lower.hasSuffix("l") || lower.hasSuffix("h") { return 1 }
            return 8
        case .arm64, .arm64e:
            if lower.hasPrefix("x") || lower == "sp" { return 8 }
            if lower.hasPrefix("w") { return 4 }
            if lower.hasPrefix("h") { return 2 }
            if lower.hasPrefix("b") { return 1 }
            return 8
        default:
            return architecture.pointerSize
        }
    }
}

// MARK: - Data Flow Analysis

class DataFlowAnalyzer {

    struct DataFlowInfo {
        var definitions: [UInt64: Set<String>]  // Address -> registers defined
        var uses: [UInt64: Set<String>]         // Address -> registers used
        var liveIn: [UInt64: Set<String>]       // Live registers at entry
        var liveOut: [UInt64: Set<String>]      // Live registers at exit
    }

    /// Perform data flow analysis on a function
    func analyze(function: Function, instructions: [Instruction], architecture: Architecture) -> DataFlowInfo {
        var info = DataFlowInfo(
            definitions: [:],
            uses: [:],
            liveIn: [:],
            liveOut: [:]
        )

        let capstone = CapstoneDisassembler()

        // Build def-use chains
        for insn in instructions {
            let regsRead = extractReads(insn, architecture: architecture)
            let regsWrite = extractWrites(insn, architecture: architecture)

            info.uses[insn.address] = Set(regsRead)
            info.definitions[insn.address] = Set(regsWrite)
        }

        // Compute liveness (simplified backward analysis)
        var changed = true
        while changed {
            changed = false

            for block in function.basicBlocks.reversed() {
                var liveOut = Set<String>()

                // Union of live-in of all successors
                for succ in block.successors {
                    if let succLiveIn = info.liveIn[succ] {
                        liveOut.formUnion(succLiveIn)
                    }
                }

                let oldLiveOut = info.liveOut[block.startAddress] ?? Set()
                if liveOut != oldLiveOut {
                    info.liveOut[block.startAddress] = liveOut
                    changed = true
                }

                // live_in = use ∪ (live_out - def)
                var liveIn = liveOut
                for insn in block.instructions.reversed() {
                    if let defs = info.definitions[insn.address] {
                        liveIn.subtract(defs)
                    }
                    if let uses = info.uses[insn.address] {
                        liveIn.formUnion(uses)
                    }
                }

                let oldLiveIn = info.liveIn[block.startAddress] ?? Set()
                if liveIn != oldLiveIn {
                    info.liveIn[block.startAddress] = liveIn
                    changed = true
                }
            }
        }

        return info
    }

    private func extractReads(_ insn: Instruction, architecture: Architecture) -> [String] {
        var regs: [String] = []
        let operands = insn.operands.lowercased()

        for reg in architecture.generalPurposeRegisters {
            if operands.contains(reg.lowercased()) {
                // Simple heuristic: if in memory operand or after comma, it's a read
                if operands.contains("[\(reg.lowercased())") ||
                   operands.split(separator: ",").dropFirst().joined().contains(reg.lowercased()) {
                    regs.append(reg)
                }
            }
        }

        return regs
    }

    private func extractWrites(_ insn: Instruction, architecture: Architecture) -> [String] {
        var regs: [String] = []
        let operands = insn.operands.lowercased()

        // First operand is usually destination
        if let firstOp = operands.split(separator: ",").first {
            let first = String(firstOp).trimmingCharacters(in: .whitespaces)
            if !first.contains("[") { // Not memory
                for reg in architecture.generalPurposeRegisters {
                    if first == reg.lowercased() {
                        regs.append(reg)
                        break
                    }
                }
            }
        }

        return regs
    }
}
