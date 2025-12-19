import Foundation

// MARK: - Lightweight CPU Emulator

/// A lightweight emulator for trace execution and symbolic analysis
class Emulator {

    // MARK: - Types

    /// Emulator state
    struct EmulatorState {
        var registers: [String: Value]
        var memory: MemoryState
        var flags: Flags
        var pc: UInt64
        var sp: UInt64
        var instructionCount: Int
        var halted: Bool
        var haltReason: HaltReason?
    }

    /// Value that can be concrete or symbolic
    enum Value: Equatable, CustomStringConvertible {
        case concrete(UInt64)
        case symbolic(String)
        case undefined

        var description: String {
            switch self {
            case .concrete(let v): return String(format: "0x%llX", v)
            case .symbolic(let s): return "<\(s)>"
            case .undefined: return "undefined"
            }
        }

        var concreteValue: UInt64? {
            if case .concrete(let v) = self { return v }
            return nil
        }

        var isSymbolic: Bool {
            if case .symbolic = self { return true }
            return false
        }
    }

    /// CPU flags
    struct Flags {
        var zero: Bool = false
        var carry: Bool = false
        var sign: Bool = false
        var overflow: Bool = false
        var parity: Bool = false
    }

    /// Memory state
    class MemoryState {
        private var pages: [UInt64: [UInt8]]  // 4KB pages
        private var symbolicMemory: [UInt64: Value]
        private let pageSize: UInt64 = 4096

        init() {
            pages = [:]
            symbolicMemory = [:]
        }

        func read(_ address: UInt64, size: Int) -> Value {
            // Check symbolic memory first
            if let symbolic = symbolicMemory[address] {
                return symbolic
            }

            // Read concrete bytes
            var result: UInt64 = 0
            for i in 0..<size {
                let addr = address + UInt64(i)
                let pageAddr = addr / pageSize * pageSize
                let offset = Int(addr % pageSize)

                if let page = pages[pageAddr], offset < page.count {
                    result |= UInt64(page[offset]) << (i * 8)
                } else {
                    return .undefined
                }
            }

            return .concrete(result)
        }

        func write(_ address: UInt64, value: Value, size: Int) {
            if value.isSymbolic {
                symbolicMemory[address] = value
                return
            }

            guard case .concrete(let v) = value else { return }

            for i in 0..<size {
                let addr = address + UInt64(i)
                let pageAddr = addr / pageSize * pageSize
                let offset = Int(addr % pageSize)

                if pages[pageAddr] == nil {
                    pages[pageAddr] = [UInt8](repeating: 0, count: Int(pageSize))
                }

                pages[pageAddr]![offset] = UInt8((v >> (i * 8)) & 0xFF)
            }
        }

        func loadBinary(data: Data, at baseAddress: UInt64) {
            for (i, byte) in data.enumerated() {
                let addr = baseAddress + UInt64(i)
                let pageAddr = addr / pageSize * pageSize
                let offset = Int(addr % pageSize)

                if pages[pageAddr] == nil {
                    pages[pageAddr] = [UInt8](repeating: 0, count: Int(pageSize))
                }

                pages[pageAddr]![offset] = byte
            }
        }
    }

    enum HaltReason {
        case returnInstruction
        case maxInstructions
        case invalidInstruction
        case memoryFault(UInt64)
        case breakpoint
        case syscall
        case unsupportedInstruction(String)
    }

    /// Execution trace entry
    struct TraceEntry {
        let address: UInt64
        let instruction: String
        let registerChanges: [String: (before: Value, after: Value)]
        let memoryWrites: [(address: UInt64, size: Int, value: Value)]
        let flags: Flags
    }

    // MARK: - Properties

    private var state: EmulatorState
    private var architecture: Architecture
    private var breakpoints: Set<UInt64>
    private var trace: [TraceEntry]
    private var maxInstructions: Int
    private var hooks: [UInt64: (inout EmulatorState) -> Bool]

    // MARK: - Initialization

    init(architecture: Architecture) {
        self.architecture = architecture
        self.breakpoints = []
        self.trace = []
        self.maxInstructions = 10000
        self.hooks = [:]

        // Initialize state
        self.state = EmulatorState(
            registers: [:],
            memory: MemoryState(),
            flags: Flags(),
            pc: 0,
            sp: 0x7FFFFFFFE000,  // Default stack
            instructionCount: 0,
            halted: false,
            haltReason: nil
        )

        initializeRegisters()
    }

    private func initializeRegisters() {
        // Initialize all registers to undefined
        for reg in architecture.generalPurposeRegisters {
            state.registers[reg] = .undefined
        }

        // Set up stack pointer
        state.registers[architecture.stackPointerName] = .concrete(state.sp)
    }

    // MARK: - Configuration

    func setBreakpoint(at address: UInt64) {
        breakpoints.insert(address)
    }

    func removeBreakpoint(at address: UInt64) {
        breakpoints.remove(address)
    }

    func setMaxInstructions(_ max: Int) {
        maxInstructions = max
    }

    func addHook(at address: UInt64, handler: @escaping (inout EmulatorState) -> Bool) {
        hooks[address] = handler
    }

    // MARK: - Memory Setup

    func loadSection(data: Data, at address: UInt64) {
        state.memory.loadBinary(data: data, at: address)
    }

    func setRegister(_ name: String, value: UInt64) {
        state.registers[name.lowercased()] = .concrete(value)
    }

    func setSymbolicRegister(_ name: String, symbol: String) {
        state.registers[name.lowercased()] = .symbolic(symbol)
    }

    func setMemory(at address: UInt64, value: UInt64, size: Int) {
        state.memory.write(address, value: .concrete(value), size: size)
    }

    // MARK: - Execution

    /// Run emulation starting from address
    func run(from startAddress: UInt64, disassembler: DisassemblerEngine? = nil) async -> EmulationResult {
        state.pc = startAddress
        state.halted = false
        state.haltReason = nil
        state.instructionCount = 0
        trace = []

        while !state.halted && state.instructionCount < maxInstructions {
            // Check breakpoints
            if breakpoints.contains(state.pc) {
                state.halted = true
                state.haltReason = .breakpoint
                break
            }

            // Check hooks
            if let hook = hooks[state.pc] {
                if !hook(&state) {
                    break
                }
            }

            // Execute one instruction
            await step(disassembler: disassembler)
        }

        if state.instructionCount >= maxInstructions && !state.halted {
            state.halted = true
            state.haltReason = .maxInstructions
        }

        return EmulationResult(
            finalState: state,
            trace: trace,
            instructionCount: state.instructionCount,
            haltReason: state.haltReason
        )
    }

    /// Execute a single instruction
    func step(disassembler: DisassemblerEngine?) async {
        let currentPC = state.pc

        // Read instruction bytes
        var bytes: [UInt8] = []
        for i in 0..<15 {  // Max instruction length
            let val = state.memory.read(currentPC + UInt64(i), size: 1)
            if case .concrete(let b) = val {
                bytes.append(UInt8(b & 0xFF))
            } else {
                break
            }
        }

        guard !bytes.isEmpty else {
            state.halted = true
            state.haltReason = .memoryFault(currentPC)
            return
        }

        // Disassemble instruction
        let instruction: Instruction?
        if let disasm = disassembler {
            let instructions = await disasm.disassemble(
                data: Data(bytes),
                address: currentPC,
                architecture: architecture
            )
            instruction = instructions.first
        } else {
            instruction = decodeInstruction(bytes: bytes, address: currentPC)
        }

        guard let insn = instruction else {
            state.halted = true
            state.haltReason = .invalidInstruction
            return
        }

        // Record state before execution
        let beforeRegisters = state.registers

        // Execute instruction
        var memoryWrites: [(UInt64, Int, Value)] = []
        execute(instruction: insn, memoryWrites: &memoryWrites)

        // Record trace entry
        var regChanges: [String: (Value, Value)] = [:]
        for (reg, afterValue) in state.registers {
            if let beforeValue = beforeRegisters[reg], beforeValue != afterValue {
                regChanges[reg] = (beforeValue, afterValue)
            }
        }

        trace.append(TraceEntry(
            address: currentPC,
            instruction: insn.text,
            registerChanges: regChanges,
            memoryWrites: memoryWrites,
            flags: state.flags
        ))

        state.instructionCount += 1

        // Advance PC if not modified by instruction
        if state.pc == currentPC {
            state.pc += UInt64(insn.size)
        }
    }

    // MARK: - Instruction Execution

    private func execute(instruction: Instruction, memoryWrites: inout [(UInt64, Int, Value)]) {
        let mnemonic = instruction.mnemonic.lowercased()
        let operands = instruction.operands.split(separator: ",").map {
            String($0).trimmingCharacters(in: .whitespaces)
        }

        switch instruction.type {
        case .move:
            executeMov(mnemonic: mnemonic, operands: operands, memoryWrites: &memoryWrites)

        case .arithmetic:
            executeArithmetic(mnemonic: mnemonic, operands: operands)

        case .logic:
            executeLogic(mnemonic: mnemonic, operands: operands)

        case .compare:
            executeCompare(operands: operands)

        case .jump:
            executeJump(instruction: instruction, operands: operands)

        case .conditionalJump:
            executeConditionalJump(instruction: instruction, mnemonic: mnemonic)

        case .call:
            executeCall(instruction: instruction)

        case .return:
            state.halted = true
            state.haltReason = .returnInstruction

        case .push:
            executePush(operands: operands, memoryWrites: &memoryWrites)

        case .pop:
            executePop(operands: operands)

        case .load:
            executeLoad(operands: operands)

        case .store:
            executeStore(operands: operands, memoryWrites: &memoryWrites)

        case .syscall:
            state.halted = true
            state.haltReason = .syscall

        default:
            // Unknown instruction - try to continue
            break
        }
    }

    private func executeMov(mnemonic: String, operands: [String], memoryWrites: inout [(UInt64, Int, Value)]) {
        guard operands.count >= 2 else { return }

        let dest = operands[0].lowercased()
        let src = operands[1]

        let value = resolveOperand(src)
        let size = operandSize(mnemonic)

        if isMemoryOperand(dest) {
            if let addr = resolveMemoryAddress(dest) {
                state.memory.write(addr, value: value, size: size)
                memoryWrites.append((addr, size, value))
            }
        } else {
            state.registers[dest] = value
        }
    }

    private func executeArithmetic(mnemonic: String, operands: [String]) {
        guard !operands.isEmpty else { return }

        let dest = operands[0].lowercased()
        let destValue = resolveOperand(dest)

        guard case .concrete(let d) = destValue else {
            // Symbolic arithmetic
            state.registers[dest] = .symbolic("\(mnemonic)(\(operands.joined(separator: ", ")))")
            return
        }

        let srcValue: UInt64
        if operands.count >= 2 {
            if case .concrete(let s) = resolveOperand(operands[1]) {
                srcValue = s
            } else {
                state.registers[dest] = .symbolic("\(mnemonic)(\(operands.joined(separator: ", ")))")
                return
            }
        } else {
            srcValue = 1  // For inc/dec
        }

        var result: UInt64

        switch mnemonic {
        case "add":
            result = d &+ srcValue
            state.flags.carry = result < d
        case "sub", "cmp":
            result = d &- srcValue
            state.flags.carry = d < srcValue
        case "inc":
            result = d &+ 1
        case "dec":
            result = d &- 1
        case "mul", "imul":
            result = d &* srcValue
        case "div", "idiv":
            result = srcValue != 0 ? d / srcValue : 0
        case "neg":
            result = ~d &+ 1
        case "shl", "sal":
            result = d << srcValue
        case "shr":
            result = d >> srcValue
        case "sar":
            result = UInt64(bitPattern: Int64(bitPattern: d) >> Int64(srcValue))
        case "rol":
            let shift = srcValue & 63
            result = (d << shift) | (d >> (64 - shift))
        case "ror":
            let shift = srcValue & 63
            result = (d >> shift) | (d << (64 - shift))
        default:
            result = d
        }

        // Update flags
        state.flags.zero = result == 0
        state.flags.sign = (result & 0x8000000000000000) != 0

        if mnemonic != "cmp" {
            state.registers[dest] = .concrete(result)
        }
    }

    private func executeLogic(mnemonic: String, operands: [String]) {
        guard operands.count >= 2 else { return }

        let dest = operands[0].lowercased()
        guard case .concrete(let d) = resolveOperand(dest),
              case .concrete(let s) = resolveOperand(operands[1]) else {
            state.registers[dest] = .symbolic("\(mnemonic)(\(operands.joined(separator: ", ")))")
            return
        }

        var result: UInt64

        switch mnemonic {
        case "and", "test":
            result = d & s
        case "or":
            result = d | s
        case "xor":
            result = d ^ s
        case "not":
            result = ~d
        default:
            result = d
        }

        state.flags.zero = result == 0
        state.flags.sign = (result & 0x8000000000000000) != 0
        state.flags.carry = false
        state.flags.overflow = false

        if mnemonic != "test" {
            state.registers[dest] = .concrete(result)
        }
    }

    private func executeCompare(operands: [String]) {
        guard operands.count >= 2 else { return }

        guard case .concrete(let a) = resolveOperand(operands[0]),
              case .concrete(let b) = resolveOperand(operands[1]) else {
            return
        }

        let result = a &- b

        state.flags.zero = result == 0
        state.flags.sign = (result & 0x8000000000000000) != 0
        state.flags.carry = a < b
        state.flags.overflow = ((a ^ b) & (a ^ result) & 0x8000000000000000) != 0
    }

    private func executeJump(instruction: Instruction, operands: [String]) {
        if let target = instruction.branchTarget {
            state.pc = target
        } else if !operands.isEmpty {
            if case .concrete(let addr) = resolveOperand(operands[0]) {
                state.pc = addr
            }
        }
    }

    private func executeConditionalJump(instruction: Instruction, mnemonic: String) {
        let shouldJump: Bool

        switch mnemonic {
        case "je", "jz":
            shouldJump = state.flags.zero
        case "jne", "jnz":
            shouldJump = !state.flags.zero
        case "jl", "jnge":
            shouldJump = state.flags.sign != state.flags.overflow
        case "jle", "jng":
            shouldJump = state.flags.zero || (state.flags.sign != state.flags.overflow)
        case "jg", "jnle":
            shouldJump = !state.flags.zero && (state.flags.sign == state.flags.overflow)
        case "jge", "jnl":
            shouldJump = state.flags.sign == state.flags.overflow
        case "jb", "jc", "jnae":
            shouldJump = state.flags.carry
        case "jbe", "jna":
            shouldJump = state.flags.carry || state.flags.zero
        case "ja", "jnbe":
            shouldJump = !state.flags.carry && !state.flags.zero
        case "jae", "jnc", "jnb":
            shouldJump = !state.flags.carry
        case "js":
            shouldJump = state.flags.sign
        case "jns":
            shouldJump = !state.flags.sign
        case "jo":
            shouldJump = state.flags.overflow
        case "jno":
            shouldJump = !state.flags.overflow
        default:
            shouldJump = false
        }

        if shouldJump, let target = instruction.branchTarget {
            state.pc = target
        }
    }

    private func executeCall(instruction: Instruction) {
        // Push return address
        let returnAddr = state.pc + UInt64(instruction.size)
        state.sp -= 8
        state.memory.write(state.sp, value: .concrete(returnAddr), size: 8)
        state.registers[architecture.stackPointerName] = .concrete(state.sp)

        // Jump to target
        if let target = instruction.branchTarget {
            state.pc = target
        }
    }

    private func executePush(operands: [String], memoryWrites: inout [(UInt64, Int, Value)]) {
        guard !operands.isEmpty else { return }

        let value = resolveOperand(operands[0])
        state.sp -= 8
        state.memory.write(state.sp, value: value, size: 8)
        state.registers[architecture.stackPointerName] = .concrete(state.sp)
        memoryWrites.append((state.sp, 8, value))
    }

    private func executePop(operands: [String]) {
        guard !operands.isEmpty else { return }

        let dest = operands[0].lowercased()
        let value = state.memory.read(state.sp, size: 8)
        state.registers[dest] = value
        state.sp += 8
        state.registers[architecture.stackPointerName] = .concrete(state.sp)
    }

    private func executeLoad(operands: [String]) {
        guard operands.count >= 2 else { return }

        let dest = operands[0].lowercased()
        let src = operands[1]

        if let addr = resolveMemoryAddress(src) {
            let size = operandSize("")
            let value = state.memory.read(addr, size: size)
            state.registers[dest] = value
        }
    }

    private func executeStore(operands: [String], memoryWrites: inout [(UInt64, Int, Value)]) {
        guard operands.count >= 2 else { return }

        let dest = operands[0]
        let src = operands[1]

        if let addr = resolveMemoryAddress(dest) {
            let value = resolveOperand(src)
            let size = operandSize("")
            state.memory.write(addr, value: value, size: size)
            memoryWrites.append((addr, size, value))
        }
    }

    // MARK: - Helpers

    private func resolveOperand(_ operand: String) -> Value {
        let op = operand.trimmingCharacters(in: .whitespaces).lowercased()

        // Immediate value
        if op.hasPrefix("#") {
            let numStr = String(op.dropFirst())
            if let val = parseNumber(numStr) {
                return .concrete(val)
            }
        }

        if op.hasPrefix("0x") {
            if let val = UInt64(op.dropFirst(2), radix: 16) {
                return .concrete(val)
            }
        }

        if let val = UInt64(op) {
            return .concrete(val)
        }

        // Register
        if let regValue = state.registers[op] {
            return regValue
        }

        // Memory operand
        if isMemoryOperand(op) {
            if let addr = resolveMemoryAddress(op) {
                return state.memory.read(addr, size: 8)
            }
        }

        return .undefined
    }

    private func isMemoryOperand(_ operand: String) -> Bool {
        operand.contains("[")
    }

    private func resolveMemoryAddress(_ operand: String) -> UInt64? {
        var op = operand.trimmingCharacters(in: .whitespaces)

        // Remove brackets
        if op.hasPrefix("[") && op.hasSuffix("]") {
            op = String(op.dropFirst().dropLast())
        }

        // Parse base + offset
        if let plusIdx = op.firstIndex(of: "+") {
            let basePart = String(op[..<plusIdx]).trimmingCharacters(in: .whitespaces).lowercased()
            let offsetPart = String(op[op.index(after: plusIdx)...]).trimmingCharacters(in: .whitespaces)

            if let baseValue = state.registers[basePart], case .concrete(let base) = baseValue {
                let offset = parseNumber(offsetPart) ?? 0
                return base &+ offset
            }
        } else if let minusIdx = op.firstIndex(of: "-") {
            let basePart = String(op[..<minusIdx]).trimmingCharacters(in: .whitespaces).lowercased()
            let offsetPart = String(op[op.index(after: minusIdx)...]).trimmingCharacters(in: .whitespaces)

            if let baseValue = state.registers[basePart], case .concrete(let base) = baseValue {
                let offset = parseNumber(offsetPart) ?? 0
                return base &- offset
            }
        } else {
            // Just a register
            if let regValue = state.registers[op.lowercased()], case .concrete(let addr) = regValue {
                return addr
            }
        }

        return nil
    }

    private func parseNumber(_ str: String) -> UInt64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "#", with: "")

        if s.hasPrefix("0x") || s.hasPrefix("0X") {
            return UInt64(s.dropFirst(2), radix: 16)
        }

        if s.hasPrefix("-") {
            if let val = Int64(s) {
                return UInt64(bitPattern: val)
            }
        }

        return UInt64(s)
    }

    private func operandSize(_ mnemonic: String) -> Int {
        let m = mnemonic.lowercased()
        if m.hasSuffix("b") { return 1 }
        if m.hasSuffix("w") { return 2 }
        if m.hasSuffix("l") || m.hasSuffix("d") { return 4 }
        return 8
    }

    private func decodeInstruction(bytes: [UInt8], address: UInt64) -> Instruction? {
        // Basic x86-64 decoding for common instructions
        // This is a simplified decoder
        guard !bytes.isEmpty else { return nil }

        return Instruction(
            address: address,
            size: 1,
            bytes: [bytes[0]],
            mnemonic: "unknown",
            operands: "",
            architecture: architecture
        )
    }
}

// MARK: - Emulation Result

struct EmulationResult {
    let finalState: Emulator.EmulatorState
    let trace: [Emulator.TraceEntry]
    let instructionCount: Int
    let haltReason: Emulator.HaltReason?

    /// Get final value of a register
    func registerValue(_ name: String) -> Emulator.Value? {
        finalState.registers[name.lowercased()]
    }

    /// Get trace entries for a specific address
    func traceAt(address: UInt64) -> [Emulator.TraceEntry] {
        trace.filter { $0.address == address }
    }

    /// Generate trace report
    func report() -> String {
        var output = "Emulation Report\n"
        output += "================\n\n"
        output += "Instructions executed: \(instructionCount)\n"
        output += "Halt reason: \(haltReason.map { String(describing: $0) } ?? "none")\n\n"

        output += "Final Register State:\n"
        for (reg, value) in finalState.registers.sorted(by: { $0.key < $1.key }) {
            output += "  \(reg): \(value)\n"
        }

        output += "\nExecution Trace:\n"
        for entry in trace.prefix(100) {
            output += String(format: "  0x%08llX: %@", entry.address, entry.instruction)
            if !entry.registerChanges.isEmpty {
                let changes = entry.registerChanges.map { "\($0.key): \($0.value.0) -> \($0.value.1)" }
                output += " | \(changes.joined(separator: ", "))"
            }
            output += "\n"
        }

        if trace.count > 100 {
            output += "  ... and \(trace.count - 100) more instructions\n"
        }

        return output
    }
}

// MARK: - Symbolic Executor

/// Performs lightweight symbolic execution
class SymbolicExecutor {

    struct PathConstraint {
        let condition: String
        let value: Bool
        let address: UInt64
    }

    struct ExecutionPath {
        var constraints: [PathConstraint]
        var state: Emulator.EmulatorState
        var reachable: Bool
    }

    /// Explore paths through a function
    func explore(function: Function, binary: BinaryFile, maxPaths: Int = 100) -> [ExecutionPath] {
        var paths: [ExecutionPath] = []
        var worklist: [ExecutionPath] = []

        // Initialize with entry state
        let emulator = Emulator(architecture: binary.architecture)

        // Load binary into emulator
        for section in binary.sections {
            emulator.loadSection(data: section.data, at: section.address)
        }

        // Set symbolic arguments
        for (i, reg) in binary.architecture.argumentRegisters.enumerated() {
            emulator.setSymbolicRegister(reg, symbol: "arg\(i + 1)")
        }

        // Start path exploration
        // This is a simplified version - full symbolic execution would use
        // a constraint solver like Z3

        return paths
    }
}
