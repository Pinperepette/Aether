import Foundation

// MARK: - Data Flow Analysis

/// Performs data flow analysis on functions to track value propagation,
/// def-use chains, and enable optimizations like constant propagation
class AdvancedDataFlowAnalyzer {

    // MARK: - Types

    /// Represents a value definition
    struct Definition: Hashable {
        let address: UInt64           // Where the definition occurs
        let register: String          // Which register/variable is defined
        let value: AbstractValue      // The abstract value
        let instruction: Instruction?

        func hash(into hasher: inout Hasher) {
            hasher.combine(address)
            hasher.combine(register)
        }

        static func == (lhs: Definition, rhs: Definition) -> Bool {
            lhs.address == rhs.address && lhs.register == rhs.register
        }
    }

    /// Represents a use of a value
    struct Use: Hashable {
        let address: UInt64           // Where the use occurs
        let register: String          // Which register/variable is used
        let definitions: Set<UInt64>  // Addresses of reaching definitions
    }

    /// Abstract value for constant propagation
    enum AbstractValue: Hashable {
        case constant(Int64)          // Known constant value
        case symbolic(String)         // Symbolic value (e.g., "arg1")
        case memory(base: String, offset: Int64)  // Memory reference
        case top                      // Unknown value
        case bottom                   // Undefined/uninitialized

        var isConstant: Bool {
            if case .constant = self { return true }
            return false
        }

        var constantValue: Int64? {
            if case .constant(let v) = self { return v }
            return nil
        }
    }

    /// Def-Use chain for a register
    struct DefUseChain {
        let register: String
        var definitions: [Definition] = []
        var uses: [Use] = []

        /// Get all definitions that reach a specific use
        func reachingDefinitions(for use: Use) -> [Definition] {
            definitions.filter { use.definitions.contains($0.address) }
        }
    }

    /// Analysis result for a function
    struct DataFlowResult {
        let function: Function
        var defUseChains: [String: DefUseChain] = [:]
        var reachingDefinitions: [UInt64: Set<Definition>] = [:]
        var liveVariables: [UInt64: Set<String>] = [:]
        var constantValues: [UInt64: [String: AbstractValue]] = [:]

        /// Get the value of a register at a specific address
        func getValue(register: String, at address: UInt64) -> AbstractValue {
            constantValues[address]?[register] ?? .top
        }

        /// Check if a register has a constant value at an address
        func isConstant(register: String, at address: UInt64) -> Bool {
            getValue(register: register, at: address).isConstant
        }
    }

    // MARK: - Analysis

    /// Perform complete data flow analysis on a function
    func analyze(function: Function, binary: BinaryFile) -> DataFlowResult {
        var result = DataFlowResult(function: function)

        // Step 1: Build def-use chains
        buildDefUseChains(function: function, result: &result, architecture: binary.architecture)

        // Step 2: Compute reaching definitions
        computeReachingDefinitions(function: function, result: &result)

        // Step 3: Perform constant propagation
        performConstantPropagation(function: function, result: &result, architecture: binary.architecture)

        // Step 4: Compute live variables
        computeLiveVariables(function: function, result: &result)

        return result
    }

    // MARK: - Def-Use Chain Building

    private func buildDefUseChains(function: Function, result: inout DataFlowResult, architecture: Architecture) {
        let allInstructions = function.basicBlocks.flatMap { $0.instructions }

        for insn in allInstructions {
            // Get defined and used registers
            let (defs, uses) = getDefsAndUses(instruction: insn, architecture: architecture)

            // Record definitions
            for (reg, value) in defs {
                let definition = Definition(
                    address: insn.address,
                    register: reg,
                    value: value,
                    instruction: insn
                )

                if result.defUseChains[reg] == nil {
                    result.defUseChains[reg] = DefUseChain(register: reg)
                }
                result.defUseChains[reg]?.definitions.append(definition)
            }

            // Record uses
            for reg in uses {
                let use = Use(
                    address: insn.address,
                    register: reg,
                    definitions: []  // Will be filled in by reaching definitions
                )

                if result.defUseChains[reg] == nil {
                    result.defUseChains[reg] = DefUseChain(register: reg)
                }
                result.defUseChains[reg]?.uses.append(use)
            }
        }
    }

    /// Extract defined and used registers from an instruction
    private func getDefsAndUses(instruction: Instruction, architecture: Architecture) -> (defs: [(String, AbstractValue)], uses: [String]) {
        var defs: [(String, AbstractValue)] = []
        var uses: [String] = []

        let operands = instruction.operands.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }

        switch instruction.type {
        case .move:
            // mov dest, src
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))
                let src = String(operands[1]).trimmingCharacters(in: .whitespaces)

                if isRegister(dest) {
                    let value = parseValue(src)
                    defs.append((dest, value))
                }

                if isRegister(src) {
                    uses.append(normalizeRegister(src))
                }
            }

        case .arithmetic:
            // add/sub/etc dest, src or dest, src1, src2
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))

                if isRegister(dest) {
                    defs.append((dest, .top))  // Result depends on operation
                    uses.append(dest)  // Often dest is also a source
                }

                for i in 1..<operands.count {
                    let op = normalizeRegister(String(operands[i]))
                    if isRegister(op) {
                        uses.append(op)
                    }
                }
            }

        case .load:
            // ldr dest, [src] or mov dest, [src]
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))
                if isRegister(dest) {
                    defs.append((dest, .top))  // Memory value unknown
                }

                // Extract base register from memory operand
                let memOp = String(operands[1])
                if let baseReg = extractBaseRegister(memOp) {
                    uses.append(normalizeRegister(baseReg))
                }
            }

        case .store:
            // str src, [dest]
            if operands.count >= 2 {
                let src = normalizeRegister(String(operands[0]))
                if isRegister(src) {
                    uses.append(src)
                }

                let memOp = String(operands[1])
                if let baseReg = extractBaseRegister(memOp) {
                    uses.append(normalizeRegister(baseReg))
                }
            }

        case .compare:
            // cmp op1, op2
            for operand in operands {
                let reg = normalizeRegister(String(operand))
                if isRegister(reg) {
                    uses.append(reg)
                }
            }

        case .call:
            // Calls clobber certain registers based on calling convention
            let clobberedRegs = getClobberedRegisters(architecture: architecture)
            for reg in clobberedRegs {
                defs.append((reg, .top))
            }

            // Arguments are used
            for reg in architecture.argumentRegisters.prefix(6) {
                uses.append(reg)
            }

        case .return:
            // Return value register is used
            uses.append(architecture.returnValueRegister)

        case .push:
            if let reg = operands.first {
                let r = normalizeRegister(String(reg))
                if isRegister(r) {
                    uses.append(r)
                }
            }

        case .pop:
            if let reg = operands.first {
                let r = normalizeRegister(String(reg))
                if isRegister(r) {
                    defs.append((r, .top))
                }
            }

        default:
            break
        }

        return (defs, uses)
    }

    // MARK: - Reaching Definitions

    private func computeReachingDefinitions(function: Function, result: inout DataFlowResult) {
        guard !function.basicBlocks.isEmpty else { return }

        // Initialize IN and OUT sets for each block
        var blockIn: [UInt64: Set<Definition>] = [:]
        var blockOut: [UInt64: Set<Definition>] = [:]
        var blockGen: [UInt64: Set<Definition>] = [:]
        var blockKill: [UInt64: Set<Definition>] = [:]

        // Compute GEN and KILL for each block
        for block in function.basicBlocks {
            var gen = Set<Definition>()
            var kill = Set<Definition>()

            for insn in block.instructions {
                // Get all definitions from def-use chains that occur at this instruction
                for (_, chain) in result.defUseChains {
                    for def in chain.definitions where def.address == insn.address {
                        // This definition kills all previous definitions of the same register
                        for otherDef in chain.definitions where otherDef.address != insn.address {
                            kill.insert(otherDef)
                        }
                        gen.insert(def)
                    }
                }
            }

            blockGen[block.startAddress] = gen
            blockKill[block.startAddress] = kill
            blockIn[block.startAddress] = []
            blockOut[block.startAddress] = gen
        }

        // Iterative data flow analysis
        var changed = true
        while changed {
            changed = false

            for block in function.basicBlocks {
                // IN[B] = union of OUT[P] for all predecessors P
                var newIn = Set<Definition>()
                for predAddr in block.predecessors {
                    if let predOut = blockOut[predAddr] {
                        newIn.formUnion(predOut)
                    }
                }

                // OUT[B] = GEN[B] union (IN[B] - KILL[B])
                let gen = blockGen[block.startAddress] ?? []
                let kill = blockKill[block.startAddress] ?? []
                let newOut = gen.union(newIn.subtracting(kill))

                if newOut != blockOut[block.startAddress] {
                    changed = true
                    blockOut[block.startAddress] = newOut
                }
                blockIn[block.startAddress] = newIn
            }
        }

        // Store reaching definitions for each instruction
        for block in function.basicBlocks {
            var reaching = blockIn[block.startAddress] ?? []

            for insn in block.instructions {
                result.reachingDefinitions[insn.address] = reaching

                // Update reaching definitions after this instruction
                for (_, chain) in result.defUseChains {
                    for def in chain.definitions where def.address == insn.address {
                        // Remove killed definitions
                        reaching = reaching.filter { $0.register != def.register }
                        // Add new definition
                        reaching.insert(def)
                    }
                }
            }
        }
    }

    // MARK: - Constant Propagation

    private func performConstantPropagation(function: Function, result: inout DataFlowResult, architecture: Architecture) {
        // Initialize argument registers with symbolic values
        var initialValues: [String: AbstractValue] = [:]
        for (i, reg) in architecture.argumentRegisters.enumerated() {
            initialValues[reg] = .symbolic("arg\(i + 1)")
        }

        // Process blocks in order
        for block in function.basicBlocks {
            var currentValues = initialValues

            // Get values from reaching definitions at block entry
            if let reaching = result.reachingDefinitions[block.startAddress] {
                for def in reaching {
                    if case .constant = def.value {
                        currentValues[def.register] = def.value
                    }
                }
            }

            for insn in block.instructions {
                // Store current values for this instruction
                result.constantValues[insn.address] = currentValues

                // Update values based on instruction
                updateValues(instruction: insn, values: &currentValues, architecture: architecture)
            }

            // Propagate to initial values for next iteration
            initialValues.merge(currentValues) { _, new in new }
        }
    }

    private func updateValues(instruction: Instruction, values: inout [String: AbstractValue], architecture: Architecture) {
        let operands = instruction.operands.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }

        switch instruction.type {
        case .move:
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))
                let src = String(operands[1]).trimmingCharacters(in: .whitespaces)

                if isRegister(dest) {
                    if let srcVal = values[normalizeRegister(src)] {
                        values[dest] = srcVal
                    } else if let constVal = parseConstant(src) {
                        values[dest] = .constant(constVal)
                    } else {
                        values[dest] = .top
                    }
                }
            }

        case .arithmetic:
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))

                // Try to compute constant result
                if let result = evaluateArithmetic(instruction: instruction, values: values) {
                    values[dest] = .constant(result)
                } else {
                    values[dest] = .top
                }
            }

        case .call:
            // Calls clobber return value and some registers
            let clobbered = getClobberedRegisters(architecture: architecture)
            for reg in clobbered {
                values[reg] = .top
            }

        case .load:
            if operands.count >= 2 {
                let dest = normalizeRegister(String(operands[0]))
                if isRegister(dest) {
                    values[dest] = .top  // Memory loads are unknown
                }
            }

        default:
            break
        }
    }

    private func evaluateArithmetic(instruction: Instruction, values: [String: AbstractValue]) -> Int64? {
        let operands = instruction.operands.split(separator: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }

        guard operands.count >= 2 else { return nil }

        let destReg = normalizeRegister(String(operands[0]))

        // Get operand values
        let op1Value: Int64?
        let op2Value: Int64?

        if operands.count == 2 {
            // dest = dest op src (e.g., add rax, 5)
            op1Value = values[destReg]?.constantValue
            op2Value = parseConstant(String(operands[1])) ?? values[normalizeRegister(String(operands[1]))]?.constantValue
        } else if operands.count >= 3 {
            // dest = src1 op src2 (e.g., add rax, rbx, 5)
            op1Value = parseConstant(String(operands[1])) ?? values[normalizeRegister(String(operands[1]))]?.constantValue
            op2Value = parseConstant(String(operands[2])) ?? values[normalizeRegister(String(operands[2]))]?.constantValue
        } else {
            return nil
        }

        guard let v1 = op1Value, let v2 = op2Value else { return nil }

        switch instruction.mnemonic.lowercased() {
        case "add":
            return v1 &+ v2
        case "sub":
            return v1 &- v2
        case "mul", "imul":
            return v1 &* v2
        case "and":
            return v1 & v2
        case "or":
            return v1 | v2
        case "xor":
            return v1 ^ v2
        case "shl", "sal":
            return v1 << v2
        case "shr":
            return Int64(bitPattern: UInt64(bitPattern: v1) >> UInt64(v2))
        case "sar":
            return v1 >> v2
        default:
            return nil
        }
    }

    // MARK: - Live Variables

    private func computeLiveVariables(function: Function, result: inout DataFlowResult) {
        guard !function.basicBlocks.isEmpty else { return }

        // Backward data flow analysis
        var blockIn: [UInt64: Set<String>] = [:]
        var blockOut: [UInt64: Set<String>] = [:]

        // Initialize
        for block in function.basicBlocks {
            blockIn[block.startAddress] = []
            blockOut[block.startAddress] = []
        }

        var changed = true
        while changed {
            changed = false

            // Process blocks in reverse order
            for block in function.basicBlocks.reversed() {
                // OUT[B] = union of IN[S] for all successors S
                var newOut = Set<String>()
                for succAddr in block.successors {
                    if let succIn = blockIn[succAddr] {
                        newOut.formUnion(succIn)
                    }
                }

                // IN[B] = USE[B] union (OUT[B] - DEF[B])
                var use = Set<String>()
                var def = Set<String>()

                for insn in block.instructions {
                    for (_, chain) in result.defUseChains {
                        for u in chain.uses where u.address == insn.address {
                            if !def.contains(u.register) {
                                use.insert(u.register)
                            }
                        }
                        for d in chain.definitions where d.address == insn.address {
                            def.insert(d.register)
                        }
                    }
                }

                let newIn = use.union(newOut.subtracting(def))

                if newIn != blockIn[block.startAddress] {
                    changed = true
                    blockIn[block.startAddress] = newIn
                }
                blockOut[block.startAddress] = newOut
            }
        }

        // Store live variables for each instruction
        for block in function.basicBlocks {
            var live = blockOut[block.startAddress] ?? []

            for insn in block.instructions.reversed() {
                result.liveVariables[insn.address] = live

                // Update live variables
                for (_, chain) in result.defUseChains {
                    for d in chain.definitions where d.address == insn.address {
                        live.remove(d.register)
                    }
                    for u in chain.uses where u.address == insn.address {
                        live.insert(u.register)
                    }
                }
            }
        }
    }

    // MARK: - Helpers

    private func normalizeRegister(_ reg: String) -> String {
        reg.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private func isRegister(_ str: String) -> Bool {
        let r = str.lowercased()
        // x86_64 registers
        if r.hasPrefix("r") || r.hasPrefix("e") || ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"].contains(r) {
            return true
        }
        // ARM64 registers
        if r.hasPrefix("x") || r.hasPrefix("w") || r == "sp" || r == "lr" {
            return true
        }
        // Common register patterns
        if r.first?.isLetter == true && !r.contains("[") && !r.contains("0x") {
            return true
        }
        return false
    }

    private func parseValue(_ str: String) -> AbstractValue {
        let s = str.trimmingCharacters(in: .whitespaces)

        // Check for constant
        if let constVal = parseConstant(s) {
            return .constant(constVal)
        }

        // Check for memory reference
        if s.contains("[") {
            if let baseReg = extractBaseRegister(s) {
                return .memory(base: baseReg, offset: extractOffset(s))
            }
        }

        // Check for register (symbolic)
        if isRegister(s) {
            return .symbolic(normalizeRegister(s))
        }

        return .top
    }

    private func parseConstant(_ str: String) -> Int64? {
        var s = str.trimmingCharacters(in: .whitespaces)

        // Remove ARM immediate prefix
        if s.hasPrefix("#") {
            s = String(s.dropFirst())
        }

        // Hex constant
        if s.hasPrefix("0x") || s.hasPrefix("-0x") {
            let negative = s.hasPrefix("-")
            let hexStr = negative ? String(s.dropFirst(3)) : String(s.dropFirst(2))
            if let val = Int64(hexStr, radix: 16) {
                return negative ? -val : val
            }
        }

        // Decimal constant
        if let val = Int64(s) {
            return val
        }

        return nil
    }

    private func extractBaseRegister(_ memOp: String) -> String? {
        // Parse [reg], [reg + offset], [reg, #offset]
        var s = memOp
        if let start = s.firstIndex(of: "["), let end = s.firstIndex(of: "]") {
            s = String(s[s.index(after: start)..<end])
        }

        // Get base register (before + or ,)
        if let plusIdx = s.firstIndex(of: "+") {
            return String(s[..<plusIdx]).trimmingCharacters(in: .whitespaces)
        }
        if let commaIdx = s.firstIndex(of: ",") {
            return String(s[..<commaIdx]).trimmingCharacters(in: .whitespaces)
        }
        if let minusIdx = s.firstIndex(of: "-") {
            return String(s[..<minusIdx]).trimmingCharacters(in: .whitespaces)
        }

        return s.trimmingCharacters(in: .whitespaces)
    }

    private func extractOffset(_ memOp: String) -> Int64 {
        if let match = memOp.range(of: "[+-]\\s*(0x[0-9a-fA-F]+|\\d+)", options: .regularExpression) {
            let offsetStr = String(memOp[match])
            return parseConstant(offsetStr) ?? 0
        }
        return 0
    }

    private func getClobberedRegisters(architecture: Architecture) -> [String] {
        switch architecture {
        case .x86_64:
            return ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]
        case .arm64, .arm64e:
            return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                    "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15", "x16", "x17"]
        case .i386:
            return ["eax", "ecx", "edx"]
        case .armv7:
            return ["r0", "r1", "r2", "r3", "r12"]
        default:
            return []
        }
    }
}

// MARK: - Value Set Analysis (for pointer analysis)

/// Simplified Value Set Analysis for tracking possible pointer values
class ValueSetAnalyzer {

    /// A set of possible values a register/variable can hold
    struct ValueSet {
        var constants: Set<Int64> = []
        var symbols: Set<String> = []
        var memoryRegions: Set<String> = []  // stack, heap, global

        var isConstant: Bool {
            constants.count == 1 && symbols.isEmpty && memoryRegions.isEmpty
        }

        var singleConstant: Int64? {
            guard isConstant else { return nil }
            return constants.first
        }

        static let top = ValueSet(constants: [], symbols: ["*"], memoryRegions: ["*"])
        static let bottom = ValueSet()

        mutating func union(_ other: ValueSet) {
            constants.formUnion(other.constants)
            symbols.formUnion(other.symbols)
            memoryRegions.formUnion(other.memoryRegions)
        }
    }

    /// Analyze pointer values in a function
    func analyzePointers(function: Function, binary: BinaryFile) -> [UInt64: [String: ValueSet]] {
        var result: [UInt64: [String: ValueSet]] = [:]

        // Basic implementation - track stack and global pointers
        for block in function.basicBlocks {
            var currentSets: [String: ValueSet] = [:]

            for insn in block.instructions {
                result[insn.address] = currentSets
                updateValueSets(instruction: insn, sets: &currentSets, binary: binary)
            }
        }

        return result
    }

    private func updateValueSets(instruction: Instruction, sets: inout [String: ValueSet], binary: BinaryFile) {
        // Track lea instructions (address computations)
        if instruction.mnemonic.lowercased() == "lea" {
            let parts = instruction.operands.split(separator: ",")
            if parts.count >= 2 {
                let dest = String(parts[0]).trimmingCharacters(in: .whitespaces).lowercased()
                let src = String(parts[1]).trimmingCharacters(in: .whitespaces)

                var valueSet = ValueSet()

                // Check if it's a stack reference
                if src.contains("rbp") || src.contains("rsp") || src.contains("sp") {
                    valueSet.memoryRegions.insert("stack")
                }
                // Check if it's a global/rip-relative
                else if src.contains("rip") {
                    valueSet.memoryRegions.insert("global")
                }

                sets[dest] = valueSet
            }
        }
    }
}

// MARK: - Slice Analysis

/// Computes backward/forward slices for a variable at a given program point
class SliceAnalyzer {

    struct Slice {
        let variable: String
        let startAddress: UInt64
        var instructions: Set<UInt64> = []
    }

    /// Compute backward slice - all instructions that affect the variable's value
    func backwardSlice(variable: String, at address: UInt64, function: Function, dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult) -> Slice {
        var slice = Slice(variable: variable, startAddress: address)
        var worklist: [(String, UInt64)] = [(variable, address)]
        var visited = Set<UInt64>()

        while !worklist.isEmpty {
            let (varName, addr) = worklist.removeFirst()

            guard !visited.contains(addr) else { continue }
            visited.insert(addr)

            // Find the instruction
            for block in function.basicBlocks {
                for insn in block.instructions where insn.address == addr {
                    slice.instructions.insert(addr)

                    // Add reaching definitions to worklist
                    if let reaching = dataFlow.reachingDefinitions[addr] {
                        for def in reaching where def.register == varName {
                            worklist.append((varName, def.address))
                        }
                    }

                    // Add used variables to worklist
                    if let chain = dataFlow.defUseChains[varName] {
                        for use in chain.uses where use.address == addr {
                            for defAddr in use.definitions {
                                worklist.append((varName, defAddr))
                            }
                        }
                    }
                }
            }
        }

        return slice
    }

    /// Compute forward slice - all instructions affected by the variable's value
    func forwardSlice(variable: String, at address: UInt64, function: Function, dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult) -> Slice {
        var slice = Slice(variable: variable, startAddress: address)
        var worklist: [(String, UInt64)] = [(variable, address)]
        var visited = Set<UInt64>()

        while !worklist.isEmpty {
            let (varName, addr) = worklist.removeFirst()

            guard !visited.contains(addr) else { continue }
            visited.insert(addr)
            slice.instructions.insert(addr)

            // Find all uses of this definition
            if let chain = dataFlow.defUseChains[varName] {
                for use in chain.uses {
                    if use.definitions.contains(addr) {
                        worklist.append((varName, use.address))
                    }
                }
            }
        }

        return slice
    }
}
