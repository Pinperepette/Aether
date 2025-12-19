import Foundation

// MARK: - Deobfuscation Engine

/// Detects and removes common obfuscation techniques
class Deobfuscator {

    // MARK: - Types

    /// Detected obfuscation technique
    struct ObfuscationFinding {
        let technique: ObfuscationTechnique
        let address: UInt64
        let affectedRange: Range<UInt64>
        let confidence: Double
        let description: String
    }

    enum ObfuscationTechnique: String, CaseIterable {
        case controlFlowFlattening = "Control Flow Flattening"
        case opaquePredicate = "Opaque Predicate"
        case deadCode = "Dead Code"
        case junkCode = "Junk Code"
        case instructionSubstitution = "Instruction Substitution"
        case constantObfuscation = "Constant Obfuscation"
        case stringEncryption = "String Encryption"
        case callObfuscation = "Call Obfuscation"
        case virtualMachine = "VM-based Protection"
        case selfModifying = "Self-Modifying Code"
        case antiDisassembly = "Anti-Disassembly"
        case packedCode = "Packed/Encrypted Code"
    }

    /// Result of deobfuscation
    struct DeobfuscationResult {
        let findings: [ObfuscationFinding]
        let simplifiedBlocks: [SimplifiedBlock]
        let removedInstructions: Set<UInt64>
        let resolvedPredicates: [UInt64: Bool]
    }

    struct SimplifiedBlock {
        let originalAddress: UInt64
        let simplifiedInstructions: [Instruction]
        let changes: [String]
    }

    // MARK: - Detection

    private var dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult?

    /// Analyze function for obfuscation
    func analyze(function: Function, binary: BinaryFile) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        // Perform data flow analysis first
        let dfAnalyzer = AdvancedDataFlowAnalyzer()
        dataFlow = dfAnalyzer.analyze(function: function, binary: binary)

        // Detect control flow flattening
        findings.append(contentsOf: detectControlFlowFlattening(function: function))

        // Detect opaque predicates
        findings.append(contentsOf: detectOpaquePredicates(function: function))

        // Detect dead code
        findings.append(contentsOf: detectDeadCode(function: function))

        // Detect junk code
        findings.append(contentsOf: detectJunkCode(function: function))

        // Detect instruction substitution
        findings.append(contentsOf: detectInstructionSubstitution(function: function))

        // Detect constant obfuscation
        findings.append(contentsOf: detectConstantObfuscation(function: function))

        // Detect anti-disassembly tricks
        findings.append(contentsOf: detectAntiDisassembly(function: function))

        // Detect VM-based protection
        findings.append(contentsOf: detectVMProtection(function: function))

        return findings
    }

    /// Attempt to deobfuscate function
    func deobfuscate(function: Function, binary: BinaryFile) -> DeobfuscationResult {
        let findings = analyze(function: function, binary: binary)

        var simplifiedBlocks: [SimplifiedBlock] = []
        var removedInstructions = Set<UInt64>()
        var resolvedPredicates: [UInt64: Bool] = [:]

        // Process each finding
        for finding in findings {
            switch finding.technique {
            case .opaquePredicate:
                if let result = resolveOpaquePredicate(at: finding.address, function: function) {
                    resolvedPredicates[finding.address] = result
                }

            case .deadCode:
                // Mark instructions for removal
                for addr in finding.affectedRange {
                    removedInstructions.insert(addr)
                }

            case .junkCode:
                for addr in finding.affectedRange {
                    removedInstructions.insert(addr)
                }

            case .constantObfuscation:
                if let simplified = simplifyConstantObfuscation(at: finding.address, function: function) {
                    simplifiedBlocks.append(simplified)
                }

            case .instructionSubstitution:
                if let simplified = reverseSubstitution(at: finding.address, function: function) {
                    simplifiedBlocks.append(simplified)
                }

            default:
                break
            }
        }

        return DeobfuscationResult(
            findings: findings,
            simplifiedBlocks: simplifiedBlocks,
            removedInstructions: removedInstructions,
            resolvedPredicates: resolvedPredicates
        )
    }

    // MARK: - Control Flow Flattening Detection

    private func detectControlFlowFlattening(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        // Characteristics of CFF:
        // 1. Large switch/dispatch block
        // 2. State variable that controls flow
        // 3. Many blocks that update state and jump back to dispatcher

        guard function.basicBlocks.count > 10 else { return findings }

        // Find potential dispatcher block
        var dispatcherCandidates: [BasicBlock] = []

        for block in function.basicBlocks {
            // Dispatcher has many predecessors and successors
            if block.predecessors.count > 3 && block.successors.count > 3 {
                dispatcherCandidates.append(block)
            }
        }

        for dispatcher in dispatcherCandidates {
            // Check if most blocks eventually return to this block
            var returningBlocks = 0
            for block in function.basicBlocks where block.startAddress != dispatcher.startAddress {
                if canReach(from: block.startAddress, to: dispatcher.startAddress, function: function) {
                    returningBlocks += 1
                }
            }

            let ratio = Double(returningBlocks) / Double(function.basicBlocks.count - 1)

            if ratio > 0.7 {
                findings.append(ObfuscationFinding(
                    technique: .controlFlowFlattening,
                    address: dispatcher.startAddress,
                    affectedRange: function.startAddress..<function.endAddress,
                    confidence: ratio,
                    description: "Control flow flattening detected. Dispatcher at 0x\(String(format: "%llX", dispatcher.startAddress))"
                ))
            }
        }

        return findings
    }

    // MARK: - Opaque Predicate Detection

    private func detectOpaquePredicates(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        for block in function.basicBlocks where block.type == .conditional {
            guard let lastInsn = block.instructions.last,
                  lastInsn.type == .conditionalJump else { continue }

            // Check if condition is always true or always false
            if let isOpaque = checkForOpaquePredicate(block: block) {
                findings.append(ObfuscationFinding(
                    technique: .opaquePredicate,
                    address: lastInsn.address,
                    affectedRange: block.startAddress..<block.endAddress,
                    confidence: isOpaque.confidence,
                    description: isOpaque.description
                ))
            }
        }

        return findings
    }

    private func checkForOpaquePredicate(block: BasicBlock) -> (confidence: Double, description: String)? {
        // Look for common opaque predicate patterns

        // Pattern 1: x * (x - 1) is always even
        // cmp (result of x*(x-1)) & 1, 0 -> always true

        // Pattern 2: x^2 >= 0 (always true for real numbers)

        // Pattern 3: 2|(x^2 + x) (always true)

        // Pattern 4: Comparison with known constants
        for insn in block.instructions {
            if insn.type == .compare {
                // Check if both operands can be evaluated to constants
                if let result = evaluateComparison(insn) {
                    return (0.9, "Opaque predicate: comparison is always \(result)")
                }
            }
        }

        // Pattern 5: Aliased pointers that never alias
        // This requires pointer analysis

        // Pattern 6: Dead comparison (result never used except for jump)
        if isDeadComparison(in: block) {
            return (0.7, "Potentially opaque predicate: comparison result unused elsewhere")
        }

        return nil
    }

    private func evaluateComparison(_ insn: Instruction) -> Bool? {
        guard let df = dataFlow else { return nil }

        let parts = insn.operands.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return nil }

        // Get constant values if available
        let val1 = df.getValue(register: parts[0].lowercased(), at: insn.address)
        let val2 = parseConstantOrGetValue(parts[1], at: insn.address, df: df)

        if case .constant(let c1) = val1, case .constant(let c2) = val2 {
            // Both are constants, we can evaluate
            // The actual comparison depends on the following conditional jump
            return true  // Predicate can be resolved
        }

        return nil
    }

    private func parseConstantOrGetValue(_ str: String, at address: UInt64, df: AdvancedDataFlowAnalyzer.DataFlowResult) -> AdvancedDataFlowAnalyzer.AbstractValue {
        var s = str.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "#", with: "")

        if s.hasPrefix("0x") {
            if let val = Int64(s.dropFirst(2), radix: 16) {
                return .constant(val)
            }
        } else if let val = Int64(s) {
            return .constant(val)
        }

        return df.getValue(register: s.lowercased(), at: address)
    }

    private func isDeadComparison(in block: BasicBlock) -> Bool {
        // Check if comparison result (flags) is only used by the conditional jump
        // and not by any other instruction
        var foundCompare = false
        var usesAfterCompare = 0

        for insn in block.instructions {
            if insn.type == .compare {
                foundCompare = true
            } else if foundCompare {
                // Check if this instruction uses flags
                let flagUsers = ["cmov", "set", "adc", "sbb"]
                if flagUsers.contains(where: { insn.mnemonic.lowercased().hasPrefix($0) }) {
                    usesAfterCompare += 1
                }
            }
        }

        return foundCompare && usesAfterCompare == 0
    }

    // MARK: - Dead Code Detection

    private func detectDeadCode(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        // Find unreachable blocks
        var reachable = Set<UInt64>()
        var worklist: [UInt64] = [function.startAddress]

        while !worklist.isEmpty {
            let addr = worklist.removeFirst()
            if reachable.contains(addr) { continue }
            reachable.insert(addr)

            if let block = function.basicBlocks.first(where: { $0.startAddress == addr }) {
                for succ in block.successors {
                    worklist.append(succ)
                }
            }
        }

        for block in function.basicBlocks {
            if !reachable.contains(block.startAddress) {
                findings.append(ObfuscationFinding(
                    technique: .deadCode,
                    address: block.startAddress,
                    affectedRange: block.startAddress..<block.endAddress,
                    confidence: 1.0,
                    description: "Unreachable code block"
                ))
            }
        }

        return findings
    }

    // MARK: - Junk Code Detection

    private func detectJunkCode(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        for block in function.basicBlocks {
            var junkSequences: [(start: UInt64, end: UInt64)] = []
            var currentJunkStart: UInt64?

            for insn in block.instructions {
                if isJunkInstruction(insn) {
                    if currentJunkStart == nil {
                        currentJunkStart = insn.address
                    }
                } else {
                    if let start = currentJunkStart {
                        junkSequences.append((start, insn.address))
                        currentJunkStart = nil
                    }
                }
            }

            // Report significant junk sequences (3+ instructions)
            for seq in junkSequences {
                let count = block.instructions.filter { $0.address >= seq.start && $0.address < seq.end }.count
                if count >= 3 {
                    findings.append(ObfuscationFinding(
                        technique: .junkCode,
                        address: seq.start,
                        affectedRange: seq.start..<seq.end,
                        confidence: 0.8,
                        description: "\(count) consecutive junk instructions"
                    ))
                }
            }
        }

        return findings
    }

    private func isJunkInstruction(_ insn: Instruction) -> Bool {
        let mnemonic = insn.mnemonic.lowercased()

        // NOP and similar
        if insn.type == .nop { return true }

        // mov reg, reg (same register)
        if mnemonic == "mov" || mnemonic == "movq" {
            let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            if parts.count == 2 && parts[0] == parts[1] {
                return true
            }
        }

        // xchg reg, reg (same register)
        if mnemonic == "xchg" {
            let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
            if parts.count == 2 && parts[0] == parts[1] {
                return true
            }
        }

        // add/sub reg, 0
        if mnemonic == "add" || mnemonic == "sub" {
            if insn.operands.hasSuffix("0") || insn.operands.hasSuffix("#0") {
                return true
            }
        }

        // Sequence: push reg; pop reg (without intervening code)
        // This is detected at sequence level

        return false
    }

    // MARK: - Instruction Substitution Detection

    private func detectInstructionSubstitution(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        for block in function.basicBlocks {
            var i = 0
            while i < block.instructions.count {
                if let pattern = detectSubstitutionPattern(at: i, in: block.instructions) {
                    findings.append(ObfuscationFinding(
                        technique: .instructionSubstitution,
                        address: block.instructions[i].address,
                        affectedRange: block.instructions[i].address..<block.instructions[i + pattern.length - 1].address,
                        confidence: pattern.confidence,
                        description: pattern.description
                    ))
                    i += pattern.length
                } else {
                    i += 1
                }
            }
        }

        return findings
    }

    private func detectSubstitutionPattern(at index: Int, in instructions: [Instruction]) -> (length: Int, confidence: Double, description: String)? {
        guard index < instructions.count else { return nil }

        // Pattern: Multiple operations that could be simplified
        // e.g., x = x - (-5) instead of x = x + 5
        // e.g., x = x ^ y ^ y instead of x (xor twice)

        let insn = instructions[index]

        // Detect xor-based substitution for negation
        // -x implemented as (x ^ -1) + 1
        if insn.mnemonic.lowercased() == "xor" && index + 1 < instructions.count {
            let next = instructions[index + 1]
            if next.mnemonic.lowercased() == "add" || next.mnemonic.lowercased() == "inc" {
                return (2, 0.7, "Possible negation via XOR + ADD")
            }
        }

        // Detect rotation implemented as shifts
        // (x << n) | (x >> (32-n)) for rol
        if (insn.mnemonic.lowercased() == "shl" || insn.mnemonic.lowercased() == "sal") &&
            index + 2 < instructions.count {
            let insn2 = instructions[index + 1]
            let insn3 = instructions[index + 2]

            if (insn2.mnemonic.lowercased() == "shr" || insn2.mnemonic.lowercased() == "sar") &&
                insn3.mnemonic.lowercased() == "or" {
                return (3, 0.85, "Rotation implemented as shift+or")
            }
        }

        return nil
    }

    // MARK: - Constant Obfuscation Detection

    private func detectConstantObfuscation(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        for block in function.basicBlocks {
            for (i, insn) in block.instructions.enumerated() {
                // Look for complex constant loading
                // e.g., mov reg, A; xor reg, B; add reg, C (result is a simple constant)

                if insn.type == .move {
                    // Check if followed by operations that compute a constant
                    var operations: [Instruction] = [insn]
                    var j = i + 1

                    while j < block.instructions.count {
                        let next = block.instructions[j]
                        if next.type == .arithmetic || next.type == .logic {
                            // Check if operates on same register
                            let dest = extractDestRegister(from: insn)
                            let nextDest = extractDestRegister(from: next)
                            if dest == nextDest {
                                operations.append(next)
                                j += 1
                                continue
                            }
                        }
                        break
                    }

                    if operations.count >= 3 {
                        // Try to evaluate
                        if let result = evaluateConstantSequence(operations) {
                            findings.append(ObfuscationFinding(
                                technique: .constantObfuscation,
                                address: insn.address,
                                affectedRange: insn.address..<operations.last!.address,
                                confidence: 0.85,
                                description: "Obfuscated constant: result = \(result)"
                            ))
                        }
                    }
                }
            }
        }

        return findings
    }

    private func extractDestRegister(from insn: Instruction) -> String? {
        let parts = insn.operands.split(separator: ",")
        return parts.first.map { String($0).trimmingCharacters(in: .whitespaces).lowercased() }
    }

    private func evaluateConstantSequence(_ instructions: [Instruction]) -> Int64? {
        guard let first = instructions.first,
              let parts = first.operands.split(separator: ",").last else { return nil }

        var value = parseConstant(String(parts))
        guard var currentValue = value else { return nil }

        for insn in instructions.dropFirst() {
            let operandParts = insn.operands.split(separator: ",")
            guard operandParts.count >= 2,
                  let operand = parseConstant(String(operandParts.last!)) else { return nil }

            switch insn.mnemonic.lowercased() {
            case "add":
                currentValue = currentValue &+ operand
            case "sub":
                currentValue = currentValue &- operand
            case "xor":
                currentValue = currentValue ^ operand
            case "and":
                currentValue = currentValue & operand
            case "or":
                currentValue = currentValue | operand
            default:
                return nil
            }
        }

        return currentValue
    }

    private func parseConstant(_ str: String) -> Int64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "#", with: "")

        if s.hasPrefix("0x") || s.hasPrefix("-0x") {
            let negative = s.hasPrefix("-")
            let hex = negative ? String(s.dropFirst(3)) : String(s.dropFirst(2))
            if let val = Int64(hex, radix: 16) {
                return negative ? -val : val
            }
        }

        return Int64(s)
    }

    // MARK: - Anti-Disassembly Detection

    private func detectAntiDisassembly(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        for block in function.basicBlocks {
            for insn in block.instructions {
                // Jump into middle of instruction
                if insn.type == .jump, let target = insn.branchTarget {
                    // Check if target is not aligned to instruction boundary
                    let isValidTarget = function.basicBlocks.flatMap(\.instructions).contains { $0.address == target }
                    if !isValidTarget && function.contains(address: target) {
                        findings.append(ObfuscationFinding(
                            technique: .antiDisassembly,
                            address: insn.address,
                            affectedRange: insn.address..<(insn.address + UInt64(insn.size)),
                            confidence: 0.8,
                            description: "Jump to non-instruction boundary"
                        ))
                    }
                }

                // Overlapping instructions
                // This would require checking instruction boundaries

                // Invalid opcode after conditional jump (to confuse linear disassembly)
            }
        }

        return findings
    }

    // MARK: - VM Protection Detection

    private func detectVMProtection(function: Function) -> [ObfuscationFinding] {
        var findings: [ObfuscationFinding] = []

        // Characteristics of VM-based protection:
        // 1. Dispatch loop pattern
        // 2. Handler table
        // 3. Bytecode execution

        let instructions = function.basicBlocks.flatMap(\.instructions)

        // Look for dispatch loop: fetch-decode-execute pattern
        var dispatchPatternScore = 0

        // Check for indirect jump (common in VM dispatch)
        let indirectJumps = instructions.filter { $0.type == .jump && $0.operands.contains("[") }
        if indirectJumps.count > 0 {
            dispatchPatternScore += 1
        }

        // Check for handler table access pattern
        let indexedLoads = instructions.filter { $0.type == .load && $0.operands.contains("*") }
        if indexedLoads.count > 5 {
            dispatchPatternScore += 1
        }

        // Check for bytecode pointer increment
        let incrementOps = instructions.filter {
            $0.type == .arithmetic &&
            ($0.mnemonic.lowercased() == "add" || $0.mnemonic.lowercased() == "inc")
        }
        if incrementOps.count > 10 {
            dispatchPatternScore += 1
        }

        if dispatchPatternScore >= 2 {
            findings.append(ObfuscationFinding(
                technique: .virtualMachine,
                address: function.startAddress,
                affectedRange: function.startAddress..<function.endAddress,
                confidence: Double(dispatchPatternScore) / 3.0,
                description: "Possible VM-based protection detected"
            ))
        }

        return findings
    }

    // MARK: - Deobfuscation Actions

    private func resolveOpaquePredicate(at address: UInt64, function: Function) -> Bool? {
        // Find the block containing the predicate
        guard let block = function.basicBlocks.first(where: { $0.instructions.contains { $0.address == address } }) else {
            return nil
        }

        // Try to determine if condition is always true or always false
        // using data flow information

        return nil  // Would need more sophisticated analysis
    }

    private func simplifyConstantObfuscation(at address: UInt64, function: Function) -> SimplifiedBlock? {
        // Find the sequence and replace with simple mov

        return nil  // Would generate simplified instructions
    }

    private func reverseSubstitution(at address: UInt64, function: Function) -> SimplifiedBlock? {
        // Find the substituted sequence and replace with original instruction

        return nil  // Would generate simplified instructions
    }

    // MARK: - Helpers

    private func canReach(from source: UInt64, to target: UInt64, function: Function) -> Bool {
        var visited = Set<UInt64>()
        var worklist: [UInt64] = [source]

        while !worklist.isEmpty {
            let current = worklist.removeFirst()
            if current == target { return true }
            if visited.contains(current) { continue }
            visited.insert(current)

            if let block = function.basicBlocks.first(where: { $0.startAddress == current }) {
                for succ in block.successors {
                    worklist.append(succ)
                }
            }
        }

        return false
    }
}

// MARK: - String Decryption Helper

/// Attempts to identify and decrypt encrypted strings
class StringDecryptor {

    struct EncryptedString {
        let address: UInt64
        let encryptedData: Data
        let decryptionRoutine: UInt64?
        let decryptedValue: String?
        let algorithm: EncryptionAlgorithm?
    }

    enum EncryptionAlgorithm {
        case xor(key: [UInt8])
        case rc4(key: [UInt8])
        case custom
        case base64
    }

    /// Identify potentially encrypted strings
    func findEncryptedStrings(binary: BinaryFile, strings: [StringReference]) -> [EncryptedString] {
        var encrypted: [EncryptedString] = []

        // Look for high-entropy data that's referenced like strings
        for section in binary.sections where !section.containsCode {
            let entropyResults = findHighEntropyRegions(in: section.data, baseAddress: section.address)

            for region in entropyResults {
                // Check if this region is referenced in code
                // This would require cross-reference analysis

                encrypted.append(EncryptedString(
                    address: region.address,
                    encryptedData: region.data,
                    decryptionRoutine: nil,
                    decryptedValue: nil,
                    algorithm: nil
                ))
            }
        }

        // Try common decryption methods
        for i in 0..<encrypted.count {
            if let decrypted = tryDecrypt(encrypted[i].encryptedData) {
                encrypted[i] = EncryptedString(
                    address: encrypted[i].address,
                    encryptedData: encrypted[i].encryptedData,
                    decryptionRoutine: encrypted[i].decryptionRoutine,
                    decryptedValue: decrypted.value,
                    algorithm: decrypted.algorithm
                )
            }
        }

        return encrypted
    }

    private func findHighEntropyRegions(in data: Data, baseAddress: UInt64) -> [(address: UInt64, data: Data)] {
        var regions: [(UInt64, Data)] = []

        // Calculate entropy in sliding windows
        let windowSize = 32
        let entropyThreshold = 6.5  // High entropy threshold

        for i in stride(from: 0, to: data.count - windowSize, by: windowSize) {
            let window = data[i..<(i + windowSize)]
            let entropy = calculateEntropy(Array(window))

            if entropy > entropyThreshold {
                regions.append((baseAddress + UInt64(i), Data(window)))
            }
        }

        return regions
    }

    private func calculateEntropy(_ bytes: [UInt8]) -> Double {
        var freq = [Int](repeating: 0, count: 256)
        for byte in bytes {
            freq[Int(byte)] += 1
        }

        var entropy = 0.0
        let count = Double(bytes.count)

        for f in freq where f > 0 {
            let p = Double(f) / count
            entropy -= p * log2(p)
        }

        return entropy
    }

    private func tryDecrypt(_ data: Data) -> (value: String, algorithm: EncryptionAlgorithm)? {
        // Try XOR with common single-byte keys
        for key: UInt8 in [0x00, 0xFF, 0x41, 0x55, 0xAA] {
            let decrypted = data.map { $0 ^ key }
            if let str = String(bytes: decrypted, encoding: .utf8), isPrintable(str) {
                return (str, .xor(key: [key]))
            }
        }

        // Try Base64 decoding
        if let decoded = Data(base64Encoded: data),
           let str = String(data: decoded, encoding: .utf8) {
            return (str, .base64)
        }

        return nil
    }

    private func isPrintable(_ str: String) -> Bool {
        let printable = CharacterSet.alphanumerics.union(.punctuationCharacters).union(.whitespaces)
        return str.unicodeScalars.allSatisfy { printable.contains($0) }
    }
}
