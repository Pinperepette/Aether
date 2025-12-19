import Foundation

// MARK: - Idiom Recognition

/// Recognizes common code patterns and idioms in assembly code
/// and replaces them with higher-level representations
class IdiomRecognizer {

    // MARK: - Idiom Types

    /// Recognized idiom categories
    enum IdiomCategory: String, CaseIterable {
        case stringOperation = "String Operation"
        case memoryOperation = "Memory Operation"
        case arithmetic = "Arithmetic"
        case bitManipulation = "Bit Manipulation"
        case comparison = "Comparison"
        case loopConstruct = "Loop Construct"
        case functionPrologue = "Function Prologue"
        case functionEpilogue = "Function Epilogue"
        case systemCall = "System Call"
        case objectiveC = "Objective-C"
        case swift = "Swift"
    }

    /// A recognized idiom
    struct Idiom {
        let category: IdiomCategory
        let name: String
        let description: String
        let startAddress: UInt64
        let endAddress: UInt64
        let replacement: String      // High-level code replacement
        let confidence: Double       // 0.0 - 1.0
        let matchedInstructions: [Instruction]
    }

    /// Pattern matching result
    struct PatternMatch {
        let idiom: Idiom
        let instructions: [Instruction]
    }

    // MARK: - Pattern Definitions

    /// Instruction pattern for matching
    struct InstructionPattern {
        let mnemonic: String?        // nil = any mnemonic
        let operandPatterns: [String]?  // nil = any operands
        let type: InstructionType?   // nil = any type

        func matches(_ insn: Instruction) -> Bool {
            if let m = mnemonic, insn.mnemonic.lowercased() != m.lowercased() {
                return false
            }
            if let t = type, insn.type != t {
                return false
            }
            if let ops = operandPatterns {
                let insnOps = insn.operands.lowercased()
                for pattern in ops {
                    if !matchOperandPattern(pattern, operands: insnOps) {
                        return false
                    }
                }
            }
            return true
        }

        private func matchOperandPattern(_ pattern: String, operands: String) -> Bool {
            // Support wildcards: * matches anything, ? matches single char
            if pattern == "*" { return true }

            let regexPattern = pattern
                .replacingOccurrences(of: "*", with: ".*")
                .replacingOccurrences(of: "?", with: ".")

            if let regex = try? NSRegularExpression(pattern: regexPattern, options: .caseInsensitive) {
                let range = NSRange(operands.startIndex..., in: operands)
                return regex.firstMatch(in: operands, range: range) != nil
            }

            return operands.contains(pattern.lowercased())
        }
    }

    /// Multi-instruction pattern
    struct MultiInstructionPattern {
        let name: String
        let category: IdiomCategory
        let description: String
        let patterns: [InstructionPattern]
        let replacement: ([Instruction]) -> String
        let confidence: Double
    }

    // MARK: - Recognizer

    private var patterns: [MultiInstructionPattern] = []

    init() {
        setupPatterns()
    }

    private func setupPatterns() {
        // String length (strlen inline)
        patterns.append(MultiInstructionPattern(
            name: "strlen inline",
            category: .stringOperation,
            description: "Inline string length calculation",
            patterns: [
                InstructionPattern(mnemonic: nil, operandPatterns: nil, type: .move),      // Setup
                InstructionPattern(mnemonic: nil, operandPatterns: ["*0*"], type: .compare), // cmp byte, 0
                InstructionPattern(mnemonic: nil, operandPatterns: nil, type: .conditionalJump),
                InstructionPattern(mnemonic: "add", operandPatterns: ["*1*"], type: .arithmetic), // ptr++
            ],
            replacement: { insns in
                let reg = insns.first?.operands.split(separator: ",").first ?? "ptr"
                return "len = strlen(\(reg));"
            },
            confidence: 0.7
        ))

        // memcpy inline (rep movsb/movsq)
        patterns.append(MultiInstructionPattern(
            name: "memcpy (rep movs)",
            category: .memoryOperation,
            description: "Inline memory copy using rep movs",
            patterns: [
                InstructionPattern(mnemonic: "rep", operandPatterns: ["movs*"], type: nil)
            ],
            replacement: { insns in
                return "memcpy(rdi, rsi, rcx);"
            },
            confidence: 0.95
        ))

        // memset inline (rep stosb)
        patterns.append(MultiInstructionPattern(
            name: "memset (rep stos)",
            category: .memoryOperation,
            description: "Inline memory set using rep stos",
            patterns: [
                InstructionPattern(mnemonic: "rep", operandPatterns: ["stos*"], type: nil)
            ],
            replacement: { _ in
                return "memset(rdi, al, rcx);"
            },
            confidence: 0.95
        ))

        // Multiplication by constant via shift+add
        patterns.append(MultiInstructionPattern(
            name: "multiply by 3",
            category: .arithmetic,
            description: "Multiplication by 3 using lea",
            patterns: [
                InstructionPattern(mnemonic: "lea", operandPatterns: ["*[*+*2]*"], type: nil)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if let dest = parts.first {
                    return "\(dest) *= 3;"
                }
                return "reg *= 3;"
            },
            confidence: 0.9
        ))

        patterns.append(MultiInstructionPattern(
            name: "multiply by 5",
            category: .arithmetic,
            description: "Multiplication by 5 using lea",
            patterns: [
                InstructionPattern(mnemonic: "lea", operandPatterns: ["*[*+*4]*"], type: nil)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if let dest = parts.first {
                    return "\(dest) *= 5;"
                }
                return "reg *= 5;"
            },
            confidence: 0.9
        ))

        // Division by power of 2
        patterns.append(MultiInstructionPattern(
            name: "divide by power of 2",
            category: .arithmetic,
            description: "Division by power of 2 using shift",
            patterns: [
                InstructionPattern(mnemonic: "sar", operandPatterns: nil, type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if parts.count >= 2 {
                    let reg = parts[0].trimmingCharacters(in: .whitespaces)
                    let shift = parts[1].trimmingCharacters(in: .whitespaces)
                    if let shiftVal = Int(shift.replacingOccurrences(of: "#", with: "")) {
                        let divisor = 1 << shiftVal
                        return "\(reg) /= \(divisor);"
                    }
                }
                return "reg /= (power of 2);"
            },
            confidence: 0.85
        ))

        // Modulo power of 2
        patterns.append(MultiInstructionPattern(
            name: "modulo power of 2",
            category: .arithmetic,
            description: "Modulo by power of 2 using AND",
            patterns: [
                InstructionPattern(mnemonic: "and", operandPatterns: nil, type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if parts.count >= 2 {
                    let reg = parts[0].trimmingCharacters(in: .whitespaces)
                    var maskStr = parts[1].trimmingCharacters(in: .whitespaces)
                    maskStr = maskStr.replacingOccurrences(of: "#", with: "")

                    // Check if mask is (power of 2) - 1
                    if let mask = self.parseNumber(maskStr) {
                        let modValue = mask + 1
                        if modValue & (modValue - 1) == 0 {  // Is power of 2
                            return "\(reg) %= \(modValue);"
                        }
                    }
                }
                return "// AND operation"
            },
            confidence: 0.8
        ))

        // Sign extension
        patterns.append(MultiInstructionPattern(
            name: "sign extension",
            category: .bitManipulation,
            description: "Sign extension via shift pair",
            patterns: [
                InstructionPattern(mnemonic: "shl", operandPatterns: nil, type: .arithmetic),
                InstructionPattern(mnemonic: "sar", operandPatterns: nil, type: .arithmetic)
            ],
            replacement: { insns in
                let shlOps = insns[0].operands.split(separator: ",")
                let sarOps = insns[1].operands.split(separator: ",")
                if shlOps.count >= 2 && sarOps.count >= 2 {
                    let reg = shlOps[0].trimmingCharacters(in: .whitespaces)
                    return "\(reg) = (int32_t)\(reg);  // sign extend"
                }
                return "// sign extension"
            },
            confidence: 0.85
        ))

        // Zero extension
        patterns.append(MultiInstructionPattern(
            name: "zero extension",
            category: .bitManipulation,
            description: "Zero extension via AND mask",
            patterns: [
                InstructionPattern(mnemonic: "and", operandPatterns: ["*0xff*"], type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if let reg = parts.first {
                    return "\(reg) = (uint8_t)\(reg);"
                }
                return "// zero extend to byte"
            },
            confidence: 0.9
        ))

        // Test for zero
        patterns.append(MultiInstructionPattern(
            name: "test for zero",
            category: .comparison,
            description: "Test if register is zero",
            patterns: [
                InstructionPattern(mnemonic: "test", operandPatterns: nil, type: .compare)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if parts.count >= 2 {
                    let op1 = parts[0].trimmingCharacters(in: .whitespaces)
                    let op2 = parts[1].trimmingCharacters(in: .whitespaces)
                    if op1.lowercased() == op2.lowercased() {
                        return "// if (\(op1) == 0)"
                    }
                }
                return "// test"
            },
            confidence: 0.95
        ))

        // XOR for zero
        patterns.append(MultiInstructionPattern(
            name: "zero register",
            category: .bitManipulation,
            description: "Set register to zero via XOR",
            patterns: [
                InstructionPattern(mnemonic: "xor", operandPatterns: nil, type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if parts.count >= 2 {
                    let op1 = parts[0].trimmingCharacters(in: .whitespaces)
                    let op2 = parts[1].trimmingCharacters(in: .whitespaces)
                    if op1.lowercased() == op2.lowercased() {
                        return "\(op1) = 0;"
                    }
                }
                return "// xor"
            },
            confidence: 0.95
        ))

        // NOT via XOR with -1
        patterns.append(MultiInstructionPattern(
            name: "bitwise NOT",
            category: .bitManipulation,
            description: "Bitwise NOT via XOR with -1",
            patterns: [
                InstructionPattern(mnemonic: "xor", operandPatterns: ["*-1*"], type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if let reg = parts.first {
                    return "\(reg) = ~\(reg);"
                }
                return "// bitwise NOT"
            },
            confidence: 0.9
        ))

        // Absolute value
        patterns.append(MultiInstructionPattern(
            name: "absolute value",
            category: .arithmetic,
            description: "Compute absolute value",
            patterns: [
                InstructionPattern(mnemonic: "mov", operandPatterns: nil, type: .move),
                InstructionPattern(mnemonic: "sar", operandPatterns: ["*31*"], type: .arithmetic),
                InstructionPattern(mnemonic: "xor", operandPatterns: nil, type: .arithmetic),
                InstructionPattern(mnemonic: "sub", operandPatterns: nil, type: .arithmetic)
            ],
            replacement: { insns in
                let parts = insns[0].operands.split(separator: ",")
                if let reg = parts.first {
                    return "\(reg) = abs(\(reg));"
                }
                return "result = abs(value);"
            },
            confidence: 0.85
        ))

        // Min/Max
        patterns.append(MultiInstructionPattern(
            name: "conditional move min",
            category: .arithmetic,
            description: "Minimum via conditional move",
            patterns: [
                InstructionPattern(mnemonic: "cmp", operandPatterns: nil, type: .compare),
                InstructionPattern(mnemonic: "cmovl", operandPatterns: nil, type: .move)
            ],
            replacement: { insns in
                let cmpParts = insns[0].operands.split(separator: ",")
                if cmpParts.count >= 2 {
                    let a = cmpParts[0].trimmingCharacters(in: .whitespaces)
                    let b = cmpParts[1].trimmingCharacters(in: .whitespaces)
                    return "result = min(\(a), \(b));"
                }
                return "result = min(a, b);"
            },
            confidence: 0.8
        ))

        patterns.append(MultiInstructionPattern(
            name: "conditional move max",
            category: .arithmetic,
            description: "Maximum via conditional move",
            patterns: [
                InstructionPattern(mnemonic: "cmp", operandPatterns: nil, type: .compare),
                InstructionPattern(mnemonic: "cmovg", operandPatterns: nil, type: .move)
            ],
            replacement: { insns in
                let cmpParts = insns[0].operands.split(separator: ",")
                if cmpParts.count >= 2 {
                    let a = cmpParts[0].trimmingCharacters(in: .whitespaces)
                    let b = cmpParts[1].trimmingCharacters(in: .whitespaces)
                    return "result = max(\(a), \(b));"
                }
                return "result = max(a, b);"
            },
            confidence: 0.8
        ))

        // Stack canary check
        patterns.append(MultiInstructionPattern(
            name: "stack canary check",
            category: .functionEpilogue,
            description: "Stack canary/cookie check",
            patterns: [
                InstructionPattern(mnemonic: "mov", operandPatterns: ["*fs:*", "*gs:*"], type: .move),
                InstructionPattern(mnemonic: "xor", operandPatterns: nil, type: .arithmetic),
                InstructionPattern(mnemonic: nil, operandPatterns: nil, type: .conditionalJump)
            ],
            replacement: { _ in
                return "// Stack canary check"
            },
            confidence: 0.9
        ))

        // Objective-C message send
        patterns.append(MultiInstructionPattern(
            name: "objc_msgSend",
            category: .objectiveC,
            description: "Objective-C message send",
            patterns: [
                InstructionPattern(mnemonic: nil, operandPatterns: nil, type: .move),  // Setup self
                InstructionPattern(mnemonic: nil, operandPatterns: nil, type: .move),  // Setup selector
                InstructionPattern(mnemonic: "call", operandPatterns: ["*objc_msgSend*"], type: .call)
            ],
            replacement: { insns in
                return "[self method];"
            },
            confidence: 0.9
        ))

        // Swift retain/release
        patterns.append(MultiInstructionPattern(
            name: "swift_retain",
            category: .swift,
            description: "Swift reference counting",
            patterns: [
                InstructionPattern(mnemonic: "call", operandPatterns: ["*swift_retain*"], type: .call)
            ],
            replacement: { _ in
                return "// Swift retain (ARC)"
            },
            confidence: 0.95
        ))

        patterns.append(MultiInstructionPattern(
            name: "swift_release",
            category: .swift,
            description: "Swift reference counting",
            patterns: [
                InstructionPattern(mnemonic: "call", operandPatterns: ["*swift_release*"], type: .call)
            ],
            replacement: { _ in
                return "// Swift release (ARC)"
            },
            confidence: 0.95
        ))
    }

    // MARK: - Recognition

    /// Recognize idioms in a function
    func recognize(function: Function) -> [Idiom] {
        var idioms: [Idiom] = []

        let allInstructions = function.basicBlocks.flatMap { $0.instructions }

        // Try each pattern
        for pattern in patterns {
            var i = 0
            while i < allInstructions.count {
                if let match = tryMatchPattern(pattern, at: i, in: allInstructions) {
                    idioms.append(match.idiom)
                    i += match.instructions.count
                } else {
                    i += 1
                }
            }
        }

        // Also detect single-instruction idioms
        for insn in allInstructions {
            if let idiom = detectSingleInstructionIdiom(insn) {
                idioms.append(idiom)
            }
        }

        return idioms.sorted { $0.startAddress < $1.startAddress }
    }

    private func tryMatchPattern(_ pattern: MultiInstructionPattern, at index: Int, in instructions: [Instruction]) -> PatternMatch? {
        guard index + pattern.patterns.count <= instructions.count else { return nil }

        var matchedInstructions: [Instruction] = []

        for (i, instrPattern) in pattern.patterns.enumerated() {
            let insn = instructions[index + i]
            if !instrPattern.matches(insn) {
                return nil
            }
            matchedInstructions.append(insn)
        }

        // All patterns matched
        let replacement = pattern.replacement(matchedInstructions)
        let idiom = Idiom(
            category: pattern.category,
            name: pattern.name,
            description: pattern.description,
            startAddress: matchedInstructions.first!.address,
            endAddress: matchedInstructions.last!.address + UInt64(matchedInstructions.last!.size),
            replacement: replacement,
            confidence: pattern.confidence,
            matchedInstructions: matchedInstructions
        )

        return PatternMatch(idiom: idiom, instructions: matchedInstructions)
    }

    private func detectSingleInstructionIdiom(_ insn: Instruction) -> Idiom? {
        // BSWAP - byte swap
        if insn.mnemonic.lowercased() == "bswap" {
            return Idiom(
                category: .bitManipulation,
                name: "byte swap",
                description: "Reverse byte order (endianness swap)",
                startAddress: insn.address,
                endAddress: insn.address + UInt64(insn.size),
                replacement: "\(insn.operands) = bswap(\(insn.operands));",
                confidence: 1.0,
                matchedInstructions: [insn]
            )
        }

        // POPCNT - population count
        if insn.mnemonic.lowercased() == "popcnt" {
            let parts = insn.operands.split(separator: ",")
            if parts.count >= 2 {
                let dest = parts[0].trimmingCharacters(in: .whitespaces)
                let src = parts[1].trimmingCharacters(in: .whitespaces)
                return Idiom(
                    category: .bitManipulation,
                    name: "population count",
                    description: "Count set bits",
                    startAddress: insn.address,
                    endAddress: insn.address + UInt64(insn.size),
                    replacement: "\(dest) = popcount(\(src));",
                    confidence: 1.0,
                    matchedInstructions: [insn]
                )
            }
        }

        // LZCNT/BSR - leading zeros
        if insn.mnemonic.lowercased() == "lzcnt" || insn.mnemonic.lowercased() == "bsr" {
            let parts = insn.operands.split(separator: ",")
            if parts.count >= 2 {
                let dest = parts[0].trimmingCharacters(in: .whitespaces)
                let src = parts[1].trimmingCharacters(in: .whitespaces)
                return Idiom(
                    category: .bitManipulation,
                    name: "count leading zeros",
                    description: "Count leading zero bits",
                    startAddress: insn.address,
                    endAddress: insn.address + UInt64(insn.size),
                    replacement: "\(dest) = clz(\(src));",
                    confidence: 1.0,
                    matchedInstructions: [insn]
                )
            }
        }

        // TZCNT/BSF - trailing zeros
        if insn.mnemonic.lowercased() == "tzcnt" || insn.mnemonic.lowercased() == "bsf" {
            let parts = insn.operands.split(separator: ",")
            if parts.count >= 2 {
                let dest = parts[0].trimmingCharacters(in: .whitespaces)
                let src = parts[1].trimmingCharacters(in: .whitespaces)
                return Idiom(
                    category: .bitManipulation,
                    name: "count trailing zeros",
                    description: "Count trailing zero bits",
                    startAddress: insn.address,
                    endAddress: insn.address + UInt64(insn.size),
                    replacement: "\(dest) = ctz(\(src));",
                    confidence: 1.0,
                    matchedInstructions: [insn]
                )
            }
        }

        // CPUID
        if insn.mnemonic.lowercased() == "cpuid" {
            return Idiom(
                category: .systemCall,
                name: "cpuid",
                description: "CPU identification",
                startAddress: insn.address,
                endAddress: insn.address + UInt64(insn.size),
                replacement: "cpuid(eax);  // Returns in eax, ebx, ecx, edx",
                confidence: 1.0,
                matchedInstructions: [insn]
            )
        }

        // RDTSC - read timestamp counter
        if insn.mnemonic.lowercased() == "rdtsc" {
            return Idiom(
                category: .systemCall,
                name: "rdtsc",
                description: "Read CPU timestamp counter",
                startAddress: insn.address,
                endAddress: insn.address + UInt64(insn.size),
                replacement: "timestamp = rdtsc();",
                confidence: 1.0,
                matchedInstructions: [insn]
            )
        }

        return nil
    }

    private func parseNumber(_ str: String) -> Int64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("0x") || s.hasPrefix("0X") {
            return Int64(s.dropFirst(2), radix: 16)
        }
        return Int64(s)
    }
}

// MARK: - Library Function Recognizer

/// Recognizes common library functions by their implementation patterns
class LibraryFunctionRecognizer {

    struct LibraryFunction {
        let name: String
        let library: String
        let signature: String
        let confidence: Double
    }

    /// Try to identify a function based on its implementation
    func identify(function: Function, binary: BinaryFile) -> LibraryFunction? {
        let instructions = function.basicBlocks.flatMap { $0.instructions }

        // Check for various patterns
        if let result = checkStrcmp(instructions) { return result }
        if let result = checkStrlen(instructions) { return result }
        if let result = checkMemcpy(instructions) { return result }
        if let result = checkMemset(instructions) { return result }
        if let result = checkMalloc(instructions) { return result }
        if let result = checkFree(instructions) { return result }

        return nil
    }

    private func checkStrcmp(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: Load bytes from two strings, compare, loop until mismatch or null
        var hasDoubleLoad = false
        var hasCompare = false
        var hasConditionalOnZero = false

        for insn in instructions {
            if insn.type == .load {
                hasDoubleLoad = true
            }
            if insn.type == .compare {
                hasCompare = true
            }
            if insn.type == .conditionalJump && insn.mnemonic.lowercased().contains("z") {
                hasConditionalOnZero = true
            }
        }

        if hasDoubleLoad && hasCompare && hasConditionalOnZero && instructions.count < 30 {
            return LibraryFunction(
                name: "strcmp",
                library: "libc",
                signature: "int strcmp(const char *s1, const char *s2)",
                confidence: 0.7
            )
        }

        return nil
    }

    private func checkStrlen(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: Load byte, check for zero, increment counter/pointer
        var hasLoadByte = false
        var hasZeroCheck = false
        var hasIncrement = false

        for insn in instructions {
            if insn.type == .load && (insn.operands.contains("byte") || insn.mnemonic.lowercased().contains("b")) {
                hasLoadByte = true
            }
            if insn.type == .compare && insn.operands.contains("0") {
                hasZeroCheck = true
            }
            if insn.type == .arithmetic && (insn.mnemonic.lowercased() == "inc" ||
                (insn.mnemonic.lowercased() == "add" && insn.operands.contains("1"))) {
                hasIncrement = true
            }
        }

        if hasLoadByte && hasZeroCheck && hasIncrement && instructions.count < 20 {
            return LibraryFunction(
                name: "strlen",
                library: "libc",
                signature: "size_t strlen(const char *s)",
                confidence: 0.75
            )
        }

        return nil
    }

    private func checkMemcpy(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: rep movsb/movsq or load/store loop
        for insn in instructions {
            if insn.mnemonic.lowercased() == "rep" && insn.operands.lowercased().contains("movs") {
                return LibraryFunction(
                    name: "memcpy",
                    library: "libc",
                    signature: "void *memcpy(void *dest, const void *src, size_t n)",
                    confidence: 0.9
                )
            }
        }

        return nil
    }

    private func checkMemset(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: rep stosb/stosq
        for insn in instructions {
            if insn.mnemonic.lowercased() == "rep" && insn.operands.lowercased().contains("stos") {
                return LibraryFunction(
                    name: "memset",
                    library: "libc",
                    signature: "void *memset(void *s, int c, size_t n)",
                    confidence: 0.9
                )
            }
        }

        return nil
    }

    private func checkMalloc(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: System call for memory allocation
        for insn in instructions {
            if insn.type == .syscall || (insn.type == .call && insn.operands.lowercased().contains("mmap")) {
                if instructions.count < 50 {
                    return LibraryFunction(
                        name: "malloc",
                        library: "libc",
                        signature: "void *malloc(size_t size)",
                        confidence: 0.5
                    )
                }
            }
        }

        return nil
    }

    private func checkFree(_ instructions: [Instruction]) -> LibraryFunction? {
        // Pattern: System call for memory deallocation, typically short
        for insn in instructions {
            if insn.type == .syscall || (insn.type == .call && insn.operands.lowercased().contains("munmap")) {
                if instructions.count < 30 {
                    return LibraryFunction(
                        name: "free",
                        library: "libc",
                        signature: "void free(void *ptr)",
                        confidence: 0.5
                    )
                }
            }
        }

        return nil
    }
}

// MARK: - Loop Idiom Recognizer

/// Specialized recognizer for loop patterns
class LoopIdiomRecognizer {

    enum LoopIdiom {
        case countedLoop(counter: String, start: Int64, end: Int64, step: Int64)
        case iteratorLoop(iterator: String, container: String)
        case whileTrue
        case doWhile
        case forEach(element: String, array: String)
    }

    /// Analyze a loop and try to identify its idiom
    func analyze(loopHeader: BasicBlock, loopBlocks: [BasicBlock]) -> LoopIdiom? {
        // Look for counted loop pattern
        if let counted = detectCountedLoop(header: loopHeader, blocks: loopBlocks) {
            return counted
        }

        // Look for iterator pattern
        if let iterator = detectIteratorLoop(header: loopHeader, blocks: loopBlocks) {
            return iterator
        }

        return nil
    }

    private func detectCountedLoop(header: BasicBlock, blocks: [BasicBlock]) -> LoopIdiom? {
        // Look for: compare with constant, increment by constant
        var counter: String?
        var endValue: Int64?
        var step: Int64 = 1

        for insn in header.instructions {
            if insn.type == .compare {
                let parts = insn.operands.split(separator: ",")
                if parts.count >= 2 {
                    counter = String(parts[0]).trimmingCharacters(in: .whitespaces)
                    if let val = parseNumber(String(parts[1])) {
                        endValue = val
                    }
                }
            }
        }

        // Look for increment in loop body
        for block in blocks {
            for insn in block.instructions {
                if insn.type == .arithmetic {
                    if insn.mnemonic.lowercased() == "inc" {
                        step = 1
                    } else if insn.mnemonic.lowercased() == "add" {
                        let parts = insn.operands.split(separator: ",")
                        if parts.count >= 2, let s = parseNumber(String(parts[1])) {
                            step = s
                        }
                    }
                }
            }
        }

        if let c = counter, let end = endValue {
            return .countedLoop(counter: c, start: 0, end: end, step: step)
        }

        return nil
    }

    private func detectIteratorLoop(header: BasicBlock, blocks: [BasicBlock]) -> LoopIdiom? {
        // Look for pointer increment pattern
        for block in blocks {
            for insn in block.instructions {
                if insn.type == .load && insn.operands.contains("+") {
                    // Might be array iteration
                    let parts = insn.operands.split(separator: ",")
                    if let dest = parts.first {
                        return .iteratorLoop(
                            iterator: String(dest).trimmingCharacters(in: .whitespaces),
                            container: "array"
                        )
                    }
                }
            }
        }

        return nil
    }

    private func parseNumber(_ str: String) -> Int64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "#", with: "")
        if s.hasPrefix("0x") || s.hasPrefix("0X") {
            return Int64(s.dropFirst(2), radix: 16)
        }
        return Int64(s)
    }
}
