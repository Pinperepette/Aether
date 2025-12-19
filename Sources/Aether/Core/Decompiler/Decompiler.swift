import Foundation

/// Enhanced pseudo-code decompiler with control flow recovery
class Decompiler {

    private let structurer = ControlFlowStructurer()
    private var binary: BinaryFile?
    private var strings: [UInt64: String] = [:]
    private var variableNames: [String: String] = [:]
    private var variableCounter = 0

    /// Decompile a function to pseudo-C code
    func decompile(function: Function, instructions: [Instruction], binary: BinaryFile) -> String {
        self.binary = binary
        self.strings = [:]
        self.variableNames = [:]
        self.variableCounter = 0

        // Build string cache
        buildStringCache(binary: binary)

        var output = ""

        // Generate function signature
        let returnType = inferReturnType(instructions: instructions, architecture: binary.architecture)
        let params = inferParameters(instructions: instructions, architecture: binary.architecture)
        let paramStr = params.isEmpty ? "void" : params.joined(separator: ", ")

        output += "// Function at \(String(format: "0x%llX", function.startAddress))\n"
        output += "// Size: \(function.size) bytes\n"
        if !function.callees.isEmpty {
            output += "// Calls: \(function.callees.prefix(5).map { String(format: "0x%llX", $0) }.joined(separator: ", "))\n"
        }
        output += "\n"

        output += "\(returnType) \(function.displayName)(\(paramStr))\n"
        output += "{\n"

        // Generate local variable declarations
        let locals = inferLocalVariables(instructions: instructions, architecture: binary.architecture)
        if !locals.isEmpty {
            for local in locals {
                output += "    \(local.type) \(local.name);  // \(local.comment)\n"
            }
            output += "\n"
        }

        // Use ControlFlowStructurer for proper structure recovery
        if !function.basicBlocks.isEmpty && function.basicBlocks.count > 1 {
            let structure = structurer.structure(function: function)
            let printer = EnhancedCodePrinter(binary: binary, strings: strings)
            output += printer.print(structure)
        } else {
            // Fallback to linear decompilation for simple functions
            output += decompileInstructions(instructions, indent: 1, binary: binary)
        }

        output += "}\n"

        return output
    }

    // MARK: - String Cache

    private func buildStringCache(binary: BinaryFile) {
        // Scan sections for strings
        for section in binary.sections {
            // Look in data sections
            if section.name.contains("cstring") || section.name.contains("string") ||
               section.name == "__const" || section.name == ".rodata" {
                scanForStrings(in: section)
            }
        }
    }

    private func scanForStrings(in section: Section) {
        var offset = 0
        while offset < section.data.count {
            var bytes: [UInt8] = []
            var currentOffset = offset

            // Read until null terminator
            while currentOffset < section.data.count {
                let byte = section.data[section.data.startIndex + currentOffset]
                if byte == 0 { break }
                bytes.append(byte)
                currentOffset += 1
            }

            // Only keep printable ASCII strings of reasonable length
            if bytes.count >= 4, let str = String(bytes: bytes, encoding: .utf8) {
                let isPrintable = str.allSatisfy { $0.isASCII && ($0.isPunctuation || $0.isLetter || $0.isNumber || $0.isWhitespace) }
                if isPrintable {
                    let address = section.address + UInt64(offset)
                    strings[address] = str
                }
            }

            offset = currentOffset + 1  // Skip null terminator
        }
    }

    // MARK: - Type Inference

    private func inferReturnType(instructions: [Instruction], architecture: Architecture) -> String {
        for insn in instructions.reversed() {
            if insn.type == .return {
                continue
            }

            let returnReg = architecture.returnValueRegister
            if insn.operands.lowercased().contains(returnReg.lowercased()) {
                // Check what type of operation
                if insn.mnemonic.lowercased().contains("movs") || insn.mnemonic.lowercased().contains("cvt") {
                    return "double"
                }
                if insn.operands.contains("byte") || insn.operands.contains("BYTE") {
                    return "char"
                }
                return "int64_t"
            }

            // XOR with self = return 0
            if insn.mnemonic == "xor" {
                let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).lowercased() }
                if parts.count == 2 && parts[0] == parts[1] && parts[0] == returnReg.lowercased() {
                    return "int"
                }
            }
        }

        return "void"
    }

    private func inferParameters(instructions: [Instruction], architecture: Architecture) -> [String] {
        var params: [String] = []
        let argRegs = architecture.argumentRegisters

        var usedArgs: [String: String] = [:] // reg -> inferred type

        for insn in instructions {
            let operands = insn.operands.lowercased()
            for (i, reg) in argRegs.enumerated() {
                if operands.contains(reg.lowercased()) {
                    let type = inferOperandType(insn: insn, operand: reg)
                    usedArgs[reg] = type
                }
            }
        }

        for (i, reg) in argRegs.enumerated() {
            if let type = usedArgs[reg] {
                let paramName = "arg\(i + 1)"
                params.append("\(type) \(paramName)")
            } else if usedArgs.keys.contains(where: { argRegs.firstIndex(of: $0) ?? 0 > i }) {
                // There's a higher numbered arg used, so this one must exist too
                params.append("int64_t arg\(i + 1)")
            } else {
                break
            }
        }

        return params
    }

    private func inferOperandType(insn: Instruction, operand: String) -> String {
        let mnem = insn.mnemonic.lowercased()

        // Floating point operations
        if mnem.hasPrefix("movs") || mnem.hasPrefix("cvt") || mnem.hasPrefix("add") && mnem.hasSuffix("s") {
            return "double"
        }

        // String operations often use pointers
        if mnem == "lea" {
            return "char*"
        }

        // Memory operations suggest pointers
        if insn.operands.contains("[") {
            return "void*"
        }

        return "int64_t"
    }

    private func inferLocalVariables(instructions: [Instruction], architecture: Architecture) -> [DecompilerLocalVar] {
        var locals: [DecompilerLocalVar] = []
        var seenOffsets = Set<Int>()

        let frameReg = architecture.framePointerName.lowercased()
        let stackReg = architecture.stackPointerName.lowercased()

        for insn in instructions {
            let operands = insn.operands.lowercased()

            // Pattern: [rbp - 0x10] or [rbp + 0x10] or [rsp + 0x20]
            let patterns = [
                "\\[\(frameReg) - (0x[0-9a-fA-F]+|\\d+)\\]",
                "\\[\(frameReg) \\+ (0x[0-9a-fA-F]+|\\d+)\\]",
                "\\[\(stackReg) \\+ (0x[0-9a-fA-F]+|\\d+)\\]"
            ]

            for pattern in patterns {
                if let match = operands.range(of: pattern, options: .regularExpression) {
                    let matchStr = String(operands[match])
                    let isSubtract = matchStr.contains("-")

                    // Extract offset value
                    if let numMatch = matchStr.range(of: "0x[0-9a-fA-F]+|\\d+", options: .regularExpression) {
                        let offsetStr = String(matchStr[numMatch])
                        let offset: Int
                        if offsetStr.hasPrefix("0x") {
                            offset = Int(offsetStr.dropFirst(2), radix: 16) ?? 0
                        } else {
                            offset = Int(offsetStr) ?? 0
                        }

                        let stackOffset = isSubtract ? -offset : offset

                        if offset > 0 && !seenOffsets.contains(stackOffset) {
                            seenOffsets.insert(stackOffset)

                            let varName = isSubtract ? "var_\(String(format: "%X", offset))" : "arg_\(String(format: "%X", offset))"
                            let varType = inferLocalType(insn: insn)
                            let comment = String(format: "[%@ %@ 0x%X]", isSubtract ? frameReg : stackReg, isSubtract ? "-" : "+", offset)

                            locals.append(DecompilerLocalVar(
                                name: varName,
                                type: varType,
                                stackOffset: stackOffset,
                                size: 8,
                                comment: comment
                            ))
                        }
                    }
                }
            }
        }

        return locals.sorted { $0.stackOffset > $1.stackOffset }
    }

    private func inferLocalType(insn: Instruction) -> String {
        let mnem = insn.mnemonic.lowercased()

        if mnem.contains("movs") || mnem.contains("cvt") {
            return "double"
        }
        if mnem == "movzx" || mnem == "movsx" {
            if insn.operands.contains("byte") || insn.operands.contains("BYTE") {
                return "uint8_t"
            }
            if insn.operands.contains("word") || insn.operands.contains("WORD") {
                return "uint16_t"
            }
        }
        if mnem == "lea" {
            return "void*"
        }

        return "int64_t"
    }

    // MARK: - Instruction Decompilation

    private func decompileInstructions(_ instructions: [Instruction], indent: Int, binary: BinaryFile) -> String {
        var output = ""
        let ind = String(repeating: "    ", count: indent)

        var i = 0
        while i < instructions.count {
            let insn = instructions[i]

            // Skip NOPs and prologue/epilogue
            if insn.type == .nop || isPrologueEpilogue(insn) {
                i += 1
                continue
            }

            // Try to combine compare + conditional jump into if statement
            if insn.type == .compare && i + 1 < instructions.count {
                let nextInsn = instructions[i + 1]
                if nextInsn.type == .conditionalJump {
                    let condition = buildCondition(cmp: insn, jump: nextInsn)
                    let targetLabel = nextInsn.branchTarget.map { String(format: "loc_%llX", $0) } ?? "unknown"
                    output += "\(ind)if (\(condition)) goto \(targetLabel);\n"
                    i += 2
                    continue
                }
            }

            let line = decompileInstruction(insn, binary: binary)
            if !line.isEmpty {
                output += "\(ind)\(line)\n"
            }

            i += 1
        }

        return output
    }

    private func isPrologueEpilogue(_ insn: Instruction) -> Bool {
        let mnem = insn.mnemonic.lowercased()
        let ops = insn.operands.lowercased()

        // Common prologue patterns
        if mnem == "push" && (ops == "rbp" || ops == "ebp") { return true }
        if mnem == "mov" && (ops.contains("rbp, rsp") || ops.contains("ebp, esp")) { return true }
        if mnem == "sub" && (ops.contains("rsp,") || ops.contains("esp,")) { return true }

        // Common epilogue patterns
        if mnem == "pop" && (ops == "rbp" || ops == "ebp") { return true }
        if mnem == "leave" { return true }

        // ARM64 patterns
        if mnem == "stp" && ops.contains("x29, x30") { return true }
        if mnem == "ldp" && ops.contains("x29, x30") { return true }

        return false
    }

    private func buildCondition(cmp: Instruction, jump: Instruction) -> String {
        let parts = cmp.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return "condition" }

        let left = registerToVariable(parts[0])
        let right = operandToExpression(parts[1])

        let op: String
        switch jump.mnemonic.lowercased() {
        case "je", "jz", "b.eq": op = "=="
        case "jne", "jnz", "b.ne": op = "!="
        case "jl", "jnge", "b.lt": op = "<"
        case "jle", "jng", "b.le": op = "<="
        case "jg", "jnle", "b.gt": op = ">"
        case "jge", "jnl", "b.ge": op = ">="
        case "jb", "jnae", "b.lo": op = "<"  // unsigned
        case "jbe", "jna", "b.ls": op = "<="
        case "ja", "jnbe", "b.hi": op = ">"
        case "jae", "jnb", "b.hs": op = ">="
        default: op = "??"
        }

        return "\(left) \(op) \(right)"
    }

    private func decompileInstruction(_ insn: Instruction, binary: BinaryFile) -> String {
        switch insn.type {
        case .call:
            return decompileCall(insn, binary: binary)
        case .return:
            return decompileReturn(insn, binary: binary)
        case .move:
            return decompileMove(insn, binary: binary)
        case .arithmetic:
            return decompileArithmetic(insn)
        case .logic:
            return decompileLogic(insn)
        case .compare:
            return ""  // Handled in combination with jump
        case .load:
            return decompileLoad(insn, binary: binary)
        case .store:
            return decompileStore(insn, binary: binary)
        case .push, .pop:
            return ""  // Usually part of prologue/epilogue
        case .jump:
            if let target = insn.branchTarget {
                return String(format: "goto loc_%llX;", target)
            }
            return "// \(insn.text)"
        case .conditionalJump:
            return "// \(insn.text)"  // Should be handled with compare
        case .nop:
            return ""
        default:
            return "// \(insn.text)"
        }
    }

    private func decompileCall(_ insn: Instruction, binary: BinaryFile) -> String {
        var funcName = "unknown"
        var args = ""

        if let target = insn.branchTarget {
            // Look up function name from symbols
            if let symbol = binary.symbols.first(where: { $0.address == target }) {
                funcName = symbol.displayName
            } else {
                funcName = String(format: "sub_%llX", target)
            }

            // Check for string arguments (common in printf, puts, etc.)
            if funcName.contains("print") || funcName.contains("puts") || funcName.contains("log") || funcName.contains("str") {
                // Try to find string argument
                if let strArg = findStringArgument(near: insn.address, binary: binary) {
                    args = "\"\(escapeString(strArg))\""
                }
            }
        } else if insn.operands.hasPrefix("x") || insn.operands.hasPrefix("r") {
            // Indirect call through register
            funcName = "(*\(registerToVariable(insn.operands)))"
        }

        if args.isEmpty {
            // Generic arguments based on calling convention
            args = "/* args */"
        }

        return "\(funcName)(\(args));"
    }

    private func findStringArgument(near address: UInt64, binary: BinaryFile) -> String? {
        // Look for LEA instruction loading string address in the vicinity
        // This is a heuristic - real implementation would track data flow
        for (strAddr, strValue) in strings {
            // Check if string is referenced near this call
            if strAddr > address - 100 && strAddr < address + 100 {
                return strValue
            }
        }
        return nil
    }

    private func escapeString(_ str: String) -> String {
        var result = str
        result = result.replacingOccurrences(of: "\\", with: "\\\\")
        result = result.replacingOccurrences(of: "\"", with: "\\\"")
        result = result.replacingOccurrences(of: "\n", with: "\\n")
        result = result.replacingOccurrences(of: "\r", with: "\\r")
        result = result.replacingOccurrences(of: "\t", with: "\\t")
        return result
    }

    private func decompileReturn(_ insn: Instruction, binary: BinaryFile) -> String {
        // Check return register for value
        let returnReg = binary.architecture.returnValueRegister.lowercased()

        // Simple heuristic: if not void function, return the result
        return "return result;"
    }

    private func decompileMove(_ insn: Instruction, binary: BinaryFile) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2 else { return "// \(insn.text)" }

        let dest = registerToVariable(parts[0])
        var src = operandToExpression(parts[1])

        // Check if source is a string address
        if let addr = parseAddress(parts[1]) {
            if let str = strings[addr] {
                src = "\"\(escapeString(str.prefix(40).description))\""
            } else if let symbol = binary.symbols.first(where: { $0.address == addr }) {
                src = "&\(symbol.displayName)"
            }
        }

        // Skip self-moves
        if dest == src { return "" }

        return "\(dest) = \(src);"
    }

    private func decompileArithmetic(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        let op: String
        switch insn.mnemonic.lowercased() {
        case "add": op = "+"
        case "sub": op = "-"
        case "mul", "imul": op = "*"
        case "div", "idiv": op = "/"
        case "inc":
            if parts.count >= 1 {
                let dest = registerToVariable(parts[0])
                return "\(dest)++;"
            }
            return "// \(insn.text)"
        case "dec":
            if parts.count >= 1 {
                let dest = registerToVariable(parts[0])
                return "\(dest)--;"
            }
            return "// \(insn.text)"
        case "neg":
            if parts.count >= 1 {
                let dest = registerToVariable(parts[0])
                return "\(dest) = -\(dest);"
            }
            return "// \(insn.text)"
        default: op = insn.mnemonic
        }

        if parts.count == 2 {
            let dest = registerToVariable(parts[0])
            let src = operandToExpression(parts[1])
            return "\(dest) \(op)= \(src);"
        } else if parts.count == 3 {
            let dest = registerToVariable(parts[0])
            let src1 = operandToExpression(parts[1])
            let src2 = operandToExpression(parts[2])
            return "\(dest) = \(src1) \(op) \(src2);"
        }

        return "// \(insn.text)"
    }

    private func decompileLogic(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        let op: String
        switch insn.mnemonic.lowercased() {
        case "and": op = "&"
        case "or": op = "|"
        case "xor":
            // XOR with self is zero
            if parts.count == 2 && parts[0].lowercased() == parts[1].lowercased() {
                let dest = registerToVariable(parts[0])
                return "\(dest) = 0;"
            }
            op = "^"
        case "not":
            if parts.count >= 1 {
                let dest = registerToVariable(parts[0])
                return "\(dest) = ~\(dest);"
            }
            return "// \(insn.text)"
        case "shl", "sal": op = "<<"
        case "shr": op = ">>"
        case "sar": op = ">>"  // arithmetic shift
        default: op = insn.mnemonic
        }

        if parts.count == 2 {
            let dest = registerToVariable(parts[0])
            let src = operandToExpression(parts[1])
            return "\(dest) \(op)= \(src);"
        } else if parts.count == 3 {
            let dest = registerToVariable(parts[0])
            let src1 = operandToExpression(parts[1])
            let src2 = operandToExpression(parts[2])
            return "\(dest) = \(src1) \(op) \(src2);"
        }

        return "// \(insn.text)"
    }

    private func decompileLoad(_ insn: Instruction, binary: BinaryFile) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return "// \(insn.text)" }

        let dest = registerToVariable(parts[0])
        let src = memoryToExpression(parts[1], binary: binary)

        // LEA is address calculation, not load
        if insn.mnemonic.lowercased() == "lea" {
            // Check if loading string address
            if let addr = parseAddressFromMemory(parts[1]) {
                if let str = strings[addr] {
                    return "\(dest) = \"\(escapeString(str.prefix(40).description))\";"
                }
                if let symbol = binary.symbols.first(where: { $0.address == addr }) {
                    return "\(dest) = &\(symbol.displayName);"
                }
            }
            return "\(dest) = &\(src.replacingOccurrences(of: "*", with: ""));"
        }

        return "\(dest) = \(src);"
    }

    private func decompileStore(_ insn: Instruction, binary: BinaryFile) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return "// \(insn.text)" }

        let dest = memoryToExpression(parts[0], binary: binary)
        let src = operandToExpression(parts[1])

        return "\(dest) = \(src);"
    }

    // MARK: - Expression Conversion

    private func registerToVariable(_ reg: String) -> String {
        let r = reg.trimmingCharacters(in: .whitespaces).lowercased()

        let regMap: [String: String] = [
            // x86_64
            "rax": "result", "eax": "result", "ax": "result", "al": "result",
            "rdi": "arg1", "edi": "arg1",
            "rsi": "arg2", "esi": "arg2",
            "rdx": "arg3", "edx": "arg3",
            "rcx": "arg4", "ecx": "arg4",
            "r8": "arg5", "r8d": "arg5",
            "r9": "arg6", "r9d": "arg6",
            "rbx": "rbx_saved", "ebx": "rbx_saved",
            "r10": "temp1", "r11": "temp2",
            "r12": "r12_saved", "r13": "r13_saved", "r14": "r14_saved", "r15": "r15_saved",
            // ARM64
            "x0": "result", "w0": "result",
            "x1": "arg2", "w1": "arg2",
            "x2": "arg3", "w2": "arg3",
            "x3": "arg4", "w3": "arg4",
            "x4": "arg5", "w4": "arg5",
            "x5": "arg6", "w5": "arg6",
            "x6": "arg7", "w6": "arg7",
            "x7": "arg8", "w7": "arg8",
            "x8": "indirect_result", "w8": "indirect_result",
            "x9": "temp1", "x10": "temp2", "x11": "temp3",
            "x19": "x19_saved", "x20": "x20_saved", "x21": "x21_saved",
            "x29": "frame_ptr", "x30": "link_reg",
        ]

        return regMap[r] ?? r
    }

    private func operandToExpression(_ operand: String) -> String {
        var op = operand.trimmingCharacters(in: .whitespaces)

        // ARM64 immediate
        if op.hasPrefix("#") {
            op = String(op.dropFirst())
        }

        // Hex number
        if op.lowercased().hasPrefix("0x") {
            if let val = UInt64(op.dropFirst(2), radix: 16) {
                if val < 256 {
                    return op  // Keep small hex values
                }
                // Check if it might be an ASCII value
                if val >= 0x20 && val <= 0x7E {
                    return "'\(Character(UnicodeScalar(UInt8(val))))'"
                }
                return op
            }
        }

        // Decimal number
        if op.first?.isNumber == true {
            return op
        }

        // Register
        return registerToVariable(op)
    }

    private func memoryToExpression(_ operand: String, binary: BinaryFile) -> String {
        var op = operand.trimmingCharacters(in: .whitespaces)

        // Remove brackets
        if op.hasPrefix("[") && op.hasSuffix("]") {
            op = String(op.dropFirst().dropLast())
        }

        // Parse address from operand
        if let addr = parseAddress(op) {
            // Check for string
            if let str = strings[addr] {
                return "\"\(escapeString(str.prefix(32).description))\""
            }
            // Check for symbol
            if let symbol = binary.symbols.first(where: { $0.address == addr }) {
                return symbol.displayName
            }
        }

        // Stack variable pattern: rbp - 0x10
        if op.lowercased().contains("rbp") || op.lowercased().contains("ebp") || op.lowercased().contains("x29") {
            if let match = op.range(of: "- ?(0x[0-9a-fA-F]+|\\d+)", options: .regularExpression) {
                let offsetStr = String(op[match]).replacingOccurrences(of: "- ", with: "").replacingOccurrences(of: "-", with: "")
                let offset: Int
                if offsetStr.lowercased().hasPrefix("0x") {
                    offset = Int(offsetStr.dropFirst(2), radix: 16) ?? 0
                } else {
                    offset = Int(offsetStr) ?? 0
                }
                return "var_\(String(format: "%X", offset))"
            }
            if let match = op.range(of: "\\+ ?(0x[0-9a-fA-F]+|\\d+)", options: .regularExpression) {
                let offsetStr = String(op[match]).replacingOccurrences(of: "+ ", with: "").replacingOccurrences(of: "+", with: "")
                let offset: Int
                if offsetStr.lowercased().hasPrefix("0x") {
                    offset = Int(offsetStr.dropFirst(2), radix: 16) ?? 0
                } else {
                    offset = Int(offsetStr) ?? 0
                }
                return "arg_\(String(format: "%X", offset))"
            }
        }

        // Complex addressing mode: base + index * scale + disp
        let mapped = op.split(separator: " ").map { part -> String in
            let p = String(part)
            if p == "+" || p == "-" || p == "*" { return p }
            if p.first?.isNumber == true || p.hasPrefix("0x") { return p }
            return registerToVariable(p)
        }.joined(separator: " ")

        return "*(\(mapped))"
    }

    private func parseAddress(_ str: String) -> UInt64? {
        let s = str.trimmingCharacters(in: .whitespaces)
        if s.lowercased().hasPrefix("0x") {
            return UInt64(s.dropFirst(2), radix: 16)
        }
        return UInt64(s)
    }

    private func parseAddressFromMemory(_ str: String) -> UInt64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("[") && s.hasSuffix("]") {
            s = String(s.dropFirst().dropLast())
        }

        // Look for immediate address
        if let match = s.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) {
            let addrStr = String(s[match])
            return UInt64(addrStr.dropFirst(2), radix: 16)
        }

        // RIP-relative
        if s.lowercased().contains("rip") {
            if let match = s.range(of: "[+-] ?(0x[0-9a-fA-F]+|\\d+)", options: .regularExpression) {
                let offsetStr = String(s[match])
                // Would need current instruction address to resolve this
            }
        }

        return nil
    }
}

// MARK: - Decompiler Local Variable

struct DecompilerLocalVar {
    let name: String
    let type: String
    let stackOffset: Int
    let size: Int
    var comment: String = ""
}

// MARK: - Enhanced Code Printer

/// Enhanced printer that produces cleaner pseudo-C code
class EnhancedCodePrinter {
    private let binary: BinaryFile?
    private let strings: [UInt64: String]
    private var indentLevel = 1

    init(binary: BinaryFile?, strings: [UInt64: String]) {
        self.binary = binary
        self.strings = strings
    }

    func print(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        return printStructure(structure)
    }

    private func printStructure(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        switch structure {
        case .sequence(let items):
            return items.map { printStructure($0) }.filter { !$0.isEmpty }.joined(separator: "\n")

        case .ifThen(let condition, let body):
            var result = indent() + "if (\(formatCondition(condition))) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .ifThenElse(let condition, let thenBody, let elseBody):
            var result = indent() + "if (\(formatCondition(condition))) {\n"
            indentLevel += 1
            result += printStructure(thenBody)
            indentLevel -= 1
            result += "\n" + indent() + "} else {\n"
            indentLevel += 1
            result += printStructure(elseBody)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .whileLoop(let condition, let body):
            var result = indent() + "while (\(formatCondition(condition))) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .doWhileLoop(let body, let condition):
            var result = indent() + "do {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "} while (\(formatCondition(condition)));"
            return result

        case .forLoop(let initStmt, let condition, let update, let body):
            let initStr = initStmt.map { printInline($0) } ?? ""
            let condStr = formatCondition(condition)
            let updateStr = update.map { printInline($0) } ?? ""

            var result = indent() + "for (\(initStr); \(condStr); \(updateStr)) {\n"
            indentLevel += 1
            result += printStructure(body)
            indentLevel -= 1
            result += "\n" + indent() + "}"
            return result

        case .switchCase(let value, let cases, let defaultBody):
            var result = indent() + "switch (\(value)) {\n"

            for caseItem in cases {
                let valueStr = caseItem.values.map { String($0) }.joined(separator: ", ")
                result += indent() + "case \(valueStr):\n"
                indentLevel += 1
                result += printStructure(caseItem.body)
                result += "\n" + indent() + "break;\n"
                indentLevel -= 1
            }

            if let defBody = defaultBody {
                result += indent() + "default:\n"
                indentLevel += 1
                result += printStructure(defBody)
                result += "\n" + indent() + "break;\n"
                indentLevel -= 1
            }

            result += indent() + "}"
            return result

        case .block(let basicBlock):
            return printBlock(basicBlock)

        case .breakStmt:
            return indent() + "break;"

        case .continueStmt:
            return indent() + "continue;"

        case .returnStmt(let value):
            if let v = value {
                return indent() + "return \(mapOperand(v));"
            }
            return indent() + "return;"

        case .goto(let addr):
            return indent() + String(format: "goto loc_%llX;", addr)
        }
    }

    private func printInline(_ structure: ControlFlowStructurer.ControlStructure) -> String {
        if case .block(let bb) = structure {
            for insn in bb.instructions.reversed() {
                if insn.type == .nop || insn.type == .jump || insn.type == .conditionalJump { continue }
                let line = decompileInstruction(insn)
                return line.replacingOccurrences(of: ";", with: "")
            }
        }
        return ""
    }

    private func printBlock(_ block: BasicBlock) -> String {
        var lines: [String] = []

        for insn in block.instructions {
            if insn.type == .nop { continue }
            if insn.type == .conditionalJump || insn.type == .jump { continue }
            if isPrologueEpilogue(insn) { continue }

            let line = decompileInstruction(insn)
            if !line.isEmpty {
                lines.append(indent() + line)
            }
        }

        return lines.joined(separator: "\n")
    }

    private func decompileInstruction(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        switch insn.type {
        case .move:
            guard parts.count >= 2 else { return "" }
            let dest = mapOperand(parts[0])
            let src = mapOperand(parts[1])
            if dest == src { return "" }
            return "\(dest) = \(src);"

        case .arithmetic:
            return decompileArithmetic(insn, parts: parts)

        case .logic:
            return decompileLogic(insn, parts: parts)

        case .call:
            return decompileCall(insn)

        case .return:
            return "return result;"

        case .load:
            guard parts.count >= 2 else { return "" }
            let dest = mapOperand(parts[0])
            let src = mapMemory(parts[1])
            if insn.mnemonic.lowercased() == "lea" {
                return "\(dest) = &\(src.replacingOccurrences(of: "*", with: ""));"
            }
            return "\(dest) = \(src);"

        case .store:
            guard parts.count >= 2 else { return "" }
            let dest = mapMemory(parts[0])
            let src = mapOperand(parts[1])
            return "\(dest) = \(src);"

        case .compare:
            return ""

        default:
            return ""
        }
    }

    private func decompileArithmetic(_ insn: Instruction, parts: [String]) -> String {
        let mnem = insn.mnemonic.lowercased()

        switch mnem {
        case "inc":
            guard parts.count >= 1 else { return "" }
            return "\(mapOperand(parts[0]))++;"
        case "dec":
            guard parts.count >= 1 else { return "" }
            return "\(mapOperand(parts[0]))--;"
        case "neg":
            guard parts.count >= 1 else { return "" }
            let v = mapOperand(parts[0])
            return "\(v) = -\(v);"
        default:
            break
        }

        let op: String
        switch mnem {
        case "add": op = "+"
        case "sub": op = "-"
        case "mul", "imul": op = "*"
        case "div", "idiv": op = "/"
        default: op = mnem
        }

        if parts.count == 2 {
            let dest = mapOperand(parts[0])
            let src = mapOperand(parts[1])
            return "\(dest) \(op)= \(src);"
        } else if parts.count >= 3 {
            let dest = mapOperand(parts[0])
            let src1 = mapOperand(parts[1])
            let src2 = mapOperand(parts[2])
            return "\(dest) = \(src1) \(op) \(src2);"
        }

        return ""
    }

    private func decompileLogic(_ insn: Instruction, parts: [String]) -> String {
        let mnem = insn.mnemonic.lowercased()

        // XOR with self = zero
        if mnem == "xor" && parts.count == 2 && parts[0].lowercased() == parts[1].lowercased() {
            return "\(mapOperand(parts[0])) = 0;"
        }

        let op: String
        switch mnem {
        case "and": op = "&"
        case "or": op = "|"
        case "xor": op = "^"
        case "not":
            guard parts.count >= 1 else { return "" }
            let v = mapOperand(parts[0])
            return "\(v) = ~\(v);"
        case "shl", "sal": op = "<<"
        case "shr", "sar": op = ">>"
        default: op = mnem
        }

        if parts.count == 2 {
            let dest = mapOperand(parts[0])
            let src = mapOperand(parts[1])
            return "\(dest) \(op)= \(src);"
        } else if parts.count >= 3 {
            let dest = mapOperand(parts[0])
            let src1 = mapOperand(parts[1])
            let src2 = mapOperand(parts[2])
            return "\(dest) = \(src1) \(op) \(src2);"
        }

        return ""
    }

    private func decompileCall(_ insn: Instruction) -> String {
        var funcName = "unknown"

        if let target = insn.branchTarget {
            if let sym = binary?.symbols.first(where: { $0.address == target }) {
                funcName = sym.displayName
            } else {
                funcName = String(format: "sub_%llX", target)
            }
        }

        return "\(funcName)();"
    }

    private func formatCondition(_ condition: ControlFlowStructurer.Condition) -> String {
        let left = mapOperand(condition.leftOperand)
        let right = mapOperand(condition.rightOperand)

        var cmpOp = condition.comparison.rawValue
        // Remove unsigned markers for readability
        cmpOp = cmpOp.replacingOccurrences(of: "u", with: "")

        if condition.isNegated {
            return "!(\(left) \(cmpOp) \(right))"
        }
        return "\(left) \(cmpOp) \(right)"
    }

    private func mapOperand(_ op: String) -> String {
        var o = op.trimmingCharacters(in: .whitespaces)
        if o.hasPrefix("#") { o = String(o.dropFirst()) }

        let regMap: [String: String] = [
            "rax": "result", "eax": "result",
            "rdi": "arg1", "edi": "arg1", "x0": "result", "w0": "result",
            "rsi": "arg2", "esi": "arg2", "x1": "arg2", "w1": "arg2",
            "rdx": "arg3", "edx": "arg3", "x2": "arg3", "w2": "arg3",
            "rcx": "arg4", "ecx": "arg4", "x3": "arg4", "w3": "arg4",
            "r8": "arg5", "r8d": "arg5", "x4": "arg5", "w4": "arg5",
            "r9": "arg6", "r9d": "arg6", "x5": "arg6", "w5": "arg6",
        ]

        return regMap[o.lowercased()] ?? o
    }

    private func mapMemory(_ op: String) -> String {
        var o = op
        if o.hasPrefix("[") && o.hasSuffix("]") {
            o = String(o.dropFirst().dropLast())
        }

        // Stack variable
        if o.lowercased().contains("rbp") || o.lowercased().contains("x29") {
            if let match = o.range(of: "- ?(0x[0-9a-fA-F]+|\\d+)", options: .regularExpression) {
                let offsetStr = String(o[match]).filter { $0.isHexDigit || $0 == "x" }
                return "var_\(offsetStr.uppercased())"
            }
        }

        return "*(\(mapOperand(o)))"
    }

    private func isPrologueEpilogue(_ insn: Instruction) -> Bool {
        let mnem = insn.mnemonic.lowercased()
        let ops = insn.operands.lowercased()

        if mnem == "push" && (ops == "rbp" || ops == "ebp") { return true }
        if mnem == "mov" && ops.contains("rbp, rsp") { return true }
        if mnem == "sub" && ops.contains("rsp,") { return true }
        if mnem == "pop" && ops == "rbp" { return true }
        if mnem == "leave" { return true }
        if mnem == "stp" && ops.contains("x29, x30") { return true }
        if mnem == "ldp" && ops.contains("x29, x30") { return true }

        return false
    }

    private func indent() -> String {
        String(repeating: "    ", count: indentLevel)
    }
}
