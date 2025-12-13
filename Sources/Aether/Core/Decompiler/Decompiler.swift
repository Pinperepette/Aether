import Foundation

/// Pseudo-code decompiler
class Decompiler {

    /// Decompile a function to pseudo-C code
    func decompile(function: Function, instructions: [Instruction], binary: BinaryFile) -> String {
        var output = ""

        // Generate function signature
        let returnType = inferReturnType(instructions: instructions, architecture: binary.architecture)
        let params = inferParameters(instructions: instructions, architecture: binary.architecture)
        let paramStr = params.isEmpty ? "void" : params.joined(separator: ", ")

        output += "\(returnType) \(function.displayName)(\(paramStr))\n"
        output += "{\n"

        // Generate local variable declarations
        let locals = inferLocalVariables(instructions: instructions, architecture: binary.architecture)
        if !locals.isEmpty {
            for local in locals {
                output += "    \(local.type) \(local.name);\n"
            }
            output += "\n"
        }

        // Decompile basic blocks
        if function.basicBlocks.isEmpty {
            // No basic blocks, just decompile instructions linearly
            output += decompileInstructions(instructions, indent: 1, binary: binary)
        } else {
            output += decompileBasicBlocks(function.basicBlocks, binary: binary)
        }

        output += "}\n"

        return output
    }

    // MARK: - Type Inference

    private func inferReturnType(instructions: [Instruction], architecture: Architecture) -> String {
        // Look at what's in the return register before ret
        for insn in instructions.reversed() {
            if insn.type == .return {
                continue
            }

            // Check if return register is set
            let returnReg = architecture.returnValueRegister
            if insn.operands.contains(returnReg) {
                // Could analyze further to determine type
                return "int"
            }

            // Check for void return (no value set)
            if insn.mnemonic == "xor" && insn.operands.contains("\(returnReg), \(returnReg)") {
                return "int"  // Returns 0
            }
        }

        return "void"
    }

    private func inferParameters(instructions: [Instruction], architecture: Architecture) -> [String] {
        var params: [String] = []
        let argRegs = architecture.argumentRegisters

        // Check which argument registers are used
        var usedArgs = Set<String>()

        for insn in instructions {
            for reg in argRegs {
                if insn.operands.contains(reg) {
                    usedArgs.insert(reg)
                }
            }
        }

        // Generate parameter list
        for (i, reg) in argRegs.enumerated() {
            if usedArgs.contains(reg) {
                params.append("int arg\(i + 1)")
            } else {
                break  // Arguments are passed in order
            }
        }

        return params
    }

    private func inferLocalVariables(instructions: [Instruction], architecture: Architecture) -> [LocalVariable] {
        var locals: [LocalVariable] = []
        var seenOffsets = Set<Int>()

        // Look for stack-relative accesses
        let stackReg = architecture.stackPointerName
        let frameReg = architecture.framePointerName

        for insn in instructions {
            // Parse stack offsets from operands
            let operands = insn.operands

            // Pattern: [rbp - 0x10] or [rsp + 0x20]
            if let match = operands.range(of: "\\[\(frameReg) - (0x[0-9a-fA-F]+|\\d+)\\]", options: .regularExpression) {
                let offsetStr = String(operands[match])
                    .replacingOccurrences(of: "[\(frameReg) - ", with: "")
                    .replacingOccurrences(of: "]", with: "")

                let offset: Int
                if offsetStr.hasPrefix("0x") {
                    offset = Int(offsetStr.dropFirst(2), radix: 16) ?? 0
                } else {
                    offset = Int(offsetStr) ?? 0
                }

                if offset > 0 && !seenOffsets.contains(offset) {
                    seenOffsets.insert(offset)
                    locals.append(LocalVariable(
                        name: "var_\(String(format: "%X", offset))",
                        type: "int",
                        stackOffset: -offset,
                        size: 8
                    ))
                }
            }
        }

        return locals.sorted { $0.stackOffset > $1.stackOffset }
    }

    // MARK: - Instruction Decompilation

    private func decompileInstructions(_ instructions: [Instruction], indent: Int, binary: BinaryFile) -> String {
        var output = ""
        let ind = String(repeating: "    ", count: indent)

        var i = 0
        while i < instructions.count {
            let insn = instructions[i]

            // Skip NOPs
            if insn.type == .nop {
                i += 1
                continue
            }

            let line = decompileInstruction(insn, binary: binary)
            if !line.isEmpty {
                output += "\(ind)\(line)\n"
            }

            i += 1
        }

        return output
    }

    private func decompileInstruction(_ insn: Instruction, binary: BinaryFile) -> String {
        switch insn.type {
        case .call:
            return decompileCall(insn, binary: binary)
        case .return:
            return decompileReturn(insn)
        case .move:
            return decompileMove(insn)
        case .arithmetic:
            return decompileArithmetic(insn)
        case .compare:
            return decompileCompare(insn)
        case .load:
            return decompileLoad(insn, binary: binary)
        case .store:
            return decompileStore(insn)
        case .push, .pop:
            return ""  // Usually part of prologue/epilogue
        case .jump, .conditionalJump:
            return "// \(insn.text)"  // Handled by CFG
        default:
            return "// \(insn.text)"
        }
    }

    private func decompileCall(_ insn: Instruction, binary: BinaryFile) -> String {
        var funcName = "unknown"

        if let target = insn.branchTarget {
            // Look up function name
            if let symbol = binary.symbols.first(where: { $0.address == target }) {
                funcName = symbol.displayName
            } else {
                funcName = String(format: "sub_%llX", target)
            }
        } else if insn.operands.hasPrefix("x") || insn.operands.hasPrefix("r") {
            // Indirect call
            funcName = "(*\(registerToVariable(insn.operands)))"
        }

        return "\(funcName)();"
    }

    private func decompileReturn(_ insn: Instruction) -> String {
        if insn.operands.isEmpty {
            return "return;"
        }
        return "return \(insn.operands);"
    }

    private func decompileMove(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count == 2 else { return "// \(insn.text)" }

        let dest = registerToVariable(parts[0])
        let src = operandToExpression(parts[1])

        return "\(dest) = \(src);"
    }

    private func decompileArithmetic(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }

        let op: String
        switch insn.mnemonic {
        case "add": op = "+"
        case "sub": op = "-"
        case "mul", "imul": op = "*"
        case "div", "idiv": op = "/"
        case "and": op = "&"
        case "or": op = "|"
        case "xor": op = "^"
        case "shl", "sal": op = "<<"
        case "shr", "sar": op = ">>"
        default: op = insn.mnemonic
        }

        if parts.count == 2 {
            let dest = registerToVariable(parts[0])
            let src = operandToExpression(parts[1])
            return "\(dest) = \(dest) \(op) \(src);"
        } else if parts.count == 3 {
            let dest = registerToVariable(parts[0])
            let src1 = operandToExpression(parts[1])
            let src2 = operandToExpression(parts[2])
            return "\(dest) = \(src1) \(op) \(src2);"
        }

        return "// \(insn.text)"
    }

    private func decompileCompare(_ insn: Instruction) -> String {
        // Comparisons are usually followed by conditional jumps
        // We'll handle them in CFG analysis
        return "// cmp: \(insn.operands)"
    }

    private func decompileLoad(_ insn: Instruction, binary: BinaryFile) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return "// \(insn.text)" }

        let dest = registerToVariable(parts[0])
        let src = memoryToExpression(parts[1], binary: binary)

        return "\(dest) = \(src);"
    }

    private func decompileStore(_ insn: Instruction) -> String {
        let parts = insn.operands.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 2 else { return "// \(insn.text)" }

        let dest = memoryToExpression(parts[0], binary: nil)
        let src = operandToExpression(parts[1])

        return "\(dest) = \(src);"
    }

    // MARK: - Basic Block Decompilation

    private func decompileBasicBlocks(_ blocks: [BasicBlock], binary: BinaryFile) -> String {
        var output = ""

        for block in blocks {
            // Add label for non-entry blocks that are jump targets
            if block.type != .entry && !block.predecessors.isEmpty {
                output += String(format: "loc_%llX:\n", block.startAddress)
            }

            // Decompile instructions
            for insn in block.instructions {
                if insn.type == .nop { continue }

                let line = decompileInstruction(insn, binary: binary)
                if !line.isEmpty && !line.hasPrefix("//") {
                    output += "    \(line)\n"
                }
            }

            // Handle control flow
            if let lastInsn = block.instructions.last {
                switch lastInsn.type {
                case .conditionalJump:
                    if let target = lastInsn.branchTarget {
                        let cond = conditionToExpression(lastInsn.mnemonic)
                        output += "    if (\(cond)) goto \(String(format: "loc_%llX", target));\n"
                    }
                case .jump:
                    if let target = lastInsn.branchTarget {
                        output += "    goto \(String(format: "loc_%llX", target));\n"
                    }
                default:
                    break
                }
            }
        }

        return output
    }

    // MARK: - Expression Conversion

    private func registerToVariable(_ reg: String) -> String {
        let r = reg.trimmingCharacters(in: .whitespaces)

        // Map registers to variable names
        // Note: On ARM64, x0-x7 are argument registers, x0 also holds return value
        // On x86_64, rdi/rsi/rdx/rcx/r8/r9 are args, rax is return
        let regMap: [String: String] = [
            "rax": "result", "eax": "result",
            "rdi": "arg1", "edi": "arg1",
            "rsi": "arg2", "esi": "arg2",
            "rdx": "arg3", "edx": "arg3",
            "rcx": "arg4", "ecx": "arg4",
            "r8": "arg5", "r8d": "arg5",
            "r9": "arg6", "r9d": "arg6",
            // ARM64 registers - x0 used for both arg1 and return
            "x0": "arg1", "w0": "arg1",
            "x1": "arg2", "w1": "arg2",
            "x2": "arg3", "w2": "arg3",
            "x3": "arg4", "w3": "arg4",
            "x4": "arg5", "w4": "arg5",
            "x5": "arg6", "w5": "arg6",
            "x6": "arg7", "w6": "arg7",
            "x7": "arg8", "w7": "arg8",
        ]

        return regMap[r.lowercased()] ?? r
    }

    private func operandToExpression(_ operand: String) -> String {
        let op = operand.trimmingCharacters(in: .whitespaces)

        // Immediate value
        if op.hasPrefix("#") {
            return String(op.dropFirst())
        }
        if op.hasPrefix("0x") || op.first?.isNumber == true {
            return op
        }

        // Register
        return registerToVariable(op)
    }

    private func memoryToExpression(_ operand: String, binary: BinaryFile?) -> String {
        var op = operand.trimmingCharacters(in: .whitespaces)

        // Remove brackets
        if op.hasPrefix("[") && op.hasSuffix("]") {
            op = String(op.dropFirst().dropLast())
        }

        // Try to resolve to symbol name
        if let binary = binary {
            if let match = op.range(of: "0x[0-9a-fA-F]+", options: .regularExpression) {
                let addrStr = String(op[match])
                if let addr = UInt64(addrStr.dropFirst(2), radix: 16) {
                    if let symbol = binary.symbols.first(where: { $0.address == addr }) {
                        return symbol.displayName
                    }
                    if let str = binary.readString(at: addr, maxLength: 64) {
                        return "\"\(str.prefix(32))\""
                    }
                }
            }
        }

        // Format as pointer dereference
        if op.contains("+") || op.contains("-") {
            return "*(\(op))"
        }

        return "*\(registerToVariable(op))"
    }

    private func conditionToExpression(_ mnemonic: String) -> String {
        let condMap: [String: String] = [
            "je": "== 0", "jz": "== 0",
            "jne": "!= 0", "jnz": "!= 0",
            "jl": "< 0", "jb": "< 0",
            "jle": "<= 0", "jbe": "<= 0",
            "jg": "> 0", "ja": "> 0",
            "jge": ">= 0", "jae": ">= 0",
            "b.eq": "== 0", "b.ne": "!= 0",
            "b.lt": "< 0", "b.le": "<= 0",
            "b.gt": "> 0", "b.ge": ">= 0",
        ]

        return condMap[mnemonic.lowercased()] ?? "/* \(mnemonic) */"
    }
}
