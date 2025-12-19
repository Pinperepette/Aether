import Foundation

// MARK: - Java Bytecode Decompiler

/// Decompiles JVM bytecode to Java-like pseudo-code
class JavaDecompiler {

    // MARK: - Types

    struct DecompiledMethod {
        let signature: String
        let body: String
        let localVariables: [String]
    }

    struct DecompiledClass {
        let packageName: String?
        let className: String
        let superClass: String
        let interfaces: [String]
        let fields: [String]
        let methods: [DecompiledMethod]
    }

    private enum StackValue {
        case constant(Any)
        case local(Int, String)  // index, name
        case field(String)       // field expression
        case expression(String)  // computed expression
        case arrayRef(String)    // array access expression
        case newObject(String)   // new instance
        case methodResult(String) // method call result

        var asString: String {
            switch self {
            case .constant(let v):
                if let s = v as? String { return "\"\(escapeString(s))\"" }
                if let b = v as? Bool { return b ? "true" : "false" }
                return "\(v)"
            case .local(_, let name): return name
            case .field(let expr): return expr
            case .expression(let expr): return expr
            case .arrayRef(let expr): return expr
            case .newObject(let type): return "new \(type)()"
            case .methodResult(let expr): return expr
            }
        }

        private func escapeString(_ s: String) -> String {
            return s.replacingOccurrences(of: "\\", with: "\\\\")
                    .replacingOccurrences(of: "\"", with: "\\\"")
                    .replacingOccurrences(of: "\n", with: "\\n")
                    .replacingOccurrences(of: "\t", with: "\\t")
                    .replacingOccurrences(of: "\r", with: "\\r")
        }
    }

    private struct BasicBlock {
        let startPC: Int
        var endPC: Int
        var instructions: [(Int, String, StackValue?)]  // (pc, statement, pushed value)
        var successors: [Int]
        var predecessors: [Int]
        var isLoopHeader: Bool = false
        var isTryBlock: Bool = false
        var catchPC: Int? = nil
    }

    // MARK: - Public API

    /// Decompile a Java class
    func decompile(javaClass: JARLoader.JavaClass) -> DecompiledClass {
        let fullName = javaClass.thisClass.replacingOccurrences(of: "/", with: ".")
        let parts = fullName.split(separator: ".")

        let packageName: String?
        let className: String
        if parts.count > 1 {
            packageName = parts.dropLast().joined(separator: ".")
            className = String(parts.last!)
        } else {
            packageName = nil
            className = fullName
        }

        let superClass = javaClass.superClass.replacingOccurrences(of: "/", with: ".")
        let interfaces = javaClass.interfaces.map { $0.replacingOccurrences(of: "/", with: ".") }

        // Decompile fields
        var fields: [String] = []
        for field in javaClass.fields {
            let modifiers = fieldModifiers(field.accessFlags)
            let type = parseDescriptor(field.descriptor)
            fields.append("\(modifiers)\(type) \(field.name);")
        }

        // Decompile methods
        var methods: [DecompiledMethod] = []
        for method in javaClass.methods {
            let decompiled = decompileMethodInternal(method, javaClass: javaClass)
            methods.append(decompiled)
        }

        return DecompiledClass(
            packageName: packageName,
            className: className,
            superClass: superClass,
            interfaces: interfaces,
            fields: fields,
            methods: methods
        )
    }

    /// Generate Java source code from decompiled class
    func generateSource(_ decompiledClass: DecompiledClass) -> String {
        var output = ""

        // Package declaration
        if let pkg = decompiledClass.packageName {
            output += "package \(pkg);\n\n"
        }

        // Class declaration
        var classDecl = "public class \(decompiledClass.className)"
        if decompiledClass.superClass != "java.lang.Object" && !decompiledClass.superClass.isEmpty {
            classDecl += " extends \(decompiledClass.superClass)"
        }
        if !decompiledClass.interfaces.isEmpty {
            classDecl += " implements \(decompiledClass.interfaces.joined(separator: ", "))"
        }
        output += "\(classDecl) {\n\n"

        // Fields
        for field in decompiledClass.fields {
            output += "    \(field)\n"
        }
        if !decompiledClass.fields.isEmpty {
            output += "\n"
        }

        // Methods
        for method in decompiledClass.methods {
            output += "    \(method.signature) {\n"
            let bodyLines = method.body.split(separator: "\n", omittingEmptySubsequences: false)
            for line in bodyLines {
                if !line.isEmpty {
                    output += "        \(line)\n"
                } else {
                    output += "\n"
                }
            }
            output += "    }\n\n"
        }

        output += "}\n"
        return output
    }

    // MARK: - Method Decompilation

    /// Decompile a single method (public API)
    func decompileMethod(_ method: JARLoader.MethodInfo, in javaClass: JARLoader.JavaClass) -> DecompiledMethod {
        return decompileMethodInternal(method, javaClass: javaClass)
    }

    private func decompileMethodInternal(_ method: JARLoader.MethodInfo, javaClass: JARLoader.JavaClass) -> DecompiledMethod {
        let modifiers = methodModifiers(method.accessFlags)
        let (returnType, paramTypes) = parseMethodDescriptor(method.descriptor)

        // Generate parameter names
        var params: [String] = []
        var localVarIndex = method.isStatic ? 0 : 1
        for (i, paramType) in paramTypes.enumerated() {
            params.append("\(paramType) arg\(i)")
            localVarIndex += (paramType == "long" || paramType == "double") ? 2 : 1
        }

        let signature: String
        if method.name == "<init>" {
            signature = "\(modifiers)\(javaClass.thisClass.split(separator: "/").last ?? "Unknown")(\(params.joined(separator: ", ")))"
        } else if method.name == "<clinit>" {
            signature = "static"
        } else {
            signature = "\(modifiers)\(returnType) \(method.name)(\(params.joined(separator: ", ")))"
        }

        // Decompile method body
        var body = ""
        var localVariables: [String] = []

        if method.isNative {
            body = "// native method"
        } else if method.isAbstract {
            body = "// abstract method"
        } else if let code = method.code {
            (body, localVariables) = decompileBytecode(
                code: code,
                constantPool: javaClass.constantPool,
                isStatic: method.isStatic,
                paramCount: paramTypes.count
            )
        }

        return DecompiledMethod(signature: signature, body: body, localVariables: localVariables)
    }

    private func decompileBytecode(
        code: JARLoader.CodeAttribute,
        constantPool: [JARLoader.ConstantPoolEntry],
        isStatic: Bool,
        paramCount: Int
    ) -> (String, [String]) {
        let bytecode = code.code
        var output: [String] = []
        var stack: [StackValue] = []
        var locals: [Int: String] = [:]  // local variable names
        var localTypes: [Int: String] = [:]

        // Initialize local variable names
        var localIndex = 0
        if !isStatic {
            locals[0] = "this"
            localIndex = 1
        }
        for i in 0..<paramCount {
            locals[localIndex] = "arg\(i)"
            localIndex += 1
        }

        // First pass: find branch targets for control flow
        var branchTargets = Set<Int>()
        var idx = 0
        while idx < bytecode.count {
            let opcode = bytecode[idx]
            let (_, instrSize, target) = decodeInstruction(bytecode: bytecode, pc: idx, constantPool: constantPool)

            if let t = target {
                branchTargets.insert(t)
            }

            // Handle tableswitch/lookupswitch
            if opcode == 0xAA || opcode == 0xAB {
                let padding = (4 - ((idx + 1) % 4)) % 4
                var switchIdx = idx + 1 + padding

                let defaultOffset = readInt32BE(bytecode, at: switchIdx)
                branchTargets.insert(idx + Int(defaultOffset))
                switchIdx += 4

                if opcode == 0xAA { // tableswitch
                    let low = readInt32BE(bytecode, at: switchIdx)
                    let high = readInt32BE(bytecode, at: switchIdx + 4)
                    switchIdx += 8
                    for _ in low...high {
                        let offset = readInt32BE(bytecode, at: switchIdx)
                        branchTargets.insert(idx + Int(offset))
                        switchIdx += 4
                    }
                } else { // lookupswitch
                    let npairs = readInt32BE(bytecode, at: switchIdx)
                    switchIdx += 4
                    for _ in 0..<npairs {
                        switchIdx += 4 // skip match
                        let offset = readInt32BE(bytecode, at: switchIdx)
                        branchTargets.insert(idx + Int(offset))
                        switchIdx += 4
                    }
                }
            }

            idx += instrSize
        }

        // Second pass: decompile
        idx = 0
        var instructionCount = 0
        while idx < bytecode.count {
            // Add label for branch targets
            if branchTargets.contains(idx) {
                output.append("label_\(idx):")
            }

            let opcode = bytecode[idx]
            let (statement, instrSize, _) = decompileInstruction(
                bytecode: bytecode,
                pc: idx,
                constantPool: constantPool,
                stack: &stack,
                locals: &locals,
                localTypes: &localTypes
            )

            if let stmt = statement, !stmt.isEmpty {
                output.append(stmt)
            } else {
                // For debugging - show what instruction was processed
                let stackDesc = stack.suffix(3).map { $0.asString }.joined(separator: ", ")
                output.append("// [0x\(String(format: "%02X", opcode))] stack: [\(stackDesc)]")
            }

            idx += instrSize
            instructionCount += 1

            // Safety limit
            if instructionCount > 10000 {
                output.append("// ... truncated (too many instructions)")
                break
            }
        }

        // Generate local variable declarations
        var localVarDecls: [String] = []
        for (varIdx, varType) in localTypes.sorted(by: { $0.key < $1.key }) {
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if !varName.hasPrefix("arg") && varName != "this" {
                localVarDecls.append("\(varType) \(varName);")
            }
        }

        var finalOutput = ""
        if !localVarDecls.isEmpty {
            finalOutput = localVarDecls.joined(separator: "\n") + "\n\n"
        }
        finalOutput += output.joined(separator: "\n")

        return (finalOutput, Array(locals.values))
    }

    // MARK: - Instruction Decoding

    private func decodeInstruction(
        bytecode: Data,
        pc: Int,
        constantPool: [JARLoader.ConstantPoolEntry]
    ) -> (mnemonic: String, size: Int, branchTarget: Int?) {
        guard pc < bytecode.count else { return ("", 1, nil) }

        let opcode = bytecode[pc]

        switch opcode {
        // Constants
        case 0x00: return ("nop", 1, nil)
        case 0x01: return ("aconst_null", 1, nil)
        case 0x02...0x08: return ("iconst_\(Int(opcode) - 3)", 1, nil)
        case 0x09, 0x0A: return ("lconst_\(Int(opcode) - 9)", 1, nil)
        case 0x0B...0x0D: return ("fconst_\(Int(opcode) - 11)", 1, nil)
        case 0x0E, 0x0F: return ("dconst_\(Int(opcode) - 14)", 1, nil)
        case 0x10: return ("bipush", 2, nil)
        case 0x11: return ("sipush", 3, nil)
        case 0x12: return ("ldc", 2, nil)
        case 0x13: return ("ldc_w", 3, nil)
        case 0x14: return ("ldc2_w", 3, nil)

        // Loads
        case 0x15: return ("iload", 2, nil)
        case 0x16: return ("lload", 2, nil)
        case 0x17: return ("fload", 2, nil)
        case 0x18: return ("dload", 2, nil)
        case 0x19: return ("aload", 2, nil)
        case 0x1A...0x1D: return ("iload_\(Int(opcode) - 0x1A)", 1, nil)
        case 0x1E...0x21: return ("lload_\(Int(opcode) - 0x1E)", 1, nil)
        case 0x22...0x25: return ("fload_\(Int(opcode) - 0x22)", 1, nil)
        case 0x26...0x29: return ("dload_\(Int(opcode) - 0x26)", 1, nil)
        case 0x2A...0x2D: return ("aload_\(Int(opcode) - 0x2A)", 1, nil)
        case 0x2E...0x35: return ("xaload", 1, nil)

        // Stores
        case 0x36: return ("istore", 2, nil)
        case 0x37: return ("lstore", 2, nil)
        case 0x38: return ("fstore", 2, nil)
        case 0x39: return ("dstore", 2, nil)
        case 0x3A: return ("astore", 2, nil)
        case 0x3B...0x3E: return ("istore_\(Int(opcode) - 0x3B)", 1, nil)
        case 0x3F...0x42: return ("lstore_\(Int(opcode) - 0x3F)", 1, nil)
        case 0x43...0x46: return ("fstore_\(Int(opcode) - 0x43)", 1, nil)
        case 0x47...0x4A: return ("dstore_\(Int(opcode) - 0x47)", 1, nil)
        case 0x4B...0x4E: return ("astore_\(Int(opcode) - 0x4B)", 1, nil)
        case 0x4F...0x56: return ("xastore", 1, nil)

        // Stack
        case 0x57: return ("pop", 1, nil)
        case 0x58: return ("pop2", 1, nil)
        case 0x59: return ("dup", 1, nil)
        case 0x5A: return ("dup_x1", 1, nil)
        case 0x5B: return ("dup_x2", 1, nil)
        case 0x5C: return ("dup2", 1, nil)
        case 0x5D: return ("dup2_x1", 1, nil)
        case 0x5E: return ("dup2_x2", 1, nil)
        case 0x5F: return ("swap", 1, nil)

        // Math
        case 0x60: return ("iadd", 1, nil)
        case 0x61: return ("ladd", 1, nil)
        case 0x62: return ("fadd", 1, nil)
        case 0x63: return ("dadd", 1, nil)
        case 0x64: return ("isub", 1, nil)
        case 0x65: return ("lsub", 1, nil)
        case 0x66: return ("fsub", 1, nil)
        case 0x67: return ("dsub", 1, nil)
        case 0x68: return ("imul", 1, nil)
        case 0x69: return ("lmul", 1, nil)
        case 0x6A: return ("fmul", 1, nil)
        case 0x6B: return ("dmul", 1, nil)
        case 0x6C: return ("idiv", 1, nil)
        case 0x6D: return ("ldiv", 1, nil)
        case 0x6E: return ("fdiv", 1, nil)
        case 0x6F: return ("ddiv", 1, nil)
        case 0x70: return ("irem", 1, nil)
        case 0x71: return ("lrem", 1, nil)
        case 0x72: return ("frem", 1, nil)
        case 0x73: return ("drem", 1, nil)
        case 0x74: return ("ineg", 1, nil)
        case 0x75: return ("lneg", 1, nil)
        case 0x76: return ("fneg", 1, nil)
        case 0x77: return ("dneg", 1, nil)
        case 0x78: return ("ishl", 1, nil)
        case 0x79: return ("lshl", 1, nil)
        case 0x7A: return ("ishr", 1, nil)
        case 0x7B: return ("lshr", 1, nil)
        case 0x7C: return ("iushr", 1, nil)
        case 0x7D: return ("lushr", 1, nil)
        case 0x7E: return ("iand", 1, nil)
        case 0x7F: return ("land", 1, nil)
        case 0x80: return ("ior", 1, nil)
        case 0x81: return ("lor", 1, nil)
        case 0x82: return ("ixor", 1, nil)
        case 0x83: return ("lxor", 1, nil)
        case 0x84: return ("iinc", 3, nil)

        // Conversions
        case 0x85...0x93: return ("x2y", 1, nil)

        // Comparisons
        case 0x94: return ("lcmp", 1, nil)
        case 0x95, 0x96: return ("fcmpx", 1, nil)
        case 0x97, 0x98: return ("dcmpx", 1, nil)

        // Branches
        case 0x99...0x9E:
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("ifxx", 3, pc + Int(offset))
        case 0x9F...0xA6:
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("if_icmpxx", 3, pc + Int(offset))
        case 0xA7:
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("goto", 3, pc + Int(offset))
        case 0xA8:
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("jsr", 3, pc + Int(offset))
        case 0xA9: return ("ret", 2, nil)
        case 0xAA: // tableswitch
            let padding = (4 - ((pc + 1) % 4)) % 4
            var switchIdx = pc + 1 + padding
            _ = readInt32BE(bytecode, at: switchIdx)
            switchIdx += 4
            let low = readInt32BE(bytecode, at: switchIdx)
            let high = readInt32BE(bytecode, at: switchIdx + 4)
            let jumpCount = high - low + 1
            let size = 1 + padding + 4 + 4 + 4 + Int(jumpCount) * 4
            return ("tableswitch", size, nil)
        case 0xAB: // lookupswitch
            let padding = (4 - ((pc + 1) % 4)) % 4
            var switchIdx = pc + 1 + padding
            switchIdx += 4
            let npairs = readInt32BE(bytecode, at: switchIdx)
            let size = 1 + padding + 4 + 4 + Int(npairs) * 8
            return ("lookupswitch", size, nil)

        // Returns
        case 0xAC: return ("ireturn", 1, nil)
        case 0xAD: return ("lreturn", 1, nil)
        case 0xAE: return ("freturn", 1, nil)
        case 0xAF: return ("dreturn", 1, nil)
        case 0xB0: return ("areturn", 1, nil)
        case 0xB1: return ("return", 1, nil)

        // Field/method access
        case 0xB2: return ("getstatic", 3, nil)
        case 0xB3: return ("putstatic", 3, nil)
        case 0xB4: return ("getfield", 3, nil)
        case 0xB5: return ("putfield", 3, nil)
        case 0xB6: return ("invokevirtual", 3, nil)
        case 0xB7: return ("invokespecial", 3, nil)
        case 0xB8: return ("invokestatic", 3, nil)
        case 0xB9: return ("invokeinterface", 5, nil)
        case 0xBA: return ("invokedynamic", 5, nil)

        // Object creation
        case 0xBB: return ("new", 3, nil)
        case 0xBC: return ("newarray", 2, nil)
        case 0xBD: return ("anewarray", 3, nil)
        case 0xBE: return ("arraylength", 1, nil)
        case 0xBF: return ("athrow", 1, nil)
        case 0xC0: return ("checkcast", 3, nil)
        case 0xC1: return ("instanceof", 3, nil)
        case 0xC2: return ("monitorenter", 1, nil)
        case 0xC3: return ("monitorexit", 1, nil)
        case 0xC4: // wide
            if pc + 1 < bytecode.count {
                let wideOpcode = bytecode[pc + 1]
                if wideOpcode == 0x84 { return ("wide iinc", 6, nil) }
                return ("wide", 4, nil)
            }
            return ("wide", 2, nil)
        case 0xC5: return ("multianewarray", 4, nil)
        case 0xC6, 0xC7:
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("ifnull/ifnonnull", 3, pc + Int(offset))
        case 0xC8:
            var offset: Int32 = 0
            for i in 0..<4 {
                offset = (offset << 8) | Int32(bytecode[pc + 1 + i])
            }
            return ("goto_w", 5, pc + Int(offset))
        case 0xC9:
            var offset: Int32 = 0
            for i in 0..<4 {
                offset = (offset << 8) | Int32(bytecode[pc + 1 + i])
            }
            return ("jsr_w", 5, pc + Int(offset))

        default:
            return ("unknown_\(String(format: "%02X", opcode))", 1, nil)
        }
    }

    private func decompileInstruction(
        bytecode: Data,
        pc: Int,
        constantPool: [JARLoader.ConstantPoolEntry],
        stack: inout [StackValue],
        locals: inout [Int: String],
        localTypes: inout [Int: String]
    ) -> (statement: String?, size: Int, branchTarget: Int?) {
        guard pc < bytecode.count else { return (nil, 1, nil) }

        let opcode = bytecode[pc]

        switch opcode {
        // NOP
        case 0x00:
            return (nil, 1, nil)

        // Constants
        case 0x01:
            stack.append(.constant("null"))
            return (nil, 1, nil)
        case 0x02...0x08:
            stack.append(.constant(Int(opcode) - 3))
            return (nil, 1, nil)
        case 0x09, 0x0A:
            stack.append(.constant(Int64(opcode) - 9))
            return (nil, 1, nil)
        case 0x0B...0x0D:
            stack.append(.constant(Float(Int(opcode) - 11)))
            return (nil, 1, nil)
        case 0x0E, 0x0F:
            stack.append(.constant(Double(Int(opcode) - 14)))
            return (nil, 1, nil)
        case 0x10:
            let value = Int8(bitPattern: bytecode[pc + 1])
            stack.append(.constant(Int(value)))
            return (nil, 2, nil)
        case 0x11:
            let value = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            stack.append(.constant(Int(value)))
            return (nil, 3, nil)
        case 0x12: // ldc
            let index = Int(bytecode[pc + 1])
            if let value = resolveConstant(index: index, constantPool: constantPool) {
                stack.append(.constant(value))
            }
            return (nil, 2, nil)
        case 0x13: // ldc_w
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            if let value = resolveConstant(index: index, constantPool: constantPool) {
                stack.append(.constant(value))
            }
            return (nil, 3, nil)
        case 0x14: // ldc2_w
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            if let value = resolveConstant(index: index, constantPool: constantPool) {
                stack.append(.constant(value))
            }
            return (nil, 3, nil)

        // Loads
        case 0x15, 0x16, 0x17, 0x18, 0x19: // xload
            let varIdx = Int(bytecode[pc + 1])
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 2, nil)
        case 0x1A...0x1D: // iload_n
            let varIdx = Int(opcode) - 0x1A
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 1, nil)
        case 0x1E...0x21: // lload_n
            let varIdx = Int(opcode) - 0x1E
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 1, nil)
        case 0x22...0x25: // fload_n
            let varIdx = Int(opcode) - 0x22
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 1, nil)
        case 0x26...0x29: // dload_n
            let varIdx = Int(opcode) - 0x26
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 1, nil)
        case 0x2A...0x2D: // aload_n
            let varIdx = Int(opcode) - 0x2A
            let varName = locals[varIdx] ?? "var\(varIdx)"
            stack.append(.local(varIdx, varName))
            return (nil, 1, nil)

        // Array loads
        case 0x2E...0x35: // xaload
            let index = stack.popLast()?.asString ?? "?"
            let arrayRef = stack.popLast()?.asString ?? "?"
            stack.append(.arrayRef("\(arrayRef)[\(index)]"))
            return (nil, 1, nil)

        // Stores
        case 0x36, 0x37, 0x38, 0x39, 0x3A: // xstore
            let varIdx = Int(bytecode[pc + 1])
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                let typePrefix = opcode == 0x36 ? "int" : opcode == 0x37 ? "long" : opcode == 0x38 ? "float" : opcode == 0x39 ? "double" : "Object"
                localTypes[varIdx] = typePrefix
            }
            return ("\(varName) = \(value);", 2, nil)
        case 0x3B...0x3E: // istore_n
            let varIdx = Int(opcode) - 0x3B
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                localTypes[varIdx] = "int"
            }
            return ("\(varName) = \(value);", 1, nil)
        case 0x3F...0x42: // lstore_n
            let varIdx = Int(opcode) - 0x3F
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                localTypes[varIdx] = "long"
            }
            return ("\(varName) = \(value);", 1, nil)
        case 0x43...0x46: // fstore_n
            let varIdx = Int(opcode) - 0x43
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                localTypes[varIdx] = "float"
            }
            return ("\(varName) = \(value);", 1, nil)
        case 0x47...0x4A: // dstore_n
            let varIdx = Int(opcode) - 0x47
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                localTypes[varIdx] = "double"
            }
            return ("\(varName) = \(value);", 1, nil)
        case 0x4B...0x4E: // astore_n
            let varIdx = Int(opcode) - 0x4B
            let value = stack.popLast()?.asString ?? "?"
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if locals[varIdx] == nil {
                locals[varIdx] = varName
                localTypes[varIdx] = "Object"
            }
            return ("\(varName) = \(value);", 1, nil)

        // Array stores
        case 0x4F...0x56: // xastore
            let value = stack.popLast()?.asString ?? "?"
            let index = stack.popLast()?.asString ?? "?"
            let arrayRef = stack.popLast()?.asString ?? "?"
            return ("\(arrayRef)[\(index)] = \(value);", 1, nil)

        // Stack operations
        case 0x57: // pop
            let popped = stack.popLast()
            // If the popped value is a method call with side effects, output it
            if case .methodResult(let call) = popped {
                return ("\(call);", 1, nil)
            }
            return (nil, 1, nil)
        case 0x58: // pop2
            _ = stack.popLast()
            _ = stack.popLast()
            return (nil, 1, nil)
        case 0x59: // dup
            if let top = stack.last {
                stack.append(top)
            }
            return (nil, 1, nil)
        case 0x5A: // dup_x1 - duplicate top and insert two down
            if stack.count >= 2 {
                let v1 = stack.removeLast()
                let v2 = stack.removeLast()
                stack.append(v1)
                stack.append(v2)
                stack.append(v1)
            }
            return (nil, 1, nil)
        case 0x5B: // dup_x2 - duplicate top and insert three down
            if stack.count >= 3 {
                let v1 = stack.removeLast()
                let v2 = stack.removeLast()
                let v3 = stack.removeLast()
                stack.append(v1)
                stack.append(v3)
                stack.append(v2)
                stack.append(v1)
            } else if stack.count >= 2 {
                let v1 = stack.removeLast()
                let v2 = stack.removeLast()
                stack.append(v1)
                stack.append(v2)
                stack.append(v1)
            }
            return (nil, 1, nil)
        case 0x5C: // dup2 - duplicate top two
            if stack.count >= 2 {
                let v1 = stack[stack.count - 1]
                let v2 = stack[stack.count - 2]
                stack.append(v2)
                stack.append(v1)
            } else if stack.count >= 1 {
                let v1 = stack.last!
                stack.append(v1)
            }
            return (nil, 1, nil)
        case 0x5D: // dup2_x1 - duplicate top two and insert three down
            if stack.count >= 3 {
                let v1 = stack.removeLast()
                let v2 = stack.removeLast()
                let v3 = stack.removeLast()
                stack.append(v2)
                stack.append(v1)
                stack.append(v3)
                stack.append(v2)
                stack.append(v1)
            }
            return (nil, 1, nil)
        case 0x5E: // dup2_x2 - duplicate top two and insert four down
            if stack.count >= 4 {
                let v1 = stack.removeLast()
                let v2 = stack.removeLast()
                let v3 = stack.removeLast()
                let v4 = stack.removeLast()
                stack.append(v2)
                stack.append(v1)
                stack.append(v4)
                stack.append(v3)
                stack.append(v2)
                stack.append(v1)
            }
            return (nil, 1, nil)
        case 0x5F: // swap
            if stack.count >= 2 {
                let a = stack.removeLast()
                let b = stack.removeLast()
                stack.append(a)
                stack.append(b)
            }
            return (nil, 1, nil)

        // Arithmetic
        case 0x60, 0x61, 0x62, 0x63: // xadd
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) + \(b))"))
            return (nil, 1, nil)
        case 0x64, 0x65, 0x66, 0x67: // xsub
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) - \(b))"))
            return (nil, 1, nil)
        case 0x68, 0x69, 0x6A, 0x6B: // xmul
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) * \(b))"))
            return (nil, 1, nil)
        case 0x6C, 0x6D, 0x6E, 0x6F: // xdiv
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) / \(b))"))
            return (nil, 1, nil)
        case 0x70, 0x71, 0x72, 0x73: // xrem
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) % \(b))"))
            return (nil, 1, nil)
        case 0x74, 0x75, 0x76, 0x77: // xneg
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(-\(a))"))
            return (nil, 1, nil)
        case 0x78, 0x79: // xshl
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) << \(b))"))
            return (nil, 1, nil)
        case 0x7A, 0x7B: // xshr
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) >> \(b))"))
            return (nil, 1, nil)
        case 0x7C, 0x7D: // xushr
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) >>> \(b))"))
            return (nil, 1, nil)
        case 0x7E, 0x7F: // xand
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) & \(b))"))
            return (nil, 1, nil)
        case 0x80, 0x81: // xor
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) | \(b))"))
            return (nil, 1, nil)
        case 0x82, 0x83: // xxor
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(a) ^ \(b))"))
            return (nil, 1, nil)
        case 0x84: // iinc
            let varIdx = Int(bytecode[pc + 1])
            let increment = Int8(bitPattern: bytecode[pc + 2])
            let varName = locals[varIdx] ?? "var\(varIdx)"
            if increment == 1 {
                return ("\(varName)++;", 3, nil)
            } else if increment == -1 {
                return ("\(varName)--;", 3, nil)
            }
            return ("\(varName) += \(increment);", 3, nil)

        // Type conversions
        case 0x85: // i2l
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(long)\(v)"))
            return (nil, 1, nil)
        case 0x86: // i2f
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(float)\(v)"))
            return (nil, 1, nil)
        case 0x87: // i2d
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(double)\(v)"))
            return (nil, 1, nil)
        case 0x88: // l2i
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(int)\(v)"))
            return (nil, 1, nil)
        case 0x89: // l2f
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(float)\(v)"))
            return (nil, 1, nil)
        case 0x8A: // l2d
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(double)\(v)"))
            return (nil, 1, nil)
        case 0x8B: // f2i
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(int)\(v)"))
            return (nil, 1, nil)
        case 0x8C: // f2l
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(long)\(v)"))
            return (nil, 1, nil)
        case 0x8D: // f2d
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(double)\(v)"))
            return (nil, 1, nil)
        case 0x8E: // d2i
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(int)\(v)"))
            return (nil, 1, nil)
        case 0x8F: // d2l
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(long)\(v)"))
            return (nil, 1, nil)
        case 0x90: // d2f
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(float)\(v)"))
            return (nil, 1, nil)
        case 0x91: // i2b
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(byte)\(v)"))
            return (nil, 1, nil)
        case 0x92: // i2c
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(char)\(v)"))
            return (nil, 1, nil)
        case 0x93: // i2s
            let v = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(short)\(v)"))
            return (nil, 1, nil)

        // Comparisons
        case 0x94: // lcmp
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("Long.compare(\(a), \(b))"))
            return (nil, 1, nil)
        case 0x95: // fcmpl
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("Float.compare(\(a), \(b))"))
            return (nil, 1, nil)
        case 0x96: // fcmpg
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("Float.compare(\(a), \(b))"))
            return (nil, 1, nil)
        case 0x97: // dcmpl
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("Double.compare(\(a), \(b))"))
            return (nil, 1, nil)
        case 0x98: // dcmpg
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            stack.append(.expression("Double.compare(\(a), \(b))"))
            return (nil, 1, nil)

        // Branches
        case 0x99: // ifeq
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) == 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9A: // ifne
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) != 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9B: // iflt
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) < 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9C: // ifge
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) >= 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9D: // ifgt
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) > 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9E: // ifle
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) <= 0) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0x9F: // if_icmpeq
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) == \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA0: // if_icmpne
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) != \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA1: // if_icmplt
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) < \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA2: // if_icmpge
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) >= \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA3: // if_icmpgt
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) > \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA4: // if_icmple
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) <= \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA5: // if_acmpeq
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) == \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA6: // if_acmpne
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let b = stack.popLast()?.asString ?? "?"
            let a = stack.popLast()?.asString ?? "?"
            return ("if (\(a) != \(b)) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA7: // goto
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xA8: // jsr
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            return ("// jsr label_\(pc + Int(offset))", 3, pc + Int(offset))
        case 0xA9: // ret
            let varIdx = Int(bytecode[pc + 1])
            return ("// ret \(varIdx)", 2, nil)
        case 0xAA: // tableswitch
            let switchValue = stack.popLast()?.asString ?? "?"
            let padding = (4 - ((pc + 1) % 4)) % 4
            var switchIdx = pc + 1 + padding

            let defaultOffset = readInt32BE(bytecode, at: switchIdx)
            switchIdx += 4
            let low = readInt32BE(bytecode, at: switchIdx)
            let high = readInt32BE(bytecode, at: switchIdx + 4)
            switchIdx += 8

            var switchStmt = "switch (\(switchValue)) {\n"
            for i in low...high {
                let offset = readInt32BE(bytecode, at: switchIdx)
                switchStmt += "    case \(i): goto label_\(pc + Int(offset));\n"
                switchIdx += 4
            }
            switchStmt += "    default: goto label_\(pc + Int(defaultOffset));\n}"

            let jumpCount = high - low + 1
            let size = 1 + padding + 4 + 4 + 4 + Int(jumpCount) * 4
            return (switchStmt, size, nil)
        case 0xAB: // lookupswitch
            let switchValue = stack.popLast()?.asString ?? "?"
            let padding = (4 - ((pc + 1) % 4)) % 4
            var switchIdx = pc + 1 + padding

            let defaultOffset = readInt32BE(bytecode, at: switchIdx)
            switchIdx += 4
            let npairs = readInt32BE(bytecode, at: switchIdx)
            switchIdx += 4

            var switchStmt = "switch (\(switchValue)) {\n"
            for _ in 0..<npairs {
                let matchValue = readInt32BE(bytecode, at: switchIdx)
                switchIdx += 4
                let offset = readInt32BE(bytecode, at: switchIdx)
                switchIdx += 4
                switchStmt += "    case \(matchValue): goto label_\(pc + Int(offset));\n"
            }
            switchStmt += "    default: goto label_\(pc + Int(defaultOffset));\n}"

            let size = 1 + padding + 4 + 4 + Int(npairs) * 8
            return (switchStmt, size, nil)

        // Returns
        case 0xAC, 0xAD, 0xAE, 0xAF, 0xB0: // xreturn
            let value = stack.popLast()?.asString ?? "?"
            return ("return \(value);", 1, nil)
        case 0xB1: // return
            return ("return;", 1, nil)

        // Field access
        case 0xB2: // getstatic
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let (className, fieldName, _) = resolveFieldRef(index: index, constantPool: constantPool)
            stack.append(.field("\(className).\(fieldName)"))
            return (nil, 3, nil)
        case 0xB3: // putstatic
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let (className, fieldName, _) = resolveFieldRef(index: index, constantPool: constantPool)
            let value = stack.popLast()?.asString ?? "?"
            return ("\(className).\(fieldName) = \(value);", 3, nil)
        case 0xB4: // getfield
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let (_, fieldName, _) = resolveFieldRef(index: index, constantPool: constantPool)
            let objectRef = stack.popLast()?.asString ?? "?"
            stack.append(.field("\(objectRef).\(fieldName)"))
            return (nil, 3, nil)
        case 0xB5: // putfield
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let (_, fieldName, _) = resolveFieldRef(index: index, constantPool: constantPool)
            let value = stack.popLast()?.asString ?? "?"
            let objectRef = stack.popLast()?.asString ?? "?"
            return ("\(objectRef).\(fieldName) = \(value);", 3, nil)

        // Method invocation
        case 0xB6, 0xB7, 0xB8, 0xB9: // invokevirtual, invokespecial, invokestatic, invokeinterface
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let (className, methodName, descriptor) = resolveMethodRef(index: index, constantPool: constantPool)
            let (returnType, paramTypes) = parseMethodDescriptor(descriptor)

            var args: [String] = []
            for _ in 0..<paramTypes.count {
                args.insert(stack.popLast()?.asString ?? "?", at: 0)
            }

            let size = opcode == 0xB9 ? 5 : 3

            if opcode == 0xB8 { // invokestatic
                let call = "\(className).\(methodName)(\(args.joined(separator: ", ")))"
                if returnType == "void" {
                    return ("\(call);", size, nil)
                } else {
                    stack.append(.methodResult(call))
                    return (nil, size, nil)
                }
            } else {
                let objectRefValue = stack.popLast()
                let objectRef = objectRefValue?.asString ?? "?"

                if methodName == "<init>" {
                    // Constructor call - check if this is a new object pattern
                    if case .newObject(let newClassName) = objectRefValue {
                        // This is a "new X(); X.<init>()" pattern after dup
                        // The result should push the constructed object back
                        let constructedObj = "new \(newClassName)(\(args.joined(separator: ", ")))"
                        stack.append(.expression(constructedObj))
                        return (nil, size, nil)
                    } else if objectRef == "this" && opcode == 0xB7 {
                        // super() or this() call in constructor
                        if className == "java.lang.Object" || !className.contains("$") {
                            return ("super(\(args.joined(separator: ", ")));", size, nil)
                        }
                        return ("\(className).<init>(\(args.joined(separator: ", ")));", size, nil)
                    } else {
                        // Normal constructor call on existing reference
                        return ("\(objectRef).<init>(\(args.joined(separator: ", ")));", size, nil)
                    }
                }

                let call = "\(objectRef).\(methodName)(\(args.joined(separator: ", ")))"
                if returnType == "void" {
                    return ("\(call);", size, nil)
                } else {
                    stack.append(.methodResult(call))
                    return (nil, size, nil)
                }
            }

        case 0xBA: // invokedynamic
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            // invokedynamic uses InvokeDynamic constant pool entry
            let (methodName, descriptor) = resolveInvokeDynamic(index: index, constantPool: constantPool)
            let (returnType, paramTypes) = parseMethodDescriptor(descriptor)

            var args: [String] = []
            for _ in 0..<paramTypes.count {
                args.insert(stack.popLast()?.asString ?? "?", at: 0)
            }

            let call = "\(methodName)(\(args.joined(separator: ", ")))"
            if returnType == "void" {
                return ("\(call);", 5, nil)
            } else {
                stack.append(.methodResult(call))
                return (nil, 5, nil)
            }

        // Object creation
        case 0xBB: // new
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let className = resolveClassName(index: index, constantPool: constantPool)
            stack.append(.newObject(className))
            return (nil, 3, nil)
        case 0xBC: // newarray
            let atype = bytecode[pc + 1]
            let typeName: String
            switch atype {
            case 4: typeName = "boolean"
            case 5: typeName = "char"
            case 6: typeName = "float"
            case 7: typeName = "double"
            case 8: typeName = "byte"
            case 9: typeName = "short"
            case 10: typeName = "int"
            case 11: typeName = "long"
            default: typeName = "?"
            }
            let count = stack.popLast()?.asString ?? "?"
            stack.append(.expression("new \(typeName)[\(count)]"))
            return (nil, 2, nil)
        case 0xBD: // anewarray
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let className = resolveClassName(index: index, constantPool: constantPool)
            let count = stack.popLast()?.asString ?? "?"
            stack.append(.expression("new \(className)[\(count)]"))
            return (nil, 3, nil)
        case 0xBE: // arraylength
            let arrayRef = stack.popLast()?.asString ?? "?"
            stack.append(.expression("\(arrayRef).length"))
            return (nil, 1, nil)
        case 0xBF: // athrow
            let exception = stack.popLast()?.asString ?? "?"
            return ("throw \(exception);", 1, nil)
        case 0xC0: // checkcast
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let className = resolveClassName(index: index, constantPool: constantPool)
            let obj = stack.popLast()?.asString ?? "?"
            stack.append(.expression("(\(className)) \(obj)"))
            return (nil, 3, nil)
        case 0xC1: // instanceof
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let className = resolveClassName(index: index, constantPool: constantPool)
            let obj = stack.popLast()?.asString ?? "?"
            stack.append(.expression("\(obj) instanceof \(className)"))
            return (nil, 3, nil)
        case 0xC2: // monitorenter
            let obj = stack.popLast()?.asString ?? "?"
            return ("synchronized(\(obj)) { // enter", 1, nil)
        case 0xC3: // monitorexit
            return ("} // monitorexit", 1, nil)
        case 0xC4: // wide
            guard pc + 1 < bytecode.count else { return (nil, 1, nil) }
            let wideOpcode = bytecode[pc + 1]
            switch wideOpcode {
            case 0x15, 0x16, 0x17, 0x18, 0x19: // wide xload
                let varIdx = Int(bytecode[pc + 2]) << 8 | Int(bytecode[pc + 3])
                let varName = locals[varIdx] ?? "var\(varIdx)"
                stack.append(.local(varIdx, varName))
                return (nil, 4, nil)
            case 0x36, 0x37, 0x38, 0x39, 0x3A: // wide xstore
                let varIdx = Int(bytecode[pc + 2]) << 8 | Int(bytecode[pc + 3])
                let value = stack.popLast()?.asString ?? "?"
                let varName = locals[varIdx] ?? "var\(varIdx)"
                if locals[varIdx] == nil {
                    locals[varIdx] = varName
                }
                return ("\(varName) = \(value);", 4, nil)
            case 0x84: // wide iinc
                let varIdx = Int(bytecode[pc + 2]) << 8 | Int(bytecode[pc + 3])
                let increment = Int16(bitPattern: UInt16(bytecode[pc + 4]) << 8 | UInt16(bytecode[pc + 5]))
                let varName = locals[varIdx] ?? "var\(varIdx)"
                if increment == 1 {
                    return ("\(varName)++;", 6, nil)
                } else if increment == -1 {
                    return ("\(varName)--;", 6, nil)
                }
                return ("\(varName) += \(increment);", 6, nil)
            case 0xA9: // wide ret
                let varIdx = Int(bytecode[pc + 2]) << 8 | Int(bytecode[pc + 3])
                return ("// ret \(varIdx)", 4, nil)
            default:
                return ("// wide unknown 0x\(String(format: "%02X", wideOpcode))", 4, nil)
            }
        case 0xC5: // multianewarray
            let index = Int(bytecode[pc + 1]) << 8 | Int(bytecode[pc + 2])
            let dimensions = Int(bytecode[pc + 3])
            let className = resolveClassName(index: index, constantPool: constantPool)
            var dims: [String] = []
            for _ in 0..<dimensions {
                dims.insert(stack.popLast()?.asString ?? "?", at: 0)
            }
            let dimStr = dims.map { "[\($0)]" }.joined()
            stack.append(.expression("new \(className)\(dimStr)"))
            return (nil, 4, nil)
        case 0xC6: // ifnull
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) == null) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xC7: // ifnonnull
            let offset = Int16(bitPattern: UInt16(bytecode[pc + 1]) << 8 | UInt16(bytecode[pc + 2]))
            let value = stack.popLast()?.asString ?? "?"
            return ("if (\(value) != null) goto label_\(pc + Int(offset));", 3, pc + Int(offset))
        case 0xC8: // goto_w
            var offset: Int32 = 0
            for i in 0..<4 {
                offset = (offset << 8) | Int32(bytecode[pc + 1 + i])
            }
            return ("goto label_\(pc + Int(offset));", 5, pc + Int(offset))
        case 0xC9: // jsr_w
            var offset: Int32 = 0
            for i in 0..<4 {
                offset = (offset << 8) | Int32(bytecode[pc + 1 + i])
            }
            return ("// jsr label_\(pc + Int(offset))", 5, pc + Int(offset))

        default:
            let (_, size, _) = decodeInstruction(bytecode: bytecode, pc: pc, constantPool: constantPool)
            return ("// unknown opcode 0x\(String(format: "%02X", opcode))", size, nil)
        }
    }

    // MARK: - Helpers

    private func resolveConstant(index: Int, constantPool: [JARLoader.ConstantPoolEntry]) -> Any? {
        guard index > 0, index < constantPool.count else { return nil }

        switch constantPool[index] {
        case .utf8(let s): return s
        case .integer(let i): return i
        case .float(let f): return f
        case .long(let l): return l
        case .double(let d): return d
        case .stringRef(let strIdx):
            if case .utf8(let s) = constantPool[strIdx] {
                return s
            }
        case .classRef(let nameIdx):
            if case .utf8(let s) = constantPool[nameIdx] {
                return "class " + s.replacingOccurrences(of: "/", with: ".")
            }
        default:
            break
        }
        return nil
    }

    private func resolveClassName(index: Int, constantPool: [JARLoader.ConstantPoolEntry]) -> String {
        guard index > 0, index < constantPool.count else { return "?" }

        if case .classRef(let nameIdx) = constantPool[index] {
            if case .utf8(let name) = constantPool[nameIdx] {
                return name.replacingOccurrences(of: "/", with: ".")
            }
        }
        return "?"
    }

    private func resolveFieldRef(index: Int, constantPool: [JARLoader.ConstantPoolEntry]) -> (String, String, String) {
        guard index > 0, index < constantPool.count else { return ("?", "?", "?") }

        if case .fieldRef(let classIdx, let natIdx) = constantPool[index] {
            let className = resolveClassName(index: classIdx, constantPool: constantPool)

            if case .nameAndType(let nameIdx, let descIdx) = constantPool[natIdx] {
                var fieldName = "?"
                var descriptor = "?"
                if case .utf8(let n) = constantPool[nameIdx] { fieldName = n }
                if case .utf8(let d) = constantPool[descIdx] { descriptor = d }
                return (className, fieldName, descriptor)
            }
        }
        return ("?", "?", "?")
    }

    private func resolveMethodRef(index: Int, constantPool: [JARLoader.ConstantPoolEntry]) -> (String, String, String) {
        guard index > 0, index < constantPool.count else { return ("?", "?", "?") }

        let entry = constantPool[index]
        var classIdx = 0
        var natIdx = 0

        switch entry {
        case .methodRef(let ci, let ni):
            classIdx = ci
            natIdx = ni
        case .interfaceMethodRef(let ci, let ni):
            classIdx = ci
            natIdx = ni
        default:
            return ("?", "?", "?")
        }

        let className = resolveClassName(index: classIdx, constantPool: constantPool)

        if case .nameAndType(let nameIdx, let descIdx) = constantPool[natIdx] {
            var methodName = "?"
            var descriptor = "?"
            if case .utf8(let n) = constantPool[nameIdx] { methodName = n }
            if case .utf8(let d) = constantPool[descIdx] { descriptor = d }
            return (className, methodName, descriptor)
        }

        return (className, "?", "?")
    }

    private func resolveInvokeDynamic(index: Int, constantPool: [JARLoader.ConstantPoolEntry]) -> (String, String) {
        guard index > 0, index < constantPool.count else { return ("?", "?") }

        if case .invokeDynamic(_, let natIdx) = constantPool[index] {
            if case .nameAndType(let nameIdx, let descIdx) = constantPool[natIdx] {
                var methodName = "?"
                var descriptor = "?"
                if case .utf8(let n) = constantPool[nameIdx] { methodName = n }
                if case .utf8(let d) = constantPool[descIdx] { descriptor = d }
                return (methodName, descriptor)
            }
        }
        return ("?", "?")
    }

    private func parseDescriptor(_ descriptor: String) -> String {
        var idx = descriptor.startIndex
        return parseType(descriptor, idx: &idx)
    }

    private func parseType(_ descriptor: String, idx: inout String.Index) -> String {
        guard idx < descriptor.endIndex else { return "?" }

        let c = descriptor[idx]
        idx = descriptor.index(after: idx)

        switch c {
        case "B": return "byte"
        case "C": return "char"
        case "D": return "double"
        case "F": return "float"
        case "I": return "int"
        case "J": return "long"
        case "S": return "short"
        case "Z": return "boolean"
        case "V": return "void"
        case "[":
            return parseType(descriptor, idx: &idx) + "[]"
        case "L":
            var className = ""
            while idx < descriptor.endIndex && descriptor[idx] != ";" {
                className.append(descriptor[idx])
                idx = descriptor.index(after: idx)
            }
            if idx < descriptor.endIndex {
                idx = descriptor.index(after: idx) // skip ';'
            }
            return className.replacingOccurrences(of: "/", with: ".")
        default:
            return "?"
        }
    }

    private func parseMethodDescriptor(_ descriptor: String) -> (returnType: String, paramTypes: [String]) {
        var paramTypes: [String] = []
        var idx = descriptor.startIndex

        // Skip '('
        if idx < descriptor.endIndex && descriptor[idx] == "(" {
            idx = descriptor.index(after: idx)
        }

        // Parse parameters
        while idx < descriptor.endIndex && descriptor[idx] != ")" {
            paramTypes.append(parseType(descriptor, idx: &idx))
        }

        // Skip ')'
        if idx < descriptor.endIndex {
            idx = descriptor.index(after: idx)
        }

        // Parse return type
        let returnType = parseType(descriptor, idx: &idx)

        return (returnType, paramTypes)
    }

    private func fieldModifiers(_ flags: UInt16) -> String {
        var mods: [String] = []
        if flags & 0x0001 != 0 { mods.append("public") }
        if flags & 0x0002 != 0 { mods.append("private") }
        if flags & 0x0004 != 0 { mods.append("protected") }
        if flags & 0x0008 != 0 { mods.append("static") }
        if flags & 0x0010 != 0 { mods.append("final") }
        if flags & 0x0040 != 0 { mods.append("volatile") }
        if flags & 0x0080 != 0 { mods.append("transient") }
        return mods.isEmpty ? "" : mods.joined(separator: " ") + " "
    }

    private func methodModifiers(_ flags: UInt16) -> String {
        var mods: [String] = []
        if flags & 0x0001 != 0 { mods.append("public") }
        if flags & 0x0002 != 0 { mods.append("private") }
        if flags & 0x0004 != 0 { mods.append("protected") }
        if flags & 0x0008 != 0 { mods.append("static") }
        if flags & 0x0010 != 0 { mods.append("final") }
        if flags & 0x0020 != 0 { mods.append("synchronized") }
        if flags & 0x0100 != 0 { mods.append("native") }
        if flags & 0x0400 != 0 { mods.append("abstract") }
        return mods.isEmpty ? "" : mods.joined(separator: " ") + " "
    }

    private func readInt32BE(_ data: Data, at offset: Int) -> Int32 {
        guard offset + 3 < data.count else { return 0 }
        return Int32(data[offset]) << 24 |
               Int32(data[offset + 1]) << 16 |
               Int32(data[offset + 2]) << 8 |
               Int32(data[offset + 3])
    }
}
