import Foundation

// MARK: - Type Recovery System

/// Recovers high-level types from binary code analysis
class TypeRecoveryEngine {

    // MARK: - Type Definitions

    /// Represents a recovered type
    indirect enum RecoveredType: Equatable, CustomStringConvertible {
        case void
        case int8
        case int16
        case int32
        case int64
        case uint8
        case uint16
        case uint32
        case uint64
        case float32
        case float64
        case bool
        case char
        case pointer(to: RecoveredType)
        case array(of: RecoveredType, count: Int?)
        case structure(StructType)
        case union(UnionType)
        case enumeration(EnumType)
        case function(FunctionType)
        case unknown(size: Int)

        var description: String {
            switch self {
            case .void: return "void"
            case .int8: return "int8_t"
            case .int16: return "int16_t"
            case .int32: return "int32_t"
            case .int64: return "int64_t"
            case .uint8: return "uint8_t"
            case .uint16: return "uint16_t"
            case .uint32: return "uint32_t"
            case .uint64: return "uint64_t"
            case .float32: return "float"
            case .float64: return "double"
            case .bool: return "bool"
            case .char: return "char"
            case .pointer(let to): return "\(to)*"
            case .array(let of, let count):
                if let c = count {
                    return "\(of)[\(c)]"
                }
                return "\(of)[]"
            case .structure(let s): return "struct \(s.name)"
            case .union(let u): return "union \(u.name)"
            case .enumeration(let e): return "enum \(e.name)"
            case .function(let f): return f.description
            case .unknown(let size): return "unknown_\(size)"
            }
        }

        var size: Int {
            switch self {
            case .void: return 0
            case .int8, .uint8, .char, .bool: return 1
            case .int16, .uint16: return 2
            case .int32, .uint32, .float32: return 4
            case .int64, .uint64, .float64: return 8
            case .pointer: return 8  // Assuming 64-bit
            case .array(let of, let count): return of.size * (count ?? 1)
            case .structure(let s): return s.size
            case .union(let u): return u.size
            case .enumeration: return 4  // Usually int-sized
            case .function: return 8  // Function pointer
            case .unknown(let size): return size
            }
        }

        var isSigned: Bool {
            switch self {
            case .int8, .int16, .int32, .int64: return true
            default: return false
            }
        }
    }

    /// Recovered struct type
    struct StructType: Equatable {
        let name: String
        var fields: [StructField]
        var size: Int { fields.map { $0.offset + $0.type.size }.max() ?? 0 }

        static func == (lhs: StructType, rhs: StructType) -> Bool {
            lhs.name == rhs.name
        }
    }

    /// Struct field
    struct StructField: Equatable {
        let name: String
        let type: RecoveredType
        let offset: Int

        static func == (lhs: StructField, rhs: StructField) -> Bool {
            lhs.name == rhs.name && lhs.offset == rhs.offset
        }
    }

    /// Union type
    struct UnionType: Equatable {
        let name: String
        var variants: [UnionVariant]
        var size: Int { variants.map { $0.type.size }.max() ?? 0 }

        static func == (lhs: UnionType, rhs: UnionType) -> Bool {
            lhs.name == rhs.name
        }
    }

    struct UnionVariant: Equatable {
        let name: String
        let type: RecoveredType
    }

    /// Enum type
    struct EnumType: Equatable {
        let name: String
        var cases: [EnumCase]
    }

    struct EnumCase: Equatable {
        let name: String
        let value: Int64
    }

    /// Function type
    struct FunctionType: Equatable, CustomStringConvertible {
        let returnType: RecoveredType
        var parameters: [ParameterType]
        let isVariadic: Bool

        var description: String {
            let params = parameters.map { $0.description }.joined(separator: ", ")
            let variadicStr = isVariadic ? ", ..." : ""
            return "\(returnType) (*)(\(params)\(variadicStr))"
        }
    }

    struct ParameterType: Equatable, CustomStringConvertible {
        let name: String?
        let type: RecoveredType

        var description: String {
            if let n = name {
                return "\(type) \(n)"
            }
            return type.description
        }
    }

    // MARK: - Memory Access Pattern

    /// Tracks memory access patterns for type inference
    struct MemoryAccess {
        let address: UInt64
        let baseRegister: String
        let offset: Int64
        let size: Int
        let isRead: Bool
        let instruction: Instruction
    }

    /// Accumulated type information for a location
    struct TypeEvidence {
        var accessSizes: [Int] = []
        var signedOperations: Int = 0
        var unsignedOperations: Int = 0
        var pointerOperations: Int = 0
        var floatOperations: Int = 0
        var comparedValues: [Int64] = []
        var arrayAccesses: [(index: Int64, size: Int)] = []
    }

    // MARK: - Type Recovery

    private var typeEvidence: [String: TypeEvidence] = [:]  // Register/variable -> evidence
    private var memoryTypes: [Int64: RecoveredType] = [:]   // Stack offset -> type
    private var recoveredStructs: [String: StructType] = [:]

    /// Recover types for a function
    func recoverTypes(function: Function, binary: BinaryFile, dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult) -> FunctionTypeInfo {
        // Reset state
        typeEvidence = [:]
        memoryTypes = [:]

        // Analyze all instructions
        let instructions = function.basicBlocks.flatMap { $0.instructions }

        for insn in instructions {
            analyzeInstruction(insn, architecture: binary.architecture, dataFlow: dataFlow)
        }

        // Infer types from evidence
        let localTypes = inferLocalTypes()
        let paramTypes = inferParameterTypes(architecture: binary.architecture)
        let returnType = inferReturnType(function: function, architecture: binary.architecture)

        // Try to recover structures
        let structs = recoverStructures()

        return FunctionTypeInfo(
            returnType: returnType,
            parameters: paramTypes,
            localVariables: localTypes,
            recoveredStructs: structs
        )
    }

    // MARK: - Instruction Analysis

    private func analyzeInstruction(_ insn: Instruction, architecture: Architecture, dataFlow: AdvancedDataFlowAnalyzer.DataFlowResult) {
        let operands = insn.operands.split(separator: ",").map { String($0).trimmingCharacters(in: .whitespaces) }

        switch insn.type {
        case .move:
            analyzeMove(insn, operands: operands, architecture: architecture)

        case .load:
            analyzeLoad(insn, operands: operands, architecture: architecture)

        case .store:
            analyzeStore(insn, operands: operands, architecture: architecture)

        case .arithmetic:
            analyzeArithmetic(insn, operands: operands, architecture: architecture)

        case .compare:
            analyzeCompare(insn, operands: operands, architecture: architecture)

        case .call:
            analyzeCall(insn, operands: operands, architecture: architecture)

        default:
            break
        }
    }

    private func analyzeMove(_ insn: Instruction, operands: [String], architecture: Architecture) {
        guard operands.count >= 2 else { return }

        let dest = normalizeRegister(operands[0])
        let src = operands[1]

        // Infer size from instruction
        let size = inferSizeFromMnemonic(insn.mnemonic, architecture: architecture)

        addEvidence(for: dest, size: size)

        // If moving from memory with offset, track as potential struct access
        if let (base, offset) = parseMemoryOperand(src) {
            trackStructAccess(base: base, offset: offset, size: size)
        }
    }

    private func analyzeLoad(_ insn: Instruction, operands: [String], architecture: Architecture) {
        guard operands.count >= 2 else { return }

        let dest = normalizeRegister(operands[0])
        let size = inferSizeFromMnemonic(insn.mnemonic, architecture: architecture)

        addEvidence(for: dest, size: size)

        // Parse memory operand for struct recovery
        if let (base, offset) = parseMemoryOperand(operands[1]) {
            trackStructAccess(base: base, offset: offset, size: size)

            // Track as pointer dereference
            addPointerEvidence(for: normalizeRegister(base))
        }
    }

    private func analyzeStore(_ insn: Instruction, operands: [String], architecture: Architecture) {
        guard operands.count >= 2 else { return }

        let size = inferSizeFromMnemonic(insn.mnemonic, architecture: architecture)

        // Parse memory destination
        if let (base, offset) = parseMemoryOperand(operands[0]) {
            trackStructAccess(base: base, offset: offset, size: size)
            addPointerEvidence(for: normalizeRegister(base))
        }
    }

    private func analyzeArithmetic(_ insn: Instruction, operands: [String], architecture: Architecture) {
        guard !operands.isEmpty else { return }

        let dest = normalizeRegister(operands[0])
        let mnemonic = insn.mnemonic.lowercased()

        // Signed vs unsigned hints
        if mnemonic.contains("imul") || mnemonic.contains("idiv") || mnemonic == "sar" {
            addSignedEvidence(for: dest)
        } else if mnemonic == "mul" || mnemonic == "div" || mnemonic == "shr" {
            addUnsignedEvidence(for: dest)
        }

        // Float operations
        if mnemonic.hasPrefix("f") || mnemonic.hasPrefix("v") ||
           mnemonic.contains("ss") || mnemonic.contains("sd") ||
           mnemonic.contains("ps") || mnemonic.contains("pd") {
            addFloatEvidence(for: dest)
        }

        // Array index pattern: reg * constant
        if mnemonic == "imul" || mnemonic == "mul" || mnemonic == "shl" {
            if operands.count >= 2 {
                if let scale = parseConstant(operands.last ?? "") {
                    // Common array element sizes
                    if [1, 2, 4, 8, 16].contains(Int(scale)) {
                        addArrayIndexEvidence(for: dest, elementSize: Int(scale))
                    }
                }
            }
        }
    }

    private func analyzeCompare(_ insn: Instruction, operands: [String], architecture: Architecture) {
        guard operands.count >= 2 else { return }

        let op1 = normalizeRegister(operands[0])

        // Track compared values for enum detection
        if let constVal = parseConstant(operands[1]) {
            addComparedValue(for: op1, value: constVal)
        }
    }

    private func analyzeCall(_ insn: Instruction, operands: [String], architecture: Architecture) {
        // Calls can provide type hints from known function signatures
        // This would integrate with library function recognition

        // Return value hints
        let returnReg = architecture.returnValueRegister
        addEvidence(for: returnReg, size: 8)  // Assume 64-bit return
    }

    // MARK: - Evidence Collection

    private func addEvidence(for register: String, size: Int) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.accessSizes.append(size)
    }

    private func addSignedEvidence(for register: String) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.signedOperations += 1
    }

    private func addUnsignedEvidence(for register: String) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.unsignedOperations += 1
    }

    private func addPointerEvidence(for register: String) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.pointerOperations += 1
    }

    private func addFloatEvidence(for register: String) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.floatOperations += 1
    }

    private func addComparedValue(for register: String, value: Int64) {
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        typeEvidence[register]?.comparedValues.append(value)
    }

    private func addArrayIndexEvidence(for register: String, elementSize: Int) {
        // This register is used as an array index
        if typeEvidence[register] == nil {
            typeEvidence[register] = TypeEvidence()
        }
        // Could track element size for better type inference
    }

    private func trackStructAccess(base: String, offset: Int64, size: Int) {
        let key = "struct_\(base)"
        if recoveredStructs[key] == nil {
            recoveredStructs[key] = StructType(name: key, fields: [])
        }

        let fieldType = sizeToType(size)
        let field = StructField(
            name: "field_\(String(format: "%X", offset))",
            type: fieldType,
            offset: Int(offset)
        )

        // Add field if not already present
        if !recoveredStructs[key]!.fields.contains(where: { $0.offset == Int(offset) }) {
            recoveredStructs[key]!.fields.append(field)
        }
    }

    // MARK: - Type Inference

    private func inferLocalTypes() -> [String: RecoveredType] {
        var types: [String: RecoveredType] = [:]

        for (register, evidence) in typeEvidence {
            types[register] = inferType(from: evidence)
        }

        return types
    }

    private func inferType(from evidence: TypeEvidence) -> RecoveredType {
        // Check for float first
        if evidence.floatOperations > 0 {
            let maxSize = evidence.accessSizes.max() ?? 4
            return maxSize > 4 ? .float64 : .float32
        }

        // Check for pointer
        if evidence.pointerOperations > 2 {
            return .pointer(to: .unknown(size: 8))
        }

        // Determine size
        let maxSize = evidence.accessSizes.max() ?? 4

        // Check for enum (multiple small constant comparisons)
        if evidence.comparedValues.count >= 3 {
            let sortedValues = evidence.comparedValues.sorted()
            // Check if values are sequential or close together (enum-like)
            var isEnumLike = true
            for i in 1..<sortedValues.count {
                if sortedValues[i] - sortedValues[i-1] > 10 {
                    isEnumLike = false
                    break
                }
            }
            if isEnumLike {
                let enumType = EnumType(
                    name: "auto_enum",
                    cases: sortedValues.enumerated().map { EnumCase(name: "case_\($0.offset)", value: $0.element) }
                )
                return .enumeration(enumType)
            }
        }

        // Determine signedness
        let isSigned = evidence.signedOperations > evidence.unsignedOperations

        // Map size to type
        switch maxSize {
        case 1:
            return isSigned ? .int8 : .uint8
        case 2:
            return isSigned ? .int16 : .uint16
        case 4:
            return isSigned ? .int32 : .uint32
        case 8:
            return isSigned ? .int64 : .uint64
        default:
            return .unknown(size: maxSize)
        }
    }

    private func inferParameterTypes(architecture: Architecture) -> [ParameterType] {
        var params: [ParameterType] = []

        for (i, reg) in architecture.argumentRegisters.enumerated() {
            if let evidence = typeEvidence[reg.lowercased()] {
                let type = inferType(from: evidence)
                params.append(ParameterType(name: "arg\(i + 1)", type: type))
            }
        }

        return params
    }

    private func inferReturnType(function: Function, architecture: Architecture) -> RecoveredType {
        let returnReg = architecture.returnValueRegister.lowercased()

        // Check if return register is set before return
        let instructions = function.basicBlocks.flatMap { $0.instructions }

        for insn in instructions.reversed() {
            if insn.type == .return {
                continue
            }
            if insn.operands.lowercased().contains(returnReg) {
                if let evidence = typeEvidence[returnReg] {
                    return inferType(from: evidence)
                }
                return .int64
            }
            break
        }

        return .void
    }

    private func recoverStructures() -> [StructType] {
        var structs: [StructType] = []

        for (_, var structType) in recoveredStructs {
            // Sort fields by offset
            structType.fields.sort { $0.offset < $1.offset }

            // Check for padding/alignment
            var alignedFields: [StructField] = []
            var lastEnd = 0

            for field in structType.fields {
                if field.offset > lastEnd {
                    // Add padding field
                    let paddingSize = field.offset - lastEnd
                    alignedFields.append(StructField(
                        name: "padding_\(String(format: "%X", lastEnd))",
                        type: .array(of: .uint8, count: paddingSize),
                        offset: lastEnd
                    ))
                }
                alignedFields.append(field)
                lastEnd = field.offset + field.type.size
            }

            structType.fields = alignedFields
            structs.append(structType)
        }

        return structs
    }

    // MARK: - Helpers

    private func normalizeRegister(_ reg: String) -> String {
        reg.trimmingCharacters(in: .whitespaces).lowercased()
    }

    private func parseMemoryOperand(_ operand: String) -> (base: String, offset: Int64)? {
        var op = operand.trimmingCharacters(in: .whitespaces)

        // Remove brackets
        if op.hasPrefix("[") && op.hasSuffix("]") {
            op = String(op.dropFirst().dropLast())
        } else if !op.contains("[") {
            return nil
        }

        // Parse [base + offset] or [base, #offset]
        var base: String = op
        var offset: Int64 = 0

        if let plusIdx = op.firstIndex(of: "+") {
            base = String(op[..<plusIdx]).trimmingCharacters(in: .whitespaces)
            let offsetStr = String(op[op.index(after: plusIdx)...]).trimmingCharacters(in: .whitespaces)
            offset = parseConstant(offsetStr) ?? 0
        } else if let minusIdx = op.firstIndex(of: "-") {
            base = String(op[..<minusIdx]).trimmingCharacters(in: .whitespaces)
            let offsetStr = String(op[op.index(after: minusIdx)...]).trimmingCharacters(in: .whitespaces)
            offset = -(parseConstant(offsetStr) ?? 0)
        } else if let commaIdx = op.firstIndex(of: ",") {
            base = String(op[..<commaIdx]).trimmingCharacters(in: .whitespaces)
            var offsetStr = String(op[op.index(after: commaIdx)...]).trimmingCharacters(in: .whitespaces)
            offsetStr = offsetStr.replacingOccurrences(of: "#", with: "")
            offset = parseConstant(offsetStr) ?? 0
        }

        return (base, offset)
    }

    private func parseConstant(_ str: String) -> Int64? {
        var s = str.trimmingCharacters(in: .whitespaces)
        s = s.replacingOccurrences(of: "#", with: "")

        let negative = s.hasPrefix("-")
        if negative { s = String(s.dropFirst()) }

        var value: Int64?
        if s.hasPrefix("0x") || s.hasPrefix("0X") {
            value = Int64(s.dropFirst(2), radix: 16)
        } else {
            value = Int64(s)
        }

        if let v = value {
            return negative ? -v : v
        }
        return nil
    }

    private func inferSizeFromMnemonic(_ mnemonic: String, architecture: Architecture) -> Int {
        let m = mnemonic.lowercased()

        // x86 size suffixes
        if m.hasSuffix("b") { return 1 }
        if m.hasSuffix("w") { return 2 }
        if m.hasSuffix("l") || m.hasSuffix("d") { return 4 }
        if m.hasSuffix("q") { return 8 }

        // ARM size hints
        if m.contains("strb") || m.contains("ldrb") { return 1 }
        if m.contains("strh") || m.contains("ldrh") { return 2 }
        if m.contains("str ") || m.contains("ldr ") {
            return architecture.pointerSize
        }

        return architecture.pointerSize
    }

    private func sizeToType(_ size: Int) -> RecoveredType {
        switch size {
        case 1: return .uint8
        case 2: return .uint16
        case 4: return .uint32
        case 8: return .uint64
        default: return .unknown(size: size)
        }
    }
}

// MARK: - Function Type Info

/// Complete type information for a function
struct FunctionTypeInfo {
    let returnType: TypeRecoveryEngine.RecoveredType
    let parameters: [TypeRecoveryEngine.ParameterType]
    let localVariables: [String: TypeRecoveryEngine.RecoveredType]
    let recoveredStructs: [TypeRecoveryEngine.StructType]

    /// Generate C-style function signature
    func signature(name: String) -> String {
        let params = parameters.map { $0.description }.joined(separator: ", ")
        return "\(returnType) \(name)(\(params.isEmpty ? "void" : params))"
    }

    /// Generate struct definitions
    func structDefinitions() -> String {
        var output = ""
        for structType in recoveredStructs {
            output += "struct \(structType.name) {\n"
            for field in structType.fields {
                output += "    \(field.type) \(field.name);  // offset: 0x\(String(format: "%X", field.offset))\n"
            }
            output += "};\n\n"
        }
        return output
    }
}

// MARK: - Array Detection

/// Specialized analyzer for detecting arrays
class ArrayAnalyzer {

    struct ArrayInfo {
        let baseAddress: UInt64
        let elementType: TypeRecoveryEngine.RecoveredType
        let elementCount: Int?
        let accessPattern: AccessPattern

        enum AccessPattern {
            case sequential     // arr[0], arr[1], arr[2]...
            case strided(Int)   // arr[0], arr[2], arr[4]... (stride)
            case indexed        // arr[i] with variable index
            case random         // No clear pattern
        }
    }

    /// Detect arrays from memory access patterns
    func detectArrays(function: Function, binary: BinaryFile) -> [ArrayInfo] {
        var arrays: [ArrayInfo] = []
        var accessesByBase: [String: [(offset: Int64, size: Int)]] = [:]

        let instructions = function.basicBlocks.flatMap { $0.instructions }

        // Collect memory accesses
        for insn in instructions {
            if insn.type == .load || insn.type == .store {
                if let (base, offset, size) = parseArrayAccess(insn) {
                    if accessesByBase[base] == nil {
                        accessesByBase[base] = []
                    }
                    accessesByBase[base]?.append((offset, size))
                }
            }
        }

        // Analyze access patterns
        for (base, accesses) in accessesByBase {
            guard accesses.count >= 2 else { continue }

            let sortedAccesses = accesses.sorted { $0.offset < $1.offset }
            let elementSize = sortedAccesses.first?.size ?? 4

            // Check for sequential pattern
            var isSequential = true
            for i in 1..<sortedAccesses.count {
                let expectedOffset = sortedAccesses[0].offset + Int64(i * elementSize)
                if sortedAccesses[i].offset != expectedOffset {
                    isSequential = false
                    break
                }
            }

            if isSequential {
                arrays.append(ArrayInfo(
                    baseAddress: 0,  // Would need actual address
                    elementType: sizeToType(elementSize),
                    elementCount: sortedAccesses.count,
                    accessPattern: .sequential
                ))
            }
        }

        return arrays
    }

    private func parseArrayAccess(_ insn: Instruction) -> (base: String, offset: Int64, size: Int)? {
        let parts = insn.operands.split(separator: ",")
        guard parts.count >= 2 else { return nil }

        let memPart = insn.type == .load ? String(parts[1]) : String(parts[0])

        // Parse [base + index*scale + offset]
        var op = memPart.trimmingCharacters(in: .whitespaces)
        if op.hasPrefix("[") && op.hasSuffix("]") {
            op = String(op.dropFirst().dropLast())
        }

        // Simple case: [base + offset]
        if let plusIdx = op.firstIndex(of: "+") {
            let base = String(op[..<plusIdx]).trimmingCharacters(in: .whitespaces)
            let offsetStr = String(op[op.index(after: plusIdx)...]).trimmingCharacters(in: .whitespaces)
            if let offset = Int64(offsetStr.replacingOccurrences(of: "0x", with: ""), radix: offsetStr.contains("0x") ? 16 : 10) {
                let size = inferSize(from: insn.mnemonic)
                return (base, offset, size)
            }
        }

        return nil
    }

    private func inferSize(from mnemonic: String) -> Int {
        let m = mnemonic.lowercased()
        if m.contains("b") { return 1 }
        if m.contains("w") || m.contains("h") { return 2 }
        if m.contains("d") || m.contains("l") { return 4 }
        return 8
    }

    private func sizeToType(_ size: Int) -> TypeRecoveryEngine.RecoveredType {
        switch size {
        case 1: return .uint8
        case 2: return .uint16
        case 4: return .uint32
        case 8: return .uint64
        default: return .unknown(size: size)
        }
    }
}
