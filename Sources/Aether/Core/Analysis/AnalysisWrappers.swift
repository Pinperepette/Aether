import Foundation

// MARK: - Analysis Result Wrappers for UI

/// Wrapper for deobfuscation report
struct DeobfuscationReportWrapper {
    let obfuscationScore: Double
    let isObfuscated: Bool
    let detectedTechniques: [DetectedTechnique]
    let recommendations: [String]

    struct DetectedTechnique {
        let type: ObfuscationType
        let confidence: Double
        let description: String
    }

    enum ObfuscationType: String {
        case controlFlowFlattening = "Control Flow Flattening"
        case opaquePredicates = "Opaque Predicates"
        case junkCode = "Junk Code"
        case instructionSubstitution = "Instruction Substitution"
        case virtualMachine = "Virtual Machine"
        case stringEncryption = "String Encryption"
        case unknown = "Unknown"
    }

    static func from(_ result: Deobfuscator.DeobfuscationResult, findings: [Deobfuscator.ObfuscationFinding]) -> DeobfuscationReportWrapper {
        let techniques = findings.map { finding in
            DetectedTechnique(
                type: mapTechnique(finding.technique),
                confidence: finding.confidence,
                description: finding.description
            )
        }

        let score = techniques.isEmpty ? 0.0 : techniques.map { $0.confidence }.reduce(0, +) / Double(techniques.count)

        var recommendations: [String] = []
        if score > 0.5 {
            recommendations.append("Consider using dynamic analysis to trace execution")
            recommendations.append("Look for decryption routines that run at startup")
        }
        if techniques.contains(where: { $0.type == .controlFlowFlattening }) {
            recommendations.append("Reconstruct original control flow using dominator analysis")
        }
        if techniques.contains(where: { $0.type == .opaquePredicates }) {
            recommendations.append("Simplify conditions using symbolic execution")
        }

        return DeobfuscationReportWrapper(
            obfuscationScore: score,
            isObfuscated: !findings.isEmpty,
            detectedTechniques: techniques,
            recommendations: recommendations
        )
    }

    private static func mapTechnique(_ technique: Deobfuscator.ObfuscationTechnique) -> ObfuscationType {
        switch technique {
        case .controlFlowFlattening: return .controlFlowFlattening
        case .opaquePredicate: return .opaquePredicates
        case .junkCode: return .junkCode
        case .deadCode: return .junkCode
        case .instructionSubstitution: return .instructionSubstitution
        case .virtualMachine: return .virtualMachine
        case .stringEncryption: return .stringEncryption
        case .constantObfuscation: return .unknown
        case .callObfuscation: return .unknown
        case .selfModifying: return .unknown
        case .antiDisassembly: return .unknown
        case .packedCode: return .unknown
        }
    }
}

/// Wrapper for recovered types for UI display
struct RecoveredTypeWrapper {
    let name: String
    let category: TypeCategory
    let cTypeDeclaration: String
    let address: UInt64
    let size: Int
    let confidence: Double

    enum TypeCategory: String {
        case struct_ = "Struct"
        case array = "Array"
        case enum_ = "Enum"
        case pointer = "Pointer"
        case primitive = "Primitive"
        case function = "Function"
        case union = "Union"
    }
}

/// TypeRecovery wrapper class for UI
class TypeRecovery {
    typealias RecoveredType = RecoveredTypeWrapper
    typealias TypeCategory = RecoveredTypeWrapper.TypeCategory

    private let engine = TypeRecoveryEngine()

    func recoverTypes(function: Function, blocks: [BasicBlock], binary: BinaryFile) -> [RecoveredTypeWrapper] {
        // Create a basic data flow analysis first
        let dfAnalyzer = AdvancedDataFlowAnalyzer()
        var func_ = function
        func_.basicBlocks = blocks
        let dataFlow = dfAnalyzer.analyze(function: func_, binary: binary)

        // Use the engine to recover types
        let recovered = engine.recoverTypes(function: func_, binary: binary, dataFlow: dataFlow)

        // Convert FunctionTypeInfo to wrapper types
        var wrappers: [RecoveredTypeWrapper] = []

        // Add parameter types
        for (index, param) in recovered.parameters.enumerated() {
            wrappers.append(RecoveredTypeWrapper(
                name: param.name ?? "param\(index)",
                category: typeCategory(param.type),
                cTypeDeclaration: param.description,
                address: function.startAddress,
                size: param.type.size,
                confidence: 0.8
            ))
        }

        // Add local variable types
        for (name, local) in recovered.localVariables {
            wrappers.append(RecoveredTypeWrapper(
                name: "local_\(name)",
                category: typeCategory(local),
                cTypeDeclaration: local.description,
                address: function.startAddress,
                size: local.size,
                confidence: 0.7
            ))
        }

        // Add return type
        if case .void = recovered.returnType {
            // Skip void
        } else {
            wrappers.append(RecoveredTypeWrapper(
                name: "return",
                category: typeCategory(recovered.returnType),
                cTypeDeclaration: recovered.returnType.description,
                address: function.startAddress,
                size: recovered.returnType.size,
                confidence: 0.75
            ))
        }

        return wrappers
    }

    private func typeName(_ type: TypeRecoveryEngine.RecoveredType) -> String {
        return type.description
    }

    private func typeCategory(_ type: TypeRecoveryEngine.RecoveredType) -> RecoveredTypeWrapper.TypeCategory {
        switch type {
        case .structure: return .struct_
        case .array: return .array
        case .enumeration: return .enum_
        case .pointer: return .pointer
        case .function: return .function
        case .union: return .union
        default: return .primitive
        }
    }

    private func typeDeclaration(_ type: TypeRecoveryEngine.RecoveredType) -> String {
        switch type {
        case .structure(let s):
            var decl = "struct \(s.name) {\n"
            for field in s.fields {
                decl += "    \(field.type) \(field.name);  // offset: \(field.offset)\n"
            }
            decl += "};"
            return decl
        case .array(let of, let count):
            if let c = count {
                return "\(of)[\(c)]"
            }
            return "\(of)[]"
        case .pointer(let to):
            return "\(to)*"
        case .function(let f):
            return f.description
        default:
            return type.description
        }
    }
}
