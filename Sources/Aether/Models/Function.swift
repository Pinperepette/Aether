import Foundation

/// Represents an identified function in the binary
struct Function: Identifiable, Hashable {
    let id = UUID()
    var name: String
    let startAddress: UInt64
    var endAddress: UInt64
    var size: UInt64 { endAddress - startAddress }

    // Analysis results
    var callers: Set<UInt64> = []       // Addresses that call this function
    var callees: Set<UInt64> = []       // Functions this function calls
    var basicBlocks: [BasicBlock] = []

    // Metadata
    var isThunk: Bool = false           // Simple jump to another function
    var isLeaf: Bool = true             // Doesn't call other functions
    var stackSize: Int = 0              // Stack frame size
    var arguments: [FunctionArgument] = []
    var localVariables: [LocalVariable] = []

    func contains(address: UInt64) -> Bool {
        address >= startAddress && address < endAddress
    }

    var displayName: String {
        if name.isEmpty {
            return String(format: "sub_%llX", startAddress)
        }
        // Strip leading underscore for display
        if name.hasPrefix("_") && !name.hasPrefix("__") {
            return String(name.dropFirst())
        }
        return name
    }

    /// Short display name for headers/UI - formats Java signatures nicely
    var shortDisplayName: String {
        if name.isEmpty {
            return String(format: "sub_%llX", startAddress)
        }

        // Check if this looks like a Java method signature
        // Format: className.methodName(descriptor)returnType
        // Detect by: has parenthesis AND has at least 2 dot-separated parts before it
        if let parenIndex = name.firstIndex(of: "(") {
            let beforeParen = String(name[..<parenIndex])
            let parts = beforeParen.split(separator: ".")

            // If we have package.class.method format (2+ parts), it's likely Java
            if parts.count >= 2 {
                let className = String(parts[parts.count - 2])
                let methodName = String(parts[parts.count - 1])

                // Parse descriptor to get simple parameter types
                let afterParen = String(name[parenIndex...])
                let params = parseJavaParams(afterParen)

                if methodName == "<init>" {
                    return "\(className)(\(params))"
                } else if methodName == "<clinit>" {
                    return "\(className).<clinit>"
                } else {
                    return "\(className).\(methodName)(\(params))"
                }
            }
        }

        // For native functions, strip underscore
        if name.hasPrefix("_") && !name.hasPrefix("__") {
            return String(name.dropFirst())
        }

        return name
    }

    /// Parse Java method descriptor to extract simple parameter types
    private func parseJavaParams(_ descriptor: String) -> String {
        guard let startIdx = descriptor.firstIndex(of: "("),
              let endIdx = descriptor.firstIndex(of: ")") else {
            return ""
        }

        let paramsStr = String(descriptor[descriptor.index(after: startIdx)..<endIdx])
        if paramsStr.isEmpty { return "" }

        var params: [String] = []
        var idx = paramsStr.startIndex

        while idx < paramsStr.endIndex {
            let c = paramsStr[idx]
            switch c {
            case "B": params.append("byte"); idx = paramsStr.index(after: idx)
            case "C": params.append("char"); idx = paramsStr.index(after: idx)
            case "D": params.append("double"); idx = paramsStr.index(after: idx)
            case "F": params.append("float"); idx = paramsStr.index(after: idx)
            case "I": params.append("int"); idx = paramsStr.index(after: idx)
            case "J": params.append("long"); idx = paramsStr.index(after: idx)
            case "S": params.append("short"); idx = paramsStr.index(after: idx)
            case "Z": params.append("boolean"); idx = paramsStr.index(after: idx)
            case "[":
                // Array - skip to get base type
                idx = paramsStr.index(after: idx)
                continue
            case "L":
                // Object type - find the semicolon
                if let semiIdx = paramsStr[idx...].firstIndex(of: ";") {
                    let fullType = String(paramsStr[paramsStr.index(after: idx)..<semiIdx])
                    // Get simple class name
                    let typeParts = fullType.split(separator: "/")
                    params.append(String(typeParts.last ?? Substring(fullType)))
                    idx = paramsStr.index(after: semiIdx)
                } else {
                    idx = paramsStr.index(after: idx)
                }
            default:
                idx = paramsStr.index(after: idx)
            }
        }

        return params.joined(separator: ", ")
    }

    static func == (lhs: Function, rhs: Function) -> Bool {
        lhs.startAddress == rhs.startAddress
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(startAddress)
    }
}

/// A basic block within a function (for CFG)
struct BasicBlock: Identifiable, Hashable {
    let id = UUID()
    let startAddress: UInt64
    var endAddress: UInt64
    var instructions: [Instruction] = []

    // CFG edges
    var successors: [UInt64] = []       // Addresses of successor blocks
    var predecessors: [UInt64] = []     // Addresses of predecessor blocks

    // Block type
    var type: BasicBlockType = .normal

    var size: UInt64 { endAddress - startAddress }

    static func == (lhs: BasicBlock, rhs: BasicBlock) -> Bool {
        lhs.startAddress == rhs.startAddress
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(startAddress)
    }
}

/// Type of basic block
enum BasicBlockType: String, Codable {
    case entry = "Entry"
    case normal = "Normal"
    case exit = "Exit"
    case conditional = "Conditional"
    case loop = "Loop"
}

/// Function argument
struct FunctionArgument: Identifiable {
    let id = UUID()
    var name: String
    var type: String
    var register: String?
    var stackOffset: Int?
}

/// Local variable
struct LocalVariable: Identifiable {
    let id = UUID()
    var name: String
    var type: String
    var stackOffset: Int
    var size: Int
}
