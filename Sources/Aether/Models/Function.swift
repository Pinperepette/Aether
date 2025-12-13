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
