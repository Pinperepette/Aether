import Foundation

/// Represents a disassembled instruction
struct Instruction: Identifiable, Hashable {
    let id = UUID()
    let address: UInt64
    let size: Int
    let bytes: [UInt8]
    let mnemonic: String
    let operands: String
    let architecture: Architecture

    // Analysis metadata
    var comment: String?
    var xrefsFrom: [UInt64] = []        // Instructions that reference this one
    var xrefsTo: [UInt64] = []          // Addresses this instruction references

    // Instruction classification
    var type: InstructionType = .other
    var branchTarget: UInt64?

    /// Full instruction string
    var text: String {
        if operands.isEmpty {
            return mnemonic
        }
        return "\(mnemonic) \(operands)"
    }

    /// Hex string of instruction bytes
    var hexString: String {
        bytes.map { String(format: "%02X", $0) }.joined(separator: " ")
    }

    /// Is this a control flow instruction?
    var isControlFlow: Bool {
        switch type {
        case .jump, .conditionalJump, .call, .return:
            return true
        default:
            return false
        }
    }

    /// Is this a branch instruction?
    var isBranch: Bool {
        switch type {
        case .jump, .conditionalJump:
            return true
        default:
            return false
        }
    }

    /// Does this instruction end a basic block?
    var endsBasicBlock: Bool {
        switch type {
        case .jump, .conditionalJump, .return:
            return true
        default:
            return false
        }
    }

    static func == (lhs: Instruction, rhs: Instruction) -> Bool {
        lhs.address == rhs.address
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(address)
    }
}

/// Classification of instruction types
enum InstructionType: String, Codable {
    case move = "Move"
    case arithmetic = "Arithmetic"
    case logic = "Logic"
    case compare = "Compare"
    case jump = "Jump"
    case conditionalJump = "Conditional Jump"
    case call = "Call"
    case `return` = "Return"
    case push = "Push"
    case pop = "Pop"
    case load = "Load"
    case store = "Store"
    case nop = "NOP"
    case interrupt = "Interrupt"
    case syscall = "Syscall"
    case other = "Other"

    var color: String {
        switch self {
        case .move: return "instructionMove"
        case .arithmetic, .logic: return "instructionMath"
        case .compare: return "instructionCompare"
        case .jump, .conditionalJump: return "instructionJump"
        case .call: return "instructionCall"
        case .return: return "instructionReturn"
        case .push, .pop: return "instructionStack"
        case .load, .store: return "instructionMemory"
        case .nop: return "instructionNop"
        case .interrupt, .syscall: return "instructionSystem"
        case .other: return "instructionOther"
        }
    }
}

/// Cross-reference
struct CrossReference: Identifiable, Hashable {
    let id = UUID()
    let fromAddress: UInt64
    let toAddress: UInt64
    let type: XRefType

    static func == (lhs: CrossReference, rhs: CrossReference) -> Bool {
        lhs.fromAddress == rhs.fromAddress && lhs.toAddress == rhs.toAddress
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(fromAddress)
        hasher.combine(toAddress)
    }
}

/// Type of cross-reference
enum XRefType: String, Codable {
    case call = "Call"
    case jump = "Jump"
    case data = "Data"
    case string = "String"
}

/// String reference found in binary
struct StringReference: Identifiable, Hashable {
    let id = UUID()
    let address: UInt64
    let value: String
    let encoding: StringEncoding
    let xrefs: [UInt64]  // Addresses that reference this string

    static func == (lhs: StringReference, rhs: StringReference) -> Bool {
        lhs.address == rhs.address
    }

    func hash(into hasher: inout Hasher) {
        hasher.combine(address)
    }
}

/// String encoding
enum StringEncoding: String, Codable {
    case ascii = "ASCII"
    case utf8 = "UTF-8"
    case utf16 = "UTF-16"
    case utf32 = "UTF-32"
}
