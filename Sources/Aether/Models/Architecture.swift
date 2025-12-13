import Foundation

/// Supported CPU architectures
enum Architecture: String, CaseIterable, Identifiable, Codable {
    case x86_64 = "x86_64"
    case arm64 = "ARM64"
    case arm64e = "ARM64e"
    case i386 = "i386"
    case armv7 = "ARMv7"
    case jvm = "JVM"
    case unknown = "Unknown"

    var id: String { rawValue }

    /// Instruction alignment in bytes
    var instructionAlignment: Int {
        switch self {
        case .x86_64, .i386:
            return 1  // Variable length instructions
        case .arm64, .arm64e:
            return 4  // Fixed 4-byte instructions
        case .armv7:
            return 2  // Thumb mode can be 2 or 4 bytes
        case .jvm:
            return 1  // Variable length bytecode
        case .unknown:
            return 1
        }
    }

    /// Pointer size in bytes
    var pointerSize: Int {
        switch self {
        case .x86_64, .arm64, .arm64e:
            return 8
        case .i386, .armv7:
            return 4
        case .jvm:
            return 4  // JVM references are 32-bit (compressed oops)
        case .unknown:
            return 8
        }
    }

    /// Stack pointer register name
    var stackPointerName: String {
        switch self {
        case .x86_64:
            return "rsp"
        case .i386:
            return "esp"
        case .arm64, .arm64e:
            return "sp"
        case .armv7:
            return "sp"
        case .jvm:
            return "stack"
        case .unknown:
            return "sp"
        }
    }

    /// Frame pointer register name
    var framePointerName: String {
        switch self {
        case .x86_64:
            return "rbp"
        case .i386:
            return "ebp"
        case .arm64, .arm64e:
            return "x29"
        case .armv7:
            return "r11"
        case .jvm:
            return "locals"
        case .unknown:
            return "fp"
        }
    }

    /// Return address register/location
    var returnAddressLocation: String {
        switch self {
        case .x86_64, .i386:
            return "[stack]"
        case .arm64, .arm64e:
            return "x30"
        case .armv7:
            return "lr"
        case .jvm:
            return "[jvm_stack]"
        case .unknown:
            return "unknown"
        }
    }

    /// Is this a 64-bit architecture?
    var is64Bit: Bool {
        switch self {
        case .x86_64, .arm64, .arm64e:
            return true
        case .i386, .armv7, .jvm, .unknown:
            return false
        }
    }

    /// General purpose registers
    var generalPurposeRegisters: [String] {
        switch self {
        case .x86_64:
            return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        case .i386:
            return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"]
        case .arm64, .arm64e:
            return (0...30).map { "x\($0)" } + ["sp"]
        case .armv7:
            return (0...15).map { "r\($0)" }
        case .jvm:
            return ["stack", "locals"]  // JVM is stack-based
        case .unknown:
            return []
        }
    }

    /// Calling convention argument registers
    var argumentRegisters: [String] {
        switch self {
        case .x86_64:
            return ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]  // System V AMD64 ABI
        case .i386:
            return []  // Arguments on stack
        case .arm64, .arm64e:
            return ["x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"]
        case .armv7:
            return ["r0", "r1", "r2", "r3"]
        case .jvm:
            return []  // Arguments passed via locals
        case .unknown:
            return []
        }
    }

    /// Return value register
    var returnValueRegister: String {
        switch self {
        case .x86_64:
            return "rax"
        case .i386:
            return "eax"
        case .arm64, .arm64e:
            return "x0"
        case .armv7:
            return "r0"
        case .jvm:
            return "stack[0]"
        case .unknown:
            return "unknown"
        }
    }
}

/// Binary file format
enum BinaryFormat: String, CaseIterable, Identifiable, Codable {
    case machO = "Mach-O"
    case elf = "ELF"
    case pe = "PE"
    case java = "Java"
    case unknown = "Unknown"

    var id: String { rawValue }

    /// File extension hints
    var commonExtensions: [String] {
        switch self {
        case .machO:
            return ["", "dylib", "bundle", "framework", "app"]
        case .elf:
            return ["", "so", "o"]
        case .pe:
            return ["exe", "dll", "sys"]
        case .java:
            return ["jar", "class", "war", "ear"]
        case .unknown:
            return []
        }
    }

    /// Magic bytes for format detection
    static func detect(from data: Data) -> BinaryFormat {
        guard data.count >= 4 else { return .unknown }

        let magic = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }

        switch magic {
        case 0xFEEDFACE, 0xFEEDFACF:  // Mach-O 32/64
            return .machO
        case 0xBEBAFECA:  // Fat/Universal binary (little endian read)
            return .machO
        case 0xCAFEBABE:  // Could be Fat binary OR Java class file
            // Check if it's a Java class by looking for valid version bytes
            if data.count >= 8 {
                // Java class files have minor/major version after magic
                let majorVersion = (UInt16(data[6]) << 8) | UInt16(data[7])
                // Java versions range from 45 (1.1) to ~65 (21)
                if majorVersion >= 45 && majorVersion <= 70 {
                    return .java
                }
            }
            return .machO  // Otherwise it's a Fat binary
        case 0x464C457F:  // ELF magic (0x7F 'E' 'L' 'F')
            return .elf
        default:
            // Check for PE (MZ header)
            if data.count >= 2 {
                let mz = data.prefix(2)
                if mz[mz.startIndex] == 0x4D && mz[mz.startIndex + 1] == 0x5A {
                    return .pe
                }
            }
            // Check for JAR/ZIP (PK header)
            if data.count >= 4 {
                if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
                    return .java
                }
            }
            return .unknown
        }
    }
}

/// Endianness
enum Endianness: String, Codable {
    case little
    case big

    /// Read UInt16 with this endianness
    func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
        let bytes = data[offset..<(offset + 2)]
        switch self {
        case .little:
            return UInt16(bytes[bytes.startIndex]) | (UInt16(bytes[bytes.startIndex + 1]) << 8)
        case .big:
            return (UInt16(bytes[bytes.startIndex]) << 8) | UInt16(bytes[bytes.startIndex + 1])
        }
    }

    /// Read UInt32 with this endianness
    func readUInt32(_ data: Data, at offset: Int) -> UInt32 {
        let bytes = data[offset..<(offset + 4)]
        switch self {
        case .little:
            return bytes.withUnsafeBytes { $0.load(as: UInt32.self) }
        case .big:
            return bytes.withUnsafeBytes { $0.load(as: UInt32.self).byteSwapped }
        }
    }

    /// Read UInt64 with this endianness
    func readUInt64(_ data: Data, at offset: Int) -> UInt64 {
        let bytes = data[offset..<(offset + 8)]
        switch self {
        case .little:
            return bytes.withUnsafeBytes { $0.load(as: UInt64.self) }
        case .big:
            return bytes.withUnsafeBytes { $0.load(as: UInt64.self).byteSwapped }
        }
    }
}
