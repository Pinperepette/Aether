import Foundation

/// Represents a loaded binary file
class BinaryFile: ObservableObject, Identifiable {
    let id = UUID()
    let url: URL
    let format: BinaryFormat
    let architecture: Architecture
    let endianness: Endianness
    let is64Bit: Bool

    // File metadata
    let fileSize: Int
    let entryPoint: UInt64
    let baseAddress: UInt64

    // Sections and segments
    @Published var sections: [Section]
    @Published var segments: [Segment]

    // Symbols
    @Published var symbols: [Symbol]

    // Raw data
    let data: Data

    init(
        url: URL,
        format: BinaryFormat,
        architecture: Architecture,
        endianness: Endianness,
        is64Bit: Bool,
        fileSize: Int,
        entryPoint: UInt64,
        baseAddress: UInt64,
        sections: [Section],
        segments: [Segment],
        symbols: [Symbol],
        data: Data
    ) {
        self.url = url
        self.format = format
        self.architecture = architecture
        self.endianness = endianness
        self.is64Bit = is64Bit
        self.fileSize = fileSize
        self.entryPoint = entryPoint
        self.baseAddress = baseAddress
        self.sections = sections
        self.segments = segments
        self.symbols = symbols
        self.data = data
    }

    var name: String {
        url.lastPathComponent
    }

    /// Find section containing address
    func section(containing address: UInt64) -> Section? {
        sections.first { $0.contains(address: address) }
    }

    /// Find segment containing address
    func segment(containing address: UInt64) -> Segment? {
        segments.first { $0.contains(address: address) }
    }

    /// Read bytes at virtual address
    func read(at address: UInt64, count: Int) -> Data? {
        guard let section = section(containing: address) else { return nil }

        let offset = Int(address - section.address)
        guard offset >= 0, offset + count <= section.data.count else { return nil }

        return section.data[offset..<(offset + count)]
    }

    /// Read null-terminated string at address
    func readString(at address: UInt64, maxLength: Int = 1024) -> String? {
        guard let section = section(containing: address) else { return nil }

        let offset = Int(address - section.address)
        guard offset >= 0 else { return nil }

        var bytes: [UInt8] = []
        var currentOffset = offset

        while currentOffset < section.data.count && bytes.count < maxLength {
            let byte = section.data[section.data.startIndex + currentOffset]
            if byte == 0 { break }
            bytes.append(byte)
            currentOffset += 1
        }

        return String(bytes: bytes, encoding: .utf8)
    }
}

/// Binary segment (e.g., __TEXT, __DATA)
struct Segment: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let address: UInt64
    let size: UInt64
    let fileOffset: UInt64
    let fileSize: UInt64
    let maxProtection: UInt32
    let initProtection: UInt32

    var isReadable: Bool { initProtection & 1 != 0 }
    var isWritable: Bool { initProtection & 2 != 0 }
    var isExecutable: Bool { initProtection & 4 != 0 }

    func contains(address addr: UInt64) -> Bool {
        addr >= address && addr < (address + size)
    }

    var protectionString: String {
        var result = ""
        result += isReadable ? "r" : "-"
        result += isWritable ? "w" : "-"
        result += isExecutable ? "x" : "-"
        return result
    }
}

/// Binary section (e.g., __text, __data)
struct Section: Identifiable, Hashable {
    let id = UUID()
    let name: String
    let segmentName: String
    let address: UInt64
    let size: UInt64
    let offset: UInt32
    let alignment: UInt32
    let flags: UInt32
    let data: Data

    var fullName: String { "\(segmentName),\(name)" }

    var isExecutable: Bool {
        // S_ATTR_PURE_INSTRUCTIONS or S_ATTR_SOME_INSTRUCTIONS
        flags & 0x80000000 != 0 || flags & 0x00000400 != 0
    }

    var isZeroFill: Bool {
        // S_ZEROFILL
        (flags & 0xFF) == 1
    }

    var containsCode: Bool {
        isExecutable || name == "__text" || name == ".text"
    }

    func contains(address addr: UInt64) -> Bool {
        addr >= address && addr < (address + size)
    }
}
