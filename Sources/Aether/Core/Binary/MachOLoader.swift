import Foundation

/// Mach-O binary format loader
class MachOLoader: BinaryLoaderProtocol {

    // MARK: - Mach-O Constants

    // Magic numbers
    private let MH_MAGIC: UInt32 = 0xFEEDFACE
    private let MH_CIGAM: UInt32 = 0xCEFAEDFE
    private let MH_MAGIC_64: UInt32 = 0xFEEDFACF
    private let MH_CIGAM_64: UInt32 = 0xCFFAEDFE
    private let FAT_MAGIC: UInt32 = 0xCAFEBABE
    private let FAT_CIGAM: UInt32 = 0xBEBAFECA

    // CPU Types
    private let CPU_TYPE_X86: UInt32 = 7
    private let CPU_TYPE_X86_64: UInt32 = 0x01000007
    private let CPU_TYPE_ARM: UInt32 = 12
    private let CPU_TYPE_ARM64: UInt32 = 0x0100000C
    private let CPU_TYPE_ARM64_32: UInt32 = 0x0200000C

    // Load Commands
    private let LC_SEGMENT: UInt32 = 0x1
    private let LC_SYMTAB: UInt32 = 0x2
    private let LC_SEGMENT_64: UInt32 = 0x19
    private let LC_DYSYMTAB: UInt32 = 0xB
    private let LC_LOAD_DYLIB: UInt32 = 0xC
    private let LC_MAIN: UInt32 = 0x80000028
    private let LC_UNIXTHREAD: UInt32 = 0x5
    private let LC_FUNCTION_STARTS: UInt32 = 0x26

    // MARK: - Protocol Implementation

    func canLoad(data: Data) -> Bool {
        guard let magic = data.readUInt32LE(at: 0) else { return false }
        return magic == MH_MAGIC || magic == MH_CIGAM ||
               magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
               magic == FAT_MAGIC || magic == FAT_CIGAM
    }

    func load(from url: URL, data: Data) async throws -> BinaryFile {
        debugLog("MachOLoader.load() starting")
        guard let magic = data.readUInt32LE(at: 0) else {
            throw BinaryLoaderError.invalidHeader
        }
        debugLog("Magic: \(String(format: "0x%X", magic))")

        // Handle fat/universal binaries
        if magic == FAT_MAGIC || magic == FAT_CIGAM {
            debugLog("Fat binary detected")
            return try await loadFatBinary(from: url, data: data, swapped: magic == FAT_CIGAM)
        }

        debugLog("Regular Mach-O")
        return try await loadMachO(from: url, data: data, offset: 0)
    }

    // MARK: - Fat Binary Loading

    private func loadFatBinary(from url: URL, data: Data, swapped: Bool) async throws -> BinaryFile {
        debugLog("loadFatBinary starting")

        // Fat header is ALWAYS big-endian, regardless of host architecture
        guard let nfatArch = data.readUInt32BE(at: 4) else {
            throw BinaryLoaderError.invalidHeader
        }

        debugLog("Fat binary has \(nfatArch) architectures")

        // Find the best architecture (prefer arm64, then x86_64)
        var bestOffset: UInt32 = 0
        var bestArch: UInt32 = 0

        for i in 0..<nfatArch {
            let archOffset = 8 + Int(i) * 20
            // Fat arch entries are also big-endian
            guard let cpuType = data.readUInt32BE(at: archOffset) else { continue }
            guard let offset = data.readUInt32BE(at: archOffset + 8) else { continue }

            debugLog("  Arch \(i): cpuType=0x\(String(format: "%X", cpuType)) offset=\(offset)")

            // Prefer ARM64, then x86_64
            if cpuType == CPU_TYPE_ARM64 {
                bestOffset = offset
                bestArch = cpuType
                break
            } else if cpuType == CPU_TYPE_X86_64 && bestArch != CPU_TYPE_ARM64 {
                bestOffset = offset
                bestArch = cpuType
            } else if bestOffset == 0 {
                bestOffset = offset
                bestArch = cpuType
            }
        }

        debugLog("Selected arch: \(String(format: "0x%X", bestArch)) at offset \(bestOffset)")
        return try await loadMachO(from: url, data: data, offset: Int(bestOffset))
    }

    // MARK: - Mach-O Loading

    private func loadMachO(from url: URL, data: Data, offset: Int) async throws -> BinaryFile {
        debugLog("loadMachO at offset \(offset)")
        guard let magic = data.readUInt32LE(at: offset) else {
            throw BinaryLoaderError.invalidHeader
        }

        let is64Bit = magic == MH_MAGIC_64 || magic == MH_CIGAM_64
        let swapped = magic == MH_CIGAM || magic == MH_CIGAM_64
        debugLog("is64Bit: \(is64Bit), swapped: \(swapped)")

        // Parse header
        let header = try parseMachOHeader(data: data, offset: offset, is64Bit: is64Bit, swapped: swapped)
        debugLog("Header: ncmds=\(header.ncmds)")

        // Parse load commands
        let headerSize = is64Bit ? 32 : 28
        var cmdOffset = offset + headerSize

        var segments: [Segment] = []
        var sections: [Section] = []
        var symbols: [Symbol] = []
        var entryPoint: UInt64 = 0

        debugLog("Parsing \(header.ncmds) load commands...")
        for i in 0..<header.ncmds {
            guard let cmd = data.readUInt32LE(at: cmdOffset),
                  let cmdSize = data.readUInt32LE(at: cmdOffset + 4) else {
                break
            }

            switch cmd {
            case LC_SEGMENT:
                let (seg, sects) = try parseSegment32(data: data, offset: cmdOffset, binaryData: data, binaryOffset: offset)
                segments.append(seg)
                sections.append(contentsOf: sects)

            case LC_SEGMENT_64:
                let (seg, sects) = try parseSegment64(data: data, offset: cmdOffset, binaryData: data, binaryOffset: offset)
                segments.append(seg)
                sections.append(contentsOf: sects)

            case LC_SYMTAB:
                debugLog("Parsing symbol table...")
                let syms = try parseSymtab(data: data, offset: cmdOffset, is64Bit: is64Bit, binaryOffset: offset)
                symbols.append(contentsOf: syms)
                debugLog("Parsed \(syms.count) symbols")

            case LC_MAIN:
                if let entryOff = data.readUInt64LE(at: cmdOffset + 8) {
                    // Find __TEXT segment to calculate entry point
                    if let textSeg = segments.first(where: { $0.name == "__TEXT" }) {
                        entryPoint = textSeg.address + entryOff
                    }
                }

            case LC_UNIXTHREAD:
                // Parse thread state for entry point (older binaries)
                entryPoint = try parseUnixThread(data: data, offset: cmdOffset, cpuType: header.cpuType)

            default:
                break
            }

            cmdOffset += Int(cmdSize)
        }

        debugLog("Load commands parsed: \(segments.count) segments, \(sections.count) sections, \(symbols.count) symbols")

        // Determine base address (skip __PAGEZERO which has address 0)
        let baseAddress = segments.first(where: { $0.name != "__PAGEZERO" && $0.address > 0 })?.address ?? segments.first?.address ?? 0
        debugLog("Creating BinaryFile...")

        return BinaryFile(
            url: url,
            format: .machO,
            architecture: mapCPUType(header.cpuType),
            endianness: swapped ? .big : .little,
            is64Bit: is64Bit,
            fileSize: data.count,
            entryPoint: entryPoint,
            baseAddress: baseAddress,
            sections: sections,
            segments: segments,
            symbols: symbols,
            data: data
        )
    }

    // MARK: - Header Parsing

    private struct MachOHeader {
        let magic: UInt32
        let cpuType: UInt32
        let cpuSubtype: UInt32
        let fileType: UInt32
        let ncmds: UInt32
        let sizeOfCmds: UInt32
        let flags: UInt32
    }

    private func parseMachOHeader(data: Data, offset: Int, is64Bit: Bool, swapped: Bool) throws -> MachOHeader {
        guard let magic = data.readUInt32LE(at: offset),
              let cpuType = data.readUInt32LE(at: offset + 4),
              let cpuSubtype = data.readUInt32LE(at: offset + 8),
              let fileType = data.readUInt32LE(at: offset + 12),
              let ncmds = data.readUInt32LE(at: offset + 16),
              let sizeOfCmds = data.readUInt32LE(at: offset + 20),
              let flags = data.readUInt32LE(at: offset + 24) else {
            throw BinaryLoaderError.invalidHeader
        }

        return MachOHeader(
            magic: magic,
            cpuType: swapped ? cpuType.byteSwapped : cpuType,
            cpuSubtype: swapped ? cpuSubtype.byteSwapped : cpuSubtype,
            fileType: swapped ? fileType.byteSwapped : fileType,
            ncmds: swapped ? ncmds.byteSwapped : ncmds,
            sizeOfCmds: swapped ? sizeOfCmds.byteSwapped : sizeOfCmds,
            flags: swapped ? flags.byteSwapped : flags
        )
    }

    // MARK: - Segment Parsing

    private func parseSegment32(data: Data, offset: Int, binaryData: Data, binaryOffset: Int) throws -> (Segment, [Section]) {
        let segNameData = data.subdata(in: (offset + 8)..<(offset + 24))
        let segName = String(data: segNameData, encoding: .utf8)?.trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""

        guard let vmaddr = data.readUInt32LE(at: offset + 24),
              let vmsize = data.readUInt32LE(at: offset + 28),
              let fileoff = data.readUInt32LE(at: offset + 32),
              let filesize = data.readUInt32LE(at: offset + 36),
              let maxprot = data.readUInt32LE(at: offset + 40),
              let initprot = data.readUInt32LE(at: offset + 44),
              let nsects = data.readUInt32LE(at: offset + 48) else {
            throw BinaryLoaderError.corruptedFile("Invalid segment")
        }

        let segment = Segment(
            name: segName,
            address: UInt64(vmaddr),
            size: UInt64(vmsize),
            fileOffset: UInt64(fileoff),
            fileSize: UInt64(filesize),
            maxProtection: maxprot,
            initProtection: initprot
        )

        var sections: [Section] = []
        var sectOffset = offset + 56

        for _ in 0..<nsects {
            let section = try parseSection32(data: data, offset: sectOffset, segName: segName, binaryData: binaryData, binaryOffset: binaryOffset)
            sections.append(section)
            sectOffset += 68
        }

        return (segment, sections)
    }

    private func parseSegment64(data: Data, offset: Int, binaryData: Data, binaryOffset: Int) throws -> (Segment, [Section]) {
        let segNameData = data.subdata(in: (offset + 8)..<(offset + 24))
        let segName = String(data: segNameData, encoding: .utf8)?.trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""

        guard let vmaddr = data.readUInt64LE(at: offset + 24),
              let vmsize = data.readUInt64LE(at: offset + 32),
              let fileoff = data.readUInt64LE(at: offset + 40),
              let filesize = data.readUInt64LE(at: offset + 48),
              let maxprot = data.readUInt32LE(at: offset + 56),
              let initprot = data.readUInt32LE(at: offset + 60),
              let nsects = data.readUInt32LE(at: offset + 64) else {
            throw BinaryLoaderError.corruptedFile("Invalid segment")
        }

        let segment = Segment(
            name: segName,
            address: vmaddr,
            size: vmsize,
            fileOffset: fileoff,
            fileSize: filesize,
            maxProtection: maxprot,
            initProtection: initprot
        )

        var sections: [Section] = []
        var sectOffset = offset + 72

        for _ in 0..<nsects {
            let section = try parseSection64(data: data, offset: sectOffset, segName: segName, binaryData: binaryData, binaryOffset: binaryOffset)
            sections.append(section)
            sectOffset += 80
        }

        return (segment, sections)
    }

    // MARK: - Section Parsing

    private func parseSection32(data: Data, offset: Int, segName: String, binaryData: Data, binaryOffset: Int) throws -> Section {
        let sectNameData = data.subdata(in: offset..<(offset + 16))
        let sectName = String(data: sectNameData, encoding: .utf8)?.trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""

        guard let addr = data.readUInt32LE(at: offset + 32),
              let size = data.readUInt32LE(at: offset + 36),
              let fileOffset = data.readUInt32LE(at: offset + 40),
              let align = data.readUInt32LE(at: offset + 44),
              let flags = data.readUInt32LE(at: offset + 52) else {
            throw BinaryLoaderError.corruptedFile("Invalid section")
        }

        // Read section data
        let sectionData: Data
        if size > 0 && fileOffset > 0 {
            let dataOffset = binaryOffset + Int(fileOffset)
            sectionData = binaryData.subdata(in: dataOffset..<(dataOffset + Int(size)))
        } else {
            sectionData = Data()
        }

        return Section(
            name: sectName,
            segmentName: segName,
            address: UInt64(addr),
            size: UInt64(size),
            offset: fileOffset,
            alignment: align,
            flags: flags,
            data: sectionData
        )
    }

    private func parseSection64(data: Data, offset: Int, segName: String, binaryData: Data, binaryOffset: Int) throws -> Section {
        let sectNameData = data.subdata(in: offset..<(offset + 16))
        let sectName = String(data: sectNameData, encoding: .utf8)?.trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""

        guard let addr = data.readUInt64LE(at: offset + 32),
              let size = data.readUInt64LE(at: offset + 40),
              let fileOffset = data.readUInt32LE(at: offset + 48),
              let align = data.readUInt32LE(at: offset + 52),
              let flags = data.readUInt32LE(at: offset + 60) else {
            throw BinaryLoaderError.corruptedFile("Invalid section")
        }

        // Read section data
        let sectionData: Data
        if size > 0 && fileOffset > 0 {
            let dataOffset = binaryOffset + Int(fileOffset)
            let endOffset = dataOffset + Int(size)
            if endOffset <= binaryData.count {
                sectionData = binaryData.subdata(in: dataOffset..<endOffset)
            } else {
                sectionData = Data()
            }
        } else {
            sectionData = Data()
        }

        return Section(
            name: sectName,
            segmentName: segName,
            address: addr,
            size: size,
            offset: fileOffset,
            alignment: align,
            flags: flags,
            data: sectionData
        )
    }

    // MARK: - Symbol Table Parsing

    private func parseSymtab(data: Data, offset: Int, is64Bit: Bool, binaryOffset: Int) throws -> [Symbol] {
        guard let symoff = data.readUInt32LE(at: offset + 8),
              let nsyms = data.readUInt32LE(at: offset + 12),
              let stroff = data.readUInt32LE(at: offset + 16) else {
            return []
        }

        var symbols: [Symbol] = []
        let nlistSize = is64Bit ? 16 : 12

        for i in 0..<nsyms {
            let symOffset = binaryOffset + Int(symoff) + Int(i) * nlistSize

            guard let strx = data.readUInt32LE(at: symOffset),
                  let type = data.readUInt8(at: symOffset + 4),
                  let sect = data.readUInt8(at: symOffset + 5) else {
                continue
            }

            let value: UInt64
            if is64Bit {
                guard let val = data.readUInt64LE(at: symOffset + 8) else { continue }
                value = val
            } else {
                guard let val = data.readUInt32LE(at: symOffset + 8) else { continue }
                value = UInt64(val)
            }

            // Read symbol name
            let nameOffset = binaryOffset + Int(stroff) + Int(strx)
            let name = data.readCString(at: nameOffset) ?? ""

            // Determine symbol type and binding
            let symType: SymbolType
            let binding: SymbolBinding

            let N_TYPE: UInt8 = 0x0E
            let N_EXT: UInt8 = 0x01
            let N_UNDF: UInt8 = 0x00
            let N_SECT: UInt8 = 0x0E

            let typeField = type & N_TYPE
            let isExternal = (type & N_EXT) != 0

            if typeField == N_UNDF {
                symType = .unknown
                binding = isExternal ? .external : .undefined
            } else if typeField == N_SECT {
                // Check if this looks like a function (in __TEXT,__text)
                symType = sect == 1 ? .function : .data
                binding = isExternal ? .global : .local
            } else {
                symType = .unknown
                binding = isExternal ? .global : .local
            }

            guard !name.isEmpty else { continue }

            symbols.append(Symbol(
                name: name,
                address: value,
                size: 0,
                type: symType,
                binding: binding,
                section: nil
            ))
        }

        return symbols
    }

    // MARK: - Thread State Parsing

    private func parseUnixThread(data: Data, offset: Int, cpuType: UInt32) throws -> UInt64 {
        // Skip cmd and cmdsize (8 bytes), then flavor and count (8 bytes)
        let stateOffset = offset + 16

        switch cpuType {
        case CPU_TYPE_X86_64:
            // RIP is at offset 16*8 in x86_64 thread state
            if let rip = data.readUInt64LE(at: stateOffset + 16 * 8) {
                return rip
            }
        case CPU_TYPE_ARM64:
            // PC is at offset 32*8 in ARM64 thread state
            if let pc = data.readUInt64LE(at: stateOffset + 32 * 8) {
                return pc
            }
        case CPU_TYPE_X86:
            // EIP is at offset 10*4 in i386 thread state
            if let eip = data.readUInt32LE(at: stateOffset + 10 * 4) {
                return UInt64(eip)
            }
        default:
            break
        }

        return 0
    }

    // MARK: - Helpers

    private func mapCPUType(_ cpuType: UInt32) -> Architecture {
        switch cpuType {
        case CPU_TYPE_X86_64:
            return .x86_64
        case CPU_TYPE_ARM64:
            return .arm64
        case CPU_TYPE_X86:
            return .i386
        case CPU_TYPE_ARM:
            return .armv7
        default:
            return .unknown
        }
    }
}
