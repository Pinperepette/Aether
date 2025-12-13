import Foundation

/// ELF binary format loader
class ELFLoader: BinaryLoaderProtocol {

    // MARK: - ELF Constants

    private let ELF_MAGIC: [UInt8] = [0x7F, 0x45, 0x4C, 0x46]  // "\x7FELF"

    // ELF Class
    private let ELFCLASS32: UInt8 = 1
    private let ELFCLASS64: UInt8 = 2

    // ELF Data encoding
    private let ELFDATA2LSB: UInt8 = 1  // Little endian
    private let ELFDATA2MSB: UInt8 = 2  // Big endian

    // Machine types
    private let EM_386: UInt16 = 3
    private let EM_X86_64: UInt16 = 62
    private let EM_ARM: UInt16 = 40
    private let EM_AARCH64: UInt16 = 183

    // Section types
    private let SHT_PROGBITS: UInt32 = 1
    private let SHT_SYMTAB: UInt32 = 2
    private let SHT_STRTAB: UInt32 = 3
    private let SHT_DYNSYM: UInt32 = 11

    // Section flags
    private let SHF_EXECINSTR: UInt64 = 0x4

    // Program header types
    private let PT_LOAD: UInt32 = 1

    // Symbol binding
    private let STB_LOCAL: UInt8 = 0
    private let STB_GLOBAL: UInt8 = 1
    private let STB_WEAK: UInt8 = 2

    // Symbol types
    private let STT_FUNC: UInt8 = 2
    private let STT_OBJECT: UInt8 = 1

    // MARK: - Protocol Implementation

    func canLoad(data: Data) -> Bool {
        guard data.count >= 4 else { return false }
        return data[0] == ELF_MAGIC[0] &&
               data[1] == ELF_MAGIC[1] &&
               data[2] == ELF_MAGIC[2] &&
               data[3] == ELF_MAGIC[3]
    }

    func load(from url: URL, data: Data) async throws -> BinaryFile {
        guard data.count >= 52 else {
            throw BinaryLoaderError.invalidHeader
        }

        // Parse ELF identification
        let elfClass = data[4]
        let elfData = data[5]

        let is64Bit = elfClass == ELFCLASS64
        let isLittleEndian = elfData == ELFDATA2LSB

        // Parse header
        let header = try parseELFHeader(data: data, is64Bit: is64Bit, littleEndian: isLittleEndian)

        // Parse program headers (segments)
        let segments = try parseProgramHeaders(
            data: data,
            offset: Int(header.phoff),
            count: Int(header.phnum),
            entrySize: Int(header.phentsize),
            is64Bit: is64Bit,
            littleEndian: isLittleEndian
        )

        // Parse section headers
        let (sections, stringTable) = try parseSectionHeaders(
            data: data,
            offset: Int(header.shoff),
            count: Int(header.shnum),
            entrySize: Int(header.shentsize),
            stringTableIndex: Int(header.shstrndx),
            is64Bit: is64Bit,
            littleEndian: isLittleEndian
        )

        // Parse symbols
        let symbols = try parseSymbols(
            data: data,
            sections: sections,
            is64Bit: is64Bit,
            littleEndian: isLittleEndian
        )

        return BinaryFile(
            url: url,
            format: .elf,
            architecture: mapMachine(header.machine),
            endianness: isLittleEndian ? .little : .big,
            is64Bit: is64Bit,
            fileSize: data.count,
            entryPoint: header.entry,
            baseAddress: segments.first?.address ?? 0,
            sections: sections,
            segments: segments,
            symbols: symbols,
            data: data
        )
    }

    // MARK: - Header Parsing

    private struct ELFHeader {
        let entry: UInt64
        let phoff: UInt64
        let shoff: UInt64
        let flags: UInt32
        let ehsize: UInt16
        let phentsize: UInt16
        let phnum: UInt16
        let shentsize: UInt16
        let shnum: UInt16
        let shstrndx: UInt16
        let machine: UInt16
    }

    private func parseELFHeader(data: Data, is64Bit: Bool, littleEndian: Bool) throws -> ELFHeader {
        let read16: (Int) -> UInt16? = { offset in
            littleEndian ? data.readUInt16LE(at: offset) : data.readUInt16BE(at: offset)
        }
        let read32: (Int) -> UInt32? = { offset in
            littleEndian ? data.readUInt32LE(at: offset) : data.readUInt32BE(at: offset)
        }
        let read64: (Int) -> UInt64? = { offset in
            littleEndian ? data.readUInt64LE(at: offset) : data.readUInt64BE(at: offset)
        }

        guard let machine = read16(18) else {
            throw BinaryLoaderError.invalidHeader
        }

        if is64Bit {
            guard let entry = read64(24),
                  let phoff = read64(32),
                  let shoff = read64(40),
                  let flags = read32(48),
                  let ehsize = read16(52),
                  let phentsize = read16(54),
                  let phnum = read16(56),
                  let shentsize = read16(58),
                  let shnum = read16(60),
                  let shstrndx = read16(62) else {
                throw BinaryLoaderError.invalidHeader
            }

            return ELFHeader(
                entry: entry, phoff: phoff, shoff: shoff,
                flags: flags, ehsize: ehsize, phentsize: phentsize,
                phnum: phnum, shentsize: shentsize, shnum: shnum,
                shstrndx: shstrndx, machine: machine
            )
        } else {
            guard let entry = read32(24),
                  let phoff = read32(28),
                  let shoff = read32(32),
                  let flags = read32(36),
                  let ehsize = read16(40),
                  let phentsize = read16(42),
                  let phnum = read16(44),
                  let shentsize = read16(46),
                  let shnum = read16(48),
                  let shstrndx = read16(50) else {
                throw BinaryLoaderError.invalidHeader
            }

            return ELFHeader(
                entry: UInt64(entry), phoff: UInt64(phoff), shoff: UInt64(shoff),
                flags: flags, ehsize: ehsize, phentsize: phentsize,
                phnum: phnum, shentsize: shentsize, shnum: shnum,
                shstrndx: shstrndx, machine: machine
            )
        }
    }

    // MARK: - Program Headers

    private func parseProgramHeaders(
        data: Data,
        offset: Int,
        count: Int,
        entrySize: Int,
        is64Bit: Bool,
        littleEndian: Bool
    ) throws -> [Segment] {
        let read32: (Int) -> UInt32? = { off in
            littleEndian ? data.readUInt32LE(at: off) : data.readUInt32BE(at: off)
        }
        let read64: (Int) -> UInt64? = { off in
            littleEndian ? data.readUInt64LE(at: off) : data.readUInt64BE(at: off)
        }

        var segments: [Segment] = []

        for i in 0..<count {
            let phOffset = offset + i * entrySize

            guard let pType = read32(phOffset) else { continue }

            // Only process LOAD segments
            guard pType == PT_LOAD else { continue }

            let vaddr: UInt64
            let memsz: UInt64
            let fileOffset: UInt64
            let filesz: UInt64
            let flags: UInt32

            if is64Bit {
                guard let f = read32(phOffset + 4),
                      let off = read64(phOffset + 8),
                      let va = read64(phOffset + 16),
                      let fsz = read64(phOffset + 32),
                      let msz = read64(phOffset + 40) else { continue }
                flags = f
                fileOffset = off
                vaddr = va
                filesz = fsz
                memsz = msz
            } else {
                guard let off = read32(phOffset + 4),
                      let va = read32(phOffset + 8),
                      let fsz = read32(phOffset + 16),
                      let msz = read32(phOffset + 20),
                      let f = read32(phOffset + 24) else { continue }
                flags = f
                fileOffset = UInt64(off)
                vaddr = UInt64(va)
                filesz = UInt64(fsz)
                memsz = UInt64(msz)
            }

            // Convert ELF flags to protection
            let prot = flags  // PF_X=1, PF_W=2, PF_R=4

            segments.append(Segment(
                name: "LOAD",
                address: vaddr,
                size: memsz,
                fileOffset: fileOffset,
                fileSize: filesz,
                maxProtection: prot,
                initProtection: prot
            ))
        }

        return segments
    }

    // MARK: - Section Headers

    private func parseSectionHeaders(
        data: Data,
        offset: Int,
        count: Int,
        entrySize: Int,
        stringTableIndex: Int,
        is64Bit: Bool,
        littleEndian: Bool
    ) throws -> ([Section], Data) {
        let read32: (Int) -> UInt32? = { off in
            littleEndian ? data.readUInt32LE(at: off) : data.readUInt32BE(at: off)
        }
        let read64: (Int) -> UInt64? = { off in
            littleEndian ? data.readUInt64LE(at: off) : data.readUInt64BE(at: off)
        }

        // First, get the string table
        let strTabOffset = offset + stringTableIndex * entrySize
        let strTabFileOffset: UInt64
        let strTabSize: UInt64

        if is64Bit {
            guard let off = read64(strTabOffset + 24),
                  let sz = read64(strTabOffset + 32) else {
                throw BinaryLoaderError.corruptedFile("Invalid string table")
            }
            strTabFileOffset = off
            strTabSize = sz
        } else {
            guard let off = read32(strTabOffset + 16),
                  let sz = read32(strTabOffset + 20) else {
                throw BinaryLoaderError.corruptedFile("Invalid string table")
            }
            strTabFileOffset = UInt64(off)
            strTabSize = UInt64(sz)
        }

        let stringTable = data.subdata(in: Int(strTabFileOffset)..<Int(strTabFileOffset + strTabSize))

        var sections: [Section] = []

        for i in 0..<count {
            let shOffset = offset + i * entrySize

            guard let nameOffset = read32(shOffset),
                  let shType = read32(shOffset + 4) else { continue }

            // Skip NULL sections
            guard shType != 0 else { continue }

            let shFlags: UInt64
            let addr: UInt64
            let fileOffset: UInt64
            let size: UInt64
            let align: UInt32

            if is64Bit {
                guard let f = read64(shOffset + 8),
                      let a = read64(shOffset + 16),
                      let off = read64(shOffset + 24),
                      let sz = read64(shOffset + 32),
                      let al = read64(shOffset + 48) else { continue }
                shFlags = f
                addr = a
                fileOffset = off
                size = sz
                align = UInt32(al)
            } else {
                guard let f = read32(shOffset + 8),
                      let a = read32(shOffset + 12),
                      let off = read32(shOffset + 16),
                      let sz = read32(shOffset + 20),
                      let al = read32(shOffset + 32) else { continue }
                shFlags = UInt64(f)
                addr = UInt64(a)
                fileOffset = UInt64(off)
                size = UInt64(sz)
                align = al
            }

            // Read section name
            let name = stringTable.readCString(at: Int(nameOffset)) ?? ""

            // Read section data
            let sectionData: Data
            if size > 0 && fileOffset > 0 && Int(fileOffset + size) <= data.count {
                sectionData = data.subdata(in: Int(fileOffset)..<Int(fileOffset + size))
            } else {
                sectionData = Data()
            }

            // Convert flags
            let flags = UInt32(shFlags & 0xFFFFFFFF)
            let isExec = (shFlags & SHF_EXECINSTR) != 0

            sections.append(Section(
                name: name,
                segmentName: "",
                address: addr,
                size: size,
                offset: UInt32(fileOffset),
                alignment: align,
                flags: isExec ? (flags | 0x80000000) : flags,
                data: sectionData
            ))
        }

        return (sections, stringTable)
    }

    // MARK: - Symbol Parsing

    private func parseSymbols(
        data: Data,
        sections: [Section],
        is64Bit: Bool,
        littleEndian: Bool
    ) throws -> [Symbol] {
        let read16: (Int) -> UInt16? = { off in
            littleEndian ? data.readUInt16LE(at: off) : data.readUInt16BE(at: off)
        }
        let read32: (Int) -> UInt32? = { off in
            littleEndian ? data.readUInt32LE(at: off) : data.readUInt32BE(at: off)
        }
        let read64: (Int) -> UInt64? = { off in
            littleEndian ? data.readUInt64LE(at: off) : data.readUInt64BE(at: off)
        }

        var symbols: [Symbol] = []

        // Find symbol tables
        for (index, section) in sections.enumerated() {
            guard section.name == ".symtab" || section.name == ".dynsym" else { continue }

            // Find associated string table
            let strTabSection: Section?
            if section.name == ".symtab" {
                strTabSection = sections.first { $0.name == ".strtab" }
            } else {
                strTabSection = sections.first { $0.name == ".dynstr" }
            }

            guard let strTab = strTabSection else { continue }

            let symSize = is64Bit ? 24 : 16
            let symCount = Int(section.size) / symSize

            for i in 0..<symCount {
                let symOffset = Int(section.offset) + i * symSize

                guard let nameIdx = read32(symOffset) else { continue }

                let info: UInt8
                let value: UInt64
                let size: UInt64

                if is64Bit {
                    guard let inf = data.readUInt8(at: symOffset + 4),
                          let val = read64(symOffset + 8),
                          let sz = read64(symOffset + 16) else { continue }
                    info = inf
                    value = val
                    size = sz
                } else {
                    guard let val = read32(symOffset + 4),
                          let sz = read32(symOffset + 8),
                          let inf = data.readUInt8(at: symOffset + 12) else { continue }
                    info = inf
                    value = UInt64(val)
                    size = UInt64(sz)
                }

                // Parse info byte
                let symBind = info >> 4
                let symType = info & 0xF

                // Read name
                let name = strTab.data.readCString(at: Int(nameIdx)) ?? ""
                guard !name.isEmpty else { continue }

                let type: SymbolType
                switch symType {
                case STT_FUNC:
                    type = .function
                case STT_OBJECT:
                    type = .object
                default:
                    type = .unknown
                }

                let binding: SymbolBinding
                switch symBind {
                case STB_LOCAL:
                    binding = .local
                case STB_GLOBAL:
                    binding = value == 0 ? .external : .global
                case STB_WEAK:
                    binding = .weak
                default:
                    binding = .local
                }

                symbols.append(Symbol(
                    name: name,
                    address: value,
                    size: size,
                    type: type,
                    binding: binding,
                    section: nil
                ))
            }
        }

        return symbols
    }

    // MARK: - Helpers

    private func mapMachine(_ machine: UInt16) -> Architecture {
        switch machine {
        case EM_X86_64:
            return .x86_64
        case EM_AARCH64:
            return .arm64
        case EM_386:
            return .i386
        case EM_ARM:
            return .armv7
        default:
            return .unknown
        }
    }
}
