import Foundation

/// PE/COFF binary format loader (Windows executables)
class PELoader: BinaryLoaderProtocol {

    // MARK: - PE Constants

    private let MZ_MAGIC: UInt16 = 0x5A4D  // "MZ"
    private let PE_SIGNATURE: UInt32 = 0x00004550  // "PE\0\0"

    // Machine types
    private let IMAGE_FILE_MACHINE_I386: UInt16 = 0x014C
    private let IMAGE_FILE_MACHINE_AMD64: UInt16 = 0x8664
    private let IMAGE_FILE_MACHINE_ARM: UInt16 = 0x01C0
    private let IMAGE_FILE_MACHINE_ARM64: UInt16 = 0xAA64

    // Optional header magic
    private let PE32_MAGIC: UInt16 = 0x10B
    private let PE32PLUS_MAGIC: UInt16 = 0x20B

    // Section characteristics
    private let IMAGE_SCN_CNT_CODE: UInt32 = 0x00000020
    private let IMAGE_SCN_MEM_EXECUTE: UInt32 = 0x20000000
    private let IMAGE_SCN_MEM_READ: UInt32 = 0x40000000
    private let IMAGE_SCN_MEM_WRITE: UInt32 = 0x80000000

    // MARK: - Protocol Implementation

    func canLoad(data: Data) -> Bool {
        guard data.count >= 2 else { return false }
        guard let magic = data.readUInt16LE(at: 0) else { return false }
        return magic == MZ_MAGIC
    }

    func load(from url: URL, data: Data) async throws -> BinaryFile {
        // Check DOS header
        guard let dosHeader = data.readUInt16LE(at: 0),
              dosHeader == MZ_MAGIC else {
            throw BinaryLoaderError.invalidHeader
        }

        // Get PE header offset from DOS header
        guard let peOffset = data.readUInt32LE(at: 0x3C) else {
            throw BinaryLoaderError.invalidHeader
        }

        // Check PE signature
        guard let peSignature = data.readUInt32LE(at: Int(peOffset)),
              peSignature == PE_SIGNATURE else {
            throw BinaryLoaderError.invalidHeader
        }

        let coffOffset = Int(peOffset) + 4

        // Parse COFF header
        guard let machine = data.readUInt16LE(at: coffOffset),
              let numberOfSections = data.readUInt16LE(at: coffOffset + 2),
              let sizeOfOptionalHeader = data.readUInt16LE(at: coffOffset + 16),
              let characteristics = data.readUInt16LE(at: coffOffset + 18) else {
            throw BinaryLoaderError.invalidHeader
        }

        let optionalHeaderOffset = coffOffset + 20

        // Parse optional header
        guard let optionalMagic = data.readUInt16LE(at: optionalHeaderOffset) else {
            throw BinaryLoaderError.invalidHeader
        }

        let is64Bit = optionalMagic == PE32PLUS_MAGIC

        // Parse optional header fields
        let entryPoint: UInt64
        let imageBase: UInt64
        let sectionAlignment: UInt32
        let fileAlignment: UInt32

        if is64Bit {
            guard let ep = data.readUInt32LE(at: optionalHeaderOffset + 16),
                  let ib = data.readUInt64LE(at: optionalHeaderOffset + 24),
                  let sa = data.readUInt32LE(at: optionalHeaderOffset + 32),
                  let fa = data.readUInt32LE(at: optionalHeaderOffset + 36) else {
                throw BinaryLoaderError.invalidHeader
            }
            imageBase = ib
            entryPoint = imageBase + UInt64(ep)
            sectionAlignment = sa
            fileAlignment = fa
        } else {
            guard let ep = data.readUInt32LE(at: optionalHeaderOffset + 16),
                  let ib = data.readUInt32LE(at: optionalHeaderOffset + 28),
                  let sa = data.readUInt32LE(at: optionalHeaderOffset + 32),
                  let fa = data.readUInt32LE(at: optionalHeaderOffset + 36) else {
                throw BinaryLoaderError.invalidHeader
            }
            imageBase = UInt64(ib)
            entryPoint = imageBase + UInt64(ep)
            sectionAlignment = sa
            fileAlignment = fa
        }

        // Parse sections
        let sectionHeaderOffset = optionalHeaderOffset + Int(sizeOfOptionalHeader)
        let (sections, segments) = try parseSections(
            data: data,
            offset: sectionHeaderOffset,
            count: Int(numberOfSections),
            imageBase: imageBase
        )

        // Parse symbols (if present)
        let symbols = try parseSymbols(data: data, coffOffset: coffOffset, is64Bit: is64Bit)

        return BinaryFile(
            url: url,
            format: .pe,
            architecture: mapMachine(machine),
            endianness: .little,
            is64Bit: is64Bit,
            fileSize: data.count,
            entryPoint: entryPoint,
            baseAddress: imageBase,
            sections: sections,
            segments: segments,
            symbols: symbols,
            data: data
        )
    }

    // MARK: - Section Parsing

    private func parseSections(
        data: Data,
        offset: Int,
        count: Int,
        imageBase: UInt64
    ) throws -> ([Section], [Segment]) {
        var sections: [Section] = []
        var segments: [Segment] = []

        for i in 0..<count {
            let sectOffset = offset + i * 40

            // Read section name (8 bytes, null-padded)
            let nameData = data.subdata(in: sectOffset..<(sectOffset + 8))
            let name = String(data: nameData, encoding: .utf8)?
                .trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""

            guard let virtualSize = data.readUInt32LE(at: sectOffset + 8),
                  let virtualAddress = data.readUInt32LE(at: sectOffset + 12),
                  let sizeOfRawData = data.readUInt32LE(at: sectOffset + 16),
                  let pointerToRawData = data.readUInt32LE(at: sectOffset + 20),
                  let characteristics = data.readUInt32LE(at: sectOffset + 36) else {
                continue
            }

            let addr = imageBase + UInt64(virtualAddress)
            let size = max(virtualSize, sizeOfRawData)

            // Read section data
            let sectionData: Data
            if sizeOfRawData > 0 && pointerToRawData > 0 {
                let start = Int(pointerToRawData)
                let end = min(start + Int(sizeOfRawData), data.count)
                if start < end {
                    sectionData = data.subdata(in: start..<end)
                } else {
                    sectionData = Data()
                }
            } else {
                sectionData = Data()
            }

            // Convert characteristics to flags
            let isCode = (characteristics & IMAGE_SCN_CNT_CODE) != 0 ||
                        (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
            let flags: UInt32 = isCode ? 0x80000000 : 0

            sections.append(Section(
                name: name,
                segmentName: "",
                address: addr,
                size: UInt64(size),
                offset: pointerToRawData,
                alignment: 0,
                flags: flags,
                data: sectionData
            ))

            // Create corresponding segment
            let protection = characteristicsToProtection(characteristics)
            segments.append(Segment(
                name: name,
                address: addr,
                size: UInt64(size),
                fileOffset: UInt64(pointerToRawData),
                fileSize: UInt64(sizeOfRawData),
                maxProtection: protection,
                initProtection: protection
            ))
        }

        return (sections, segments)
    }

    // MARK: - Symbol Parsing

    private func parseSymbols(data: Data, coffOffset: Int, is64Bit: Bool) throws -> [Symbol] {
        guard let pointerToSymbolTable = data.readUInt32LE(at: coffOffset + 8),
              let numberOfSymbols = data.readUInt32LE(at: coffOffset + 12),
              pointerToSymbolTable > 0, numberOfSymbols > 0 else {
            return []
        }

        var symbols: [Symbol] = []

        // String table is right after symbol table
        let stringTableOffset = Int(pointerToSymbolTable) + Int(numberOfSymbols) * 18

        var i = 0
        while i < numberOfSymbols {
            let symOffset = Int(pointerToSymbolTable) + i * 18

            // Read symbol name
            let nameBytes = data.subdata(in: symOffset..<(symOffset + 8))
            let name: String

            // Check if name is inline or in string table
            if nameBytes[0] == 0 && nameBytes[1] == 0 && nameBytes[2] == 0 && nameBytes[3] == 0 {
                // Name is in string table
                guard let strOffset = data.readUInt32LE(at: symOffset + 4) else {
                    i += 1
                    continue
                }
                name = data.readCString(at: stringTableOffset + Int(strOffset)) ?? ""
            } else {
                name = String(data: nameBytes, encoding: .utf8)?
                    .trimmingCharacters(in: .init(charactersIn: "\0")) ?? ""
            }

            guard let value = data.readUInt32LE(at: symOffset + 8),
                  let sectionNumber = data.readUInt16LE(at: symOffset + 12),
                  let type = data.readUInt16LE(at: symOffset + 14),
                  let storageClass = data.readUInt8(at: symOffset + 16),
                  let numberOfAuxSymbols = data.readUInt8(at: symOffset + 17) else {
                i += 1
                continue
            }

            // Skip auxiliary symbols
            i += 1 + Int(numberOfAuxSymbols)

            guard !name.isEmpty else { continue }

            // Determine symbol type
            let symType: SymbolType
            if (type & 0x20) != 0 {
                symType = .function
            } else if sectionNumber > 0 {
                symType = .data
            } else {
                symType = .unknown
            }

            // Determine binding
            let binding: SymbolBinding
            switch storageClass {
            case 2:  // IMAGE_SYM_CLASS_EXTERNAL
                binding = sectionNumber == 0 ? .external : .global
            case 3:  // IMAGE_SYM_CLASS_STATIC
                binding = .local
            case 6:  // IMAGE_SYM_CLASS_LABEL
                binding = .local
            default:
                binding = .local
            }

            symbols.append(Symbol(
                name: name,
                address: UInt64(value),
                size: 0,
                type: symType,
                binding: binding,
                section: nil
            ))
        }

        return symbols
    }

    // MARK: - Helpers

    private func mapMachine(_ machine: UInt16) -> Architecture {
        switch machine {
        case IMAGE_FILE_MACHINE_AMD64:
            return .x86_64
        case IMAGE_FILE_MACHINE_ARM64:
            return .arm64
        case IMAGE_FILE_MACHINE_I386:
            return .i386
        case IMAGE_FILE_MACHINE_ARM:
            return .armv7
        default:
            return .unknown
        }
    }

    private func characteristicsToProtection(_ characteristics: UInt32) -> UInt32 {
        var prot: UInt32 = 0
        if (characteristics & IMAGE_SCN_MEM_READ) != 0 { prot |= 1 }
        if (characteristics & IMAGE_SCN_MEM_WRITE) != 0 { prot |= 2 }
        if (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0 { prot |= 4 }
        return prot
    }
}
