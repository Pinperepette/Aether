import Foundation

// MARK: - DWARF Debug Information Parser

/// Parser for DWARF debug information
class DWARFParser {

    // MARK: - DWARF Constants

    private enum DWARFTag: UInt16 {
        case compileUnit = 0x11
        case subprogram = 0x2e
        case variable = 0x34
        case formalParameter = 0x05
        case baseType = 0x24
        case pointerType = 0x0f
        case structureType = 0x13
        case arrayType = 0x01
        case typedefTag = 0x16
        case member = 0x0d
        case enumerationType = 0x04
        case enumerator = 0x28
        case lexicalBlock = 0x0b
        case inlinedSubroutine = 0x1d
    }

    private enum DWARFAttribute: UInt16 {
        case name = 0x03
        case lowPC = 0x11
        case highPC = 0x12
        case type = 0x49
        case location = 0x02
        case byteSize = 0x0b
        case encoding = 0x3e
        case declFile = 0x3a
        case declLine = 0x3b
        case external = 0x3f
        case frameBase = 0x40
        case linkageName = 0x6e
        case artificial = 0x34
    }

    private enum DWARFForm: UInt8 {
        case addr = 0x01
        case data2 = 0x05
        case data4 = 0x06
        case data8 = 0x07
        case string = 0x08
        case strp = 0x0e
        case udata = 0x0f
        case refAddr = 0x10
        case ref1 = 0x11
        case ref2 = 0x12
        case ref4 = 0x13
        case ref8 = 0x14
        case secOffset = 0x17
        case exprloc = 0x18
        case flag = 0x0c
        case flagPresent = 0x19
    }

    // MARK: - Debug Information Models

    struct DebugInfo {
        var compileUnits: [CompileUnit]
        var functions: [DebugFunction]
        var types: [DebugType]
        var variables: [DebugVariable]
        var sourceFiles: [String]
        var lineInfo: [LineInfo]
    }

    struct CompileUnit {
        let name: String
        let compDir: String
        let producer: String
        let language: String
        let lowPC: UInt64
        let highPC: UInt64
    }

    struct DebugFunction {
        let name: String
        let linkageName: String?
        let startAddress: UInt64
        let endAddress: UInt64
        let returnType: String?
        let parameters: [DebugParameter]
        let localVariables: [DebugVariable]
        let sourceFile: String?
        let sourceLine: Int?
        let isExternal: Bool
        let frameBase: FrameBase?
    }

    struct DebugParameter {
        let name: String
        let type: String
        let location: VariableLocation?
    }

    struct DebugVariable {
        let name: String
        let type: String
        let location: VariableLocation?
        let sourceFile: String?
        let sourceLine: Int?
        let scope: VariableScope
    }

    enum VariableScope {
        case global
        case local(functionAddress: UInt64)
        case parameter(functionAddress: UInt64)
    }

    struct DebugType {
        let name: String
        let size: Int
        let kind: TypeKind
        let members: [TypeMember]?
    }

    enum TypeKind {
        case base(encoding: String)
        case pointer(pointeeType: String)
        case structure
        case array(elementType: String, count: Int?)
        case enumeration
        case typedef(underlyingType: String)
        case function(returnType: String, paramTypes: [String])
    }

    struct TypeMember {
        let name: String
        let type: String
        let offset: Int
        let bitSize: Int?
        let bitOffset: Int?
    }

    struct VariableLocation {
        enum LocationKind {
            case register(String)
            case frameOffset(Int)
            case address(UInt64)
            case expression([UInt8])
        }

        let kind: LocationKind
        let startAddress: UInt64?
        let endAddress: UInt64?
    }

    struct FrameBase {
        let kind: VariableLocation.LocationKind
    }

    struct LineInfo {
        let address: UInt64
        let file: String
        let line: Int
        let column: Int
        let isStatement: Bool
        let isBasicBlockStart: Bool
        let isPrologueEnd: Bool
        let isEpilogueBegin: Bool
    }

    // MARK: - Parsing

    /// Parse DWARF debug information from a binary
    func parse(binary: BinaryFile) -> DebugInfo? {
        // Find DWARF sections
        guard let debugInfoSection = findDWARFSection(binary, name: "__debug_info", altName: ".debug_info"),
              let debugAbbrevSection = findDWARFSection(binary, name: "__debug_abbrev", altName: ".debug_abbrev"),
              let debugStrSection = findDWARFSection(binary, name: "__debug_str", altName: ".debug_str") else {
            return nil
        }

        let debugLineSection = findDWARFSection(binary, name: "__debug_line", altName: ".debug_line")

        var info = DebugInfo(
            compileUnits: [],
            functions: [],
            types: [],
            variables: [],
            sourceFiles: [],
            lineInfo: []
        )

        // Parse abbreviation tables
        let abbreviations = parseAbbreviations(debugAbbrevSection.data)

        // Parse string table
        let strings = debugStrSection.data

        // Parse compile units
        var offset = 0
        while offset < debugInfoSection.data.count {
            if let (cu, newOffset) = parseCompileUnit(
                data: debugInfoSection.data,
                offset: offset,
                abbreviations: abbreviations,
                strings: strings,
                binary: binary,
                info: &info
            ) {
                info.compileUnits.append(cu)
                offset = newOffset
            } else {
                break
            }
        }

        // Parse line number information
        if let lineSection = debugLineSection {
            info.lineInfo = parseLineInfo(lineSection.data, binary: binary)
        }

        return info
    }

    // MARK: - Section Finding

    private func findDWARFSection(_ binary: BinaryFile, name: String, altName: String) -> Section? {
        return binary.sections.first { $0.name == name || $0.name == altName }
    }

    // MARK: - Abbreviation Parsing

    private struct Abbreviation {
        let code: UInt64
        let tag: UInt16
        let hasChildren: Bool
        let attributes: [(attribute: UInt16, form: UInt8)]
    }

    private func parseAbbreviations(_ data: Data) -> [UInt64: Abbreviation] {
        var abbreviations: [UInt64: Abbreviation] = [:]
        var offset = 0

        while offset < data.count {
            let (code, codeSize) = readULEB128(data, offset: offset)
            offset += codeSize

            if code == 0 { continue }

            let (tag, tagSize) = readULEB128(data, offset: offset)
            offset += tagSize

            guard offset < data.count else { break }
            let hasChildren = data[data.startIndex + offset] != 0
            offset += 1

            var attributes: [(UInt16, UInt8)] = []

            while offset < data.count {
                let (attr, attrSize) = readULEB128(data, offset: offset)
                offset += attrSize

                let (form, formSize) = readULEB128(data, offset: offset)
                offset += formSize

                if attr == 0 && form == 0 { break }

                attributes.append((UInt16(attr), UInt8(form)))
            }

            abbreviations[code] = Abbreviation(
                code: code,
                tag: UInt16(tag),
                hasChildren: hasChildren,
                attributes: attributes
            )
        }

        return abbreviations
    }

    // MARK: - Compile Unit Parsing

    private func parseCompileUnit(
        data: Data,
        offset: Int,
        abbreviations: [UInt64: Abbreviation],
        strings: Data,
        binary: BinaryFile,
        info: inout DebugInfo
    ) -> (CompileUnit, Int)? {
        guard offset + 11 < data.count else { return nil }

        // Read unit header
        guard let unitLength = data.readUInt32LE(at: offset) else { return nil }
        var headerOffset = offset + 4

        let is64Bit = unitLength == 0xFFFFFFFF
        let actualLength: UInt64

        if is64Bit {
            guard let len64 = data.readUInt64LE(at: headerOffset) else { return nil }
            actualLength = len64
            headerOffset += 8
        } else {
            actualLength = UInt64(unitLength)
        }

        guard let version = data.readUInt16LE(at: headerOffset) else { return nil }
        headerOffset += 2

        guard let abbrevOffset = data.readUInt32LE(at: headerOffset) else { return nil }
        headerOffset += 4

        guard let addressSize = data.readUInt8(at: headerOffset) else { return nil }
        headerOffset += 1

        // Parse DIEs (Debug Information Entries)
        var cu = CompileUnit(
            name: "",
            compDir: "",
            producer: "",
            language: "",
            lowPC: 0,
            highPC: 0
        )

        let endOffset = offset + 4 + Int(actualLength)
        var dieOffset = headerOffset

        // Simplified DIE parsing - just get basic info
        while dieOffset < endOffset {
            let (abbrevCode, codeSize) = readULEB128(data, offset: dieOffset)
            dieOffset += codeSize

            if abbrevCode == 0 { continue }

            guard let abbrev = abbreviations[abbrevCode] else { break }

            // Parse attributes
            for (attr, form) in abbrev.attributes {
                let (value, size) = readAttributeValue(
                    data: data,
                    offset: dieOffset,
                    form: form,
                    addressSize: Int(addressSize),
                    strings: strings
                )
                dieOffset += size

                // Extract relevant information based on tag
                if abbrev.tag == DWARFTag.subprogram.rawValue {
                    // Function
                    if let funcInfo = extractFunctionInfo(
                        attr: attr,
                        value: value,
                        binary: binary
                    ) {
                        // Add to functions list
                    }
                }
            }
        }

        return (cu, endOffset)
    }

    // MARK: - Line Number Parsing

    private func parseLineInfo(_ data: Data, binary: BinaryFile) -> [LineInfo] {
        var lineInfo: [LineInfo] = []
        var offset = 0

        while offset < data.count {
            guard let header = parseLineHeader(data: data, offset: offset) else { break }

            let programStart = offset + header.headerLength
            let programEnd = offset + header.unitLength + (header.is64Bit ? 12 : 4)

            // Parse line number program
            var state = LineState(
                address: 0,
                file: 1,
                line: 1,
                column: 0,
                isStatement: header.defaultIsStmt,
                isBasicBlock: false,
                isPrologueEnd: false,
                isEpilogueBegin: false,
                endSequence: false
            )

            var programOffset = programStart
            while programOffset < programEnd && programOffset < data.count {
                guard let opcode = data.readUInt8(at: programOffset) else { break }
                programOffset += 1

                if opcode == 0 {
                    // Extended opcode
                    let (extLen, lenSize) = readULEB128(data, offset: programOffset)
                    programOffset += lenSize
                    guard programOffset < data.count else { break }
                    let extOpcode = data[data.startIndex + programOffset]
                    programOffset += 1

                    switch extOpcode {
                    case 1: // DW_LNE_end_sequence
                        state.endSequence = true
                        if let fileName = header.fileNames.indices.contains(Int(state.file) - 1) ? header.fileNames[Int(state.file) - 1] : nil {
                            lineInfo.append(LineInfo(
                                address: state.address,
                                file: fileName,
                                line: Int(state.line),
                                column: Int(state.column),
                                isStatement: state.isStatement,
                                isBasicBlockStart: state.isBasicBlock,
                                isPrologueEnd: state.isPrologueEnd,
                                isEpilogueBegin: state.isEpilogueBegin
                            ))
                        }
                        state = LineState(address: 0, file: 1, line: 1, column: 0,
                                         isStatement: header.defaultIsStmt, isBasicBlock: false,
                                         isPrologueEnd: false, isEpilogueBegin: false, endSequence: false)
                    case 2: // DW_LNE_set_address
                        if header.addressSize == 8 {
                            state.address = data.readUInt64LE(at: programOffset) ?? 0
                            programOffset += 8
                        } else {
                            state.address = UInt64(data.readUInt32LE(at: programOffset) ?? 0)
                            programOffset += 4
                        }
                    case 4: // DW_LNE_set_discriminator
                        let (_, discSize) = readULEB128(data, offset: programOffset)
                        programOffset += discSize
                    default:
                        programOffset += Int(extLen) - 1
                    }
                } else if opcode < header.opcodeBase {
                    // Standard opcode
                    switch opcode {
                    case 1: // DW_LNS_copy
                        if let fileName = header.fileNames.indices.contains(Int(state.file) - 1) ? header.fileNames[Int(state.file) - 1] : nil {
                            lineInfo.append(LineInfo(
                                address: state.address,
                                file: fileName,
                                line: Int(state.line),
                                column: Int(state.column),
                                isStatement: state.isStatement,
                                isBasicBlockStart: state.isBasicBlock,
                                isPrologueEnd: state.isPrologueEnd,
                                isEpilogueBegin: state.isEpilogueBegin
                            ))
                        }
                        state.isBasicBlock = false
                        state.isPrologueEnd = false
                        state.isEpilogueBegin = false
                    case 2: // DW_LNS_advance_pc
                        let (adv, advSize) = readULEB128(data, offset: programOffset)
                        programOffset += advSize
                        state.address += adv * UInt64(header.minInstructionLength)
                    case 3: // DW_LNS_advance_line
                        let (lineAdv, lineSize) = readSLEB128(data, offset: programOffset)
                        programOffset += lineSize
                        state.line = UInt64(Int64(state.line) + lineAdv)
                    case 4: // DW_LNS_set_file
                        let (fileNum, fileSize) = readULEB128(data, offset: programOffset)
                        programOffset += fileSize
                        state.file = fileNum
                    case 5: // DW_LNS_set_column
                        let (col, colSize) = readULEB128(data, offset: programOffset)
                        programOffset += colSize
                        state.column = col
                    case 6: // DW_LNS_negate_stmt
                        state.isStatement = !state.isStatement
                    case 7: // DW_LNS_set_basic_block
                        state.isBasicBlock = true
                    case 8: // DW_LNS_const_add_pc
                        let adjustedOpcode = Int(255) - Int(header.opcodeBase)
                        let addrIncrement = (adjustedOpcode / Int(header.lineRange)) * Int(header.minInstructionLength)
                        state.address += UInt64(addrIncrement)
                    case 9: // DW_LNS_fixed_advance_pc
                        let advance = data.readUInt16LE(at: programOffset) ?? 0
                        programOffset += 2
                        state.address += UInt64(advance)
                    case 10: // DW_LNS_set_prologue_end
                        state.isPrologueEnd = true
                    case 11: // DW_LNS_set_epilogue_begin
                        state.isEpilogueBegin = true
                    default:
                        // Skip unknown standard opcode operands
                        if Int(opcode) - 1 < header.standardOpcodeLengths.count {
                            let argCount = header.standardOpcodeLengths[Int(opcode) - 1]
                            for _ in 0..<argCount {
                                let (_, argSize) = readULEB128(data, offset: programOffset)
                                programOffset += argSize
                            }
                        }
                    }
                } else {
                    // Special opcode
                    let adjustedOpcode = Int(opcode) - Int(header.opcodeBase)
                    let addrIncrement = (adjustedOpcode / Int(header.lineRange)) * Int(header.minInstructionLength)
                    let lineIncrement = Int(header.lineBase) + (adjustedOpcode % Int(header.lineRange))
                    state.address += UInt64(addrIncrement)
                    state.line = UInt64(Int64(state.line) + Int64(lineIncrement))

                    if let fileName = header.fileNames.indices.contains(Int(state.file) - 1) ? header.fileNames[Int(state.file) - 1] : nil {
                        lineInfo.append(LineInfo(
                            address: state.address,
                            file: fileName,
                            line: Int(state.line),
                            column: Int(state.column),
                            isStatement: state.isStatement,
                            isBasicBlockStart: state.isBasicBlock,
                            isPrologueEnd: state.isPrologueEnd,
                            isEpilogueBegin: state.isEpilogueBegin
                        ))
                    }
                    state.isBasicBlock = false
                    state.isPrologueEnd = false
                    state.isEpilogueBegin = false
                }
            }

            offset = programEnd
        }

        return lineInfo.sorted { $0.address < $1.address }
    }

    private struct LineState {
        var address: UInt64
        var file: UInt64
        var line: UInt64
        var column: UInt64
        var isStatement: Bool
        var isBasicBlock: Bool
        var isPrologueEnd: Bool
        var isEpilogueBegin: Bool
        var endSequence: Bool
    }

    private struct LineHeader {
        var unitLength: Int
        var is64Bit: Bool
        var version: UInt16
        var headerLength: Int
        var minInstructionLength: UInt8
        var maxOpsPerInstruction: UInt8
        var defaultIsStmt: Bool
        var lineBase: Int8
        var lineRange: UInt8
        var opcodeBase: UInt8
        var standardOpcodeLengths: [UInt8]
        var includeDirectories: [String]
        var fileNames: [String]
        var addressSize: Int
    }

    private func parseLineHeader(data: Data, offset: Int) -> LineHeader? {
        var idx = offset

        guard let unitLength32 = data.readUInt32LE(at: idx) else { return nil }
        idx += 4

        var unitLength: Int
        var is64Bit = false

        if unitLength32 == 0xFFFFFFFF {
            guard let unitLength64 = data.readUInt64LE(at: idx) else { return nil }
            unitLength = Int(unitLength64)
            is64Bit = true
            idx += 8
        } else {
            unitLength = Int(unitLength32)
        }

        guard let version = data.readUInt16LE(at: idx) else { return nil }
        idx += 2

        var addressSize: Int = 8
        var segmentSelectorSize: UInt8 = 0

        if version >= 5 {
            guard let addrSize = data.readUInt8(at: idx) else { return nil }
            addressSize = Int(addrSize)
            idx += 1
            segmentSelectorSize = data.readUInt8(at: idx) ?? 0
            idx += 1
        }

        let headerLengthSize = is64Bit ? 8 : 4
        let headerLength: Int
        if is64Bit {
            headerLength = Int(data.readUInt64LE(at: idx) ?? 0)
        } else {
            headerLength = Int(data.readUInt32LE(at: idx) ?? 0)
        }
        idx += headerLengthSize

        let headerStart = idx

        guard let minInstLen = data.readUInt8(at: idx) else { return nil }
        idx += 1

        var maxOpsPerInst: UInt8 = 1
        if version >= 4 {
            maxOpsPerInst = data.readUInt8(at: idx) ?? 1
            idx += 1
        }

        let defaultIsStmt = (data.readUInt8(at: idx) ?? 0) != 0
        idx += 1

        let lineBase = Int8(bitPattern: data.readUInt8(at: idx) ?? 0)
        idx += 1

        guard let lineRange = data.readUInt8(at: idx) else { return nil }
        idx += 1

        guard let opcodeBase = data.readUInt8(at: idx) else { return nil }
        idx += 1

        var standardOpcodeLengths: [UInt8] = []
        for _ in 1..<opcodeBase {
            guard let len = data.readUInt8(at: idx) else { break }
            standardOpcodeLengths.append(len)
            idx += 1
        }

        var includeDirectories: [String] = []
        var fileNames: [String] = []

        if version >= 5 {
            // DWARF 5 format
            guard let dirEntryFormatCount = data.readUInt8(at: idx) else { return nil }
            idx += 1
            // Skip directory entry format
            for _ in 0..<dirEntryFormatCount {
                let (_, s1) = readULEB128(data, offset: idx)
                idx += s1
                let (_, s2) = readULEB128(data, offset: idx)
                idx += s2
            }
            let (dirCount, dirCountSize) = readULEB128(data, offset: idx)
            idx += dirCountSize
            for _ in 0..<dirCount {
                if let str = data.readCString(at: idx) {
                    includeDirectories.append(str)
                    idx += str.utf8.count + 1
                }
            }

            guard let fileEntryFormatCount = data.readUInt8(at: idx) else { return nil }
            idx += 1
            for _ in 0..<fileEntryFormatCount {
                let (_, s1) = readULEB128(data, offset: idx)
                idx += s1
                let (_, s2) = readULEB128(data, offset: idx)
                idx += s2
            }
            let (fileCount, fileCountSize) = readULEB128(data, offset: idx)
            idx += fileCountSize
            for _ in 0..<fileCount {
                if let str = data.readCString(at: idx) {
                    fileNames.append(str)
                    idx += str.utf8.count + 1
                }
            }
        } else {
            // DWARF 4 and earlier
            while idx < data.count {
                if let str = data.readCString(at: idx), !str.isEmpty {
                    includeDirectories.append(str)
                    idx += str.utf8.count + 1
                } else {
                    idx += 1
                    break
                }
            }

            while idx < data.count {
                if let str = data.readCString(at: idx), !str.isEmpty {
                    fileNames.append(str)
                    idx += str.utf8.count + 1
                    // Skip directory index, time, size
                    let (_, s1) = readULEB128(data, offset: idx)
                    idx += s1
                    let (_, s2) = readULEB128(data, offset: idx)
                    idx += s2
                    let (_, s3) = readULEB128(data, offset: idx)
                    idx += s3
                } else {
                    idx += 1
                    break
                }
            }
        }

        return LineHeader(
            unitLength: unitLength,
            is64Bit: is64Bit,
            version: version,
            headerLength: headerStart + headerLength - offset,
            minInstructionLength: minInstLen,
            maxOpsPerInstruction: maxOpsPerInst,
            defaultIsStmt: defaultIsStmt,
            lineBase: lineBase,
            lineRange: lineRange,
            opcodeBase: opcodeBase,
            standardOpcodeLengths: standardOpcodeLengths,
            includeDirectories: includeDirectories,
            fileNames: fileNames,
            addressSize: addressSize
        )
    }

    // MARK: - Attribute Value Reading

    private func readAttributeValue(
        data: Data,
        offset: Int,
        form: UInt8,
        addressSize: Int,
        strings: Data
    ) -> (Any?, Int) {
        switch DWARFForm(rawValue: form) {
        case .addr:
            if addressSize == 8 {
                return (data.readUInt64LE(at: offset), 8)
            } else {
                return (data.readUInt32LE(at: offset).map { UInt64($0) }, 4)
            }

        case .data2:
            return (data.readUInt16LE(at: offset), 2)

        case .data4:
            return (data.readUInt32LE(at: offset), 4)

        case .data8:
            return (data.readUInt64LE(at: offset), 8)

        case .string:
            let str = data.readCString(at: offset) ?? ""
            return (str, str.utf8.count + 1)

        case .strp:
            if let strOffset = data.readUInt32LE(at: offset) {
                let str = strings.readCString(at: Int(strOffset)) ?? ""
                return (str, 4)
            }
            return (nil, 4)

        case .udata:
            let (value, size) = readULEB128(data, offset: offset)
            return (value, size)

        case .flag:
            return (data.readUInt8(at: offset) != 0, 1)

        case .flagPresent:
            return (true, 0)

        case .ref4:
            return (data.readUInt32LE(at: offset), 4)

        case .exprloc:
            let (length, lenSize) = readULEB128(data, offset: offset)
            let exprData = data.subdata(offset: offset + lenSize, count: Int(length))
            return (exprData, lenSize + Int(length))

        case .secOffset:
            return (data.readUInt32LE(at: offset), 4)

        default:
            return (nil, 0)
        }
    }

    // MARK: - DIE Parsing Context

    private class DIEContext {
        var name: String?
        var linkageName: String?
        var lowPC: UInt64?
        var highPC: UInt64?
        var returnType: String?
        var sourceFile: String?
        var sourceLine: Int?
        var isExternal: Bool = false
        var frameBase: FrameBase?
        var parameters: [DebugParameter] = []
        var localVariables: [DebugVariable] = []
        var typeName: String?
        var typeSize: Int?
        var location: VariableLocation?
    }

    private func parseDIEs(
        data: Data,
        offset: Int,
        endOffset: Int,
        abbreviations: [UInt64: Abbreviation],
        strings: Data,
        addressSize: Int,
        info: inout DebugInfo
    ) {
        var currentOffset = offset
        var contextStack: [DIEContext] = []
        var currentContext: DIEContext? = nil

        while currentOffset < endOffset {
            let (abbrevCode, codeSize) = readULEB128(data, offset: currentOffset)
            currentOffset += codeSize

            if abbrevCode == 0 {
                // End of siblings, pop context
                if let ctx = currentContext {
                    finalizeContext(ctx, info: &info)
                }
                currentContext = contextStack.popLast()
                continue
            }

            guard let abbrev = abbreviations[abbrevCode] else { break }

            let ctx = DIEContext()

            // Parse attributes
            for (attr, form) in abbrev.attributes {
                let (value, size) = readAttributeValue(
                    data: data,
                    offset: currentOffset,
                    form: form,
                    addressSize: addressSize,
                    strings: strings
                )
                currentOffset += size

                // Store attribute value in context
                switch DWARFAttribute(rawValue: attr) {
                case .name:
                    ctx.name = value as? String
                case .linkageName:
                    ctx.linkageName = value as? String
                case .lowPC:
                    ctx.lowPC = value as? UInt64
                case .highPC:
                    if let highPC = value as? UInt64 {
                        // highPC can be an address or an offset from lowPC
                        if form == DWARFForm.addr.rawValue {
                            ctx.highPC = highPC
                        } else if let lowPC = ctx.lowPC {
                            ctx.highPC = lowPC + highPC
                        } else {
                            ctx.highPC = highPC
                        }
                    }
                case .declFile:
                    if let fileNum = value as? UInt64 {
                        ctx.sourceFile = "file_\(fileNum)"
                    }
                case .declLine:
                    if let line = value as? UInt64 {
                        ctx.sourceLine = Int(line)
                    } else if let line = value as? UInt16 {
                        ctx.sourceLine = Int(line)
                    }
                case .external:
                    ctx.isExternal = (value as? Bool) ?? false
                case .byteSize:
                    if let size = value as? UInt64 {
                        ctx.typeSize = Int(size)
                    } else if let size = value as? UInt32 {
                        ctx.typeSize = Int(size)
                    }
                case .location:
                    if let exprData = value as? Data {
                        ctx.location = parseLocationExpression(exprData)
                    }
                case .frameBase:
                    if let exprData = value as? Data {
                        if let loc = parseLocationExpression(exprData) {
                            ctx.frameBase = FrameBase(kind: loc.kind)
                        }
                    }
                default:
                    break
                }
            }

            // Handle tag-specific processing
            switch DWARFTag(rawValue: abbrev.tag) {
            case .subprogram:
                if abbrev.hasChildren {
                    if let current = currentContext {
                        contextStack.append(current)
                    }
                    currentContext = ctx
                } else {
                    finalizeFunction(ctx, info: &info)
                }
            case .variable:
                if let parentCtx = currentContext {
                    if let name = ctx.name {
                        let variable = DebugVariable(
                            name: name,
                            type: ctx.typeName ?? "unknown",
                            location: ctx.location,
                            sourceFile: ctx.sourceFile,
                            sourceLine: ctx.sourceLine,
                            scope: .local(functionAddress: parentCtx.lowPC ?? 0)
                        )
                        parentCtx.localVariables.append(variable)
                    }
                } else if let name = ctx.name {
                    // Global variable
                    let variable = DebugVariable(
                        name: name,
                        type: ctx.typeName ?? "unknown",
                        location: ctx.location,
                        sourceFile: ctx.sourceFile,
                        sourceLine: ctx.sourceLine,
                        scope: .global
                    )
                    info.variables.append(variable)
                }
            case .formalParameter:
                if let parentCtx = currentContext, let name = ctx.name {
                    let param = DebugParameter(
                        name: name,
                        type: ctx.typeName ?? "unknown",
                        location: ctx.location
                    )
                    parentCtx.parameters.append(param)
                }
            case .baseType, .pointerType, .structureType, .arrayType, .typedefTag, .enumerationType:
                if let name = ctx.name {
                    let typeKind: TypeKind
                    switch DWARFTag(rawValue: abbrev.tag) {
                    case .baseType:
                        typeKind = .base(encoding: "int")
                    case .pointerType:
                        typeKind = .pointer(pointeeType: "void")
                    case .structureType:
                        typeKind = .structure
                    case .arrayType:
                        typeKind = .array(elementType: "unknown", count: nil)
                    case .typedefTag:
                        typeKind = .typedef(underlyingType: "unknown")
                    case .enumerationType:
                        typeKind = .enumeration
                    default:
                        typeKind = .base(encoding: "unknown")
                    }
                    let debugType = DebugType(
                        name: name,
                        size: ctx.typeSize ?? 0,
                        kind: typeKind,
                        members: nil
                    )
                    info.types.append(debugType)
                }
            default:
                break
            }

            // Handle children
            if abbrev.hasChildren && currentContext == nil {
                contextStack.append(ctx)
                currentContext = ctx
            }
        }

        // Finalize remaining contexts
        while let ctx = currentContext {
            finalizeContext(ctx, info: &info)
            currentContext = contextStack.popLast()
        }
    }

    private func finalizeContext(_ ctx: DIEContext, info: inout DebugInfo) {
        if ctx.lowPC != nil {
            finalizeFunction(ctx, info: &info)
        }
    }

    private func finalizeFunction(_ ctx: DIEContext, info: inout DebugInfo) {
        guard let name = ctx.name ?? ctx.linkageName,
              let lowPC = ctx.lowPC else { return }

        let highPC = ctx.highPC ?? (lowPC + 1)

        let function = DebugFunction(
            name: name,
            linkageName: ctx.linkageName,
            startAddress: lowPC,
            endAddress: highPC,
            returnType: ctx.returnType,
            parameters: ctx.parameters,
            localVariables: ctx.localVariables,
            sourceFile: ctx.sourceFile,
            sourceLine: ctx.sourceLine,
            isExternal: ctx.isExternal,
            frameBase: ctx.frameBase
        )
        info.functions.append(function)
    }

    private func parseLocationExpression(_ data: Data) -> VariableLocation? {
        guard data.count > 0 else { return nil }

        let opcode = data[data.startIndex]

        switch opcode {
        case 0x50...0x6F: // DW_OP_reg0-DW_OP_reg31
            let regNum = Int(opcode - 0x50)
            return VariableLocation(kind: .register(registerName(regNum)), startAddress: nil, endAddress: nil)
        case 0x70...0x8F: // DW_OP_breg0-DW_OP_breg31
            let regNum = Int(opcode - 0x70)
            if data.count > 1 {
                let (offset, _) = readSLEB128(data, offset: 1)
                return VariableLocation(kind: .frameOffset(Int(offset)), startAddress: nil, endAddress: nil)
            }
            return VariableLocation(kind: .register(registerName(regNum)), startAddress: nil, endAddress: nil)
        case 0x91: // DW_OP_fbreg
            if data.count > 1 {
                let (offset, _) = readSLEB128(data, offset: 1)
                return VariableLocation(kind: .frameOffset(Int(offset)), startAddress: nil, endAddress: nil)
            }
        case 0x03: // DW_OP_addr
            if data.count >= 9 {
                var addr: UInt64 = 0
                for i in 0..<8 {
                    addr |= UInt64(data[data.startIndex + 1 + i]) << (i * 8)
                }
                return VariableLocation(kind: .address(addr), startAddress: nil, endAddress: nil)
            }
        default:
            return VariableLocation(kind: .expression(Array(data)), startAddress: nil, endAddress: nil)
        }

        return nil
    }

    private func registerName(_ num: Int) -> String {
        // x86_64 register names
        let regs = ["rax", "rdx", "rcx", "rbx", "rsi", "rdi", "rbp", "rsp",
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        if num < regs.count {
            return regs[num]
        }
        return "reg\(num)"
    }

    private func extractFunctionInfo(attr: UInt16, value: Any?, binary: BinaryFile) -> DebugFunction? {
        // This method is kept for compatibility but main parsing is done in parseDIEs
        return nil
    }

    // MARK: - LEB128 Decoding

    private func readULEB128(_ data: Data, offset: Int) -> (UInt64, Int) {
        var result: UInt64 = 0
        var shift = 0
        var bytesRead = 0

        while offset + bytesRead < data.count {
            let byte = data[data.startIndex + offset + bytesRead]
            bytesRead += 1

            result |= UInt64(byte & 0x7F) << shift
            shift += 7

            if byte & 0x80 == 0 { break }
        }

        return (result, bytesRead)
    }

    private func readSLEB128(_ data: Data, offset: Int) -> (Int64, Int) {
        var result: Int64 = 0
        var shift = 0
        var bytesRead = 0
        var byte: UInt8 = 0

        while offset + bytesRead < data.count {
            byte = data[data.startIndex + offset + bytesRead]
            bytesRead += 1

            result |= Int64(byte & 0x7F) << shift
            shift += 7

            if byte & 0x80 == 0 { break }
        }

        // Sign extend
        if shift < 64 && (byte & 0x40) != 0 {
            result |= -(1 << shift)
        }

        return (result, bytesRead)
    }
}

// MARK: - Debug Info Provider

class DebugInfoProvider {
    private var parsedInfo: DWARFParser.DebugInfo?
    private let parser = DWARFParser()

    func loadDebugInfo(from binary: BinaryFile) {
        parsedInfo = parser.parse(binary: binary)
    }

    /// Get source location for an address
    func sourceLocation(for address: UInt64) -> (file: String, line: Int, column: Int)? {
        guard let info = parsedInfo else { return nil }

        for lineInfo in info.lineInfo {
            if lineInfo.address == address {
                return (lineInfo.file, lineInfo.line, lineInfo.column)
            }
        }

        return nil
    }

    /// Get function name with debug info
    func functionName(at address: UInt64) -> String? {
        guard let info = parsedInfo else { return nil }

        for func_ in info.functions {
            if address >= func_.startAddress && address < func_.endAddress {
                return func_.linkageName ?? func_.name
            }
        }

        return nil
    }

    /// Get variable info at address
    func variableInfo(at address: UInt64) -> [DWARFParser.DebugVariable] {
        guard let info = parsedInfo else { return [] }

        return info.variables.filter { variable in
            if case .local(let funcAddr) = variable.scope {
                // Check if address is within function
                return info.functions.contains { f in
                    f.startAddress == funcAddr && address >= f.startAddress && address < f.endAddress
                }
            }
            return true
        }
    }

    /// Get type information
    func typeInfo(named name: String) -> DWARFParser.DebugType? {
        return parsedInfo?.types.first { $0.name == name }
    }
}
