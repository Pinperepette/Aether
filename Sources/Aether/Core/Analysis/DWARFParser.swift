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
        // Simplified line info parsing
        // Full implementation would decode the line number program
        return lineInfo
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

    private func extractFunctionInfo(attr: UInt16, value: Any?, binary: BinaryFile) -> DebugFunction? {
        // Simplified extraction - full implementation would accumulate attributes
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
