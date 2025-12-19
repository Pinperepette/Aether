import Foundation

// MARK: - Swift Metadata Analysis

/// Analyzes Swift runtime metadata in binaries
class SwiftAnalyzer {

    // MARK: - Models

    struct SwiftType: Identifiable {
        let id = UUID()
        let name: String
        let mangledName: String
        let kind: TypeKind
        let size: Int?
        let alignment: Int?
        let fields: [SwiftField]
        let methods: [SwiftMethod]
        let protocols: [String]
        let genericParameters: [String]
        let address: UInt64

        enum TypeKind: String {
            case `struct` = "Struct"
            case `class` = "Class"
            case `enum` = "Enum"
            case `protocol` = "Protocol"
            case existential = "Existential"
            case tuple = "Tuple"
            case function = "Function"
            case metatype = "Metatype"
            case unknown = "Unknown"
        }
    }

    struct SwiftField: Identifiable {
        let id = UUID()
        let name: String
        let type: String
        let offset: Int?
        let isLet: Bool
    }

    struct SwiftMethod: Identifiable {
        let id = UUID()
        let name: String
        let mangledName: String
        let signature: String
        let implementation: UInt64
        let isStatic: Bool
        let kind: MethodKind

        enum MethodKind {
            case `init`
            case `deinit`
            case getter
            case setter
            case method
            case witness
        }
    }

    struct SwiftProtocol: Identifiable {
        let id = UUID()
        let name: String
        let mangledName: String
        let requirements: [ProtocolRequirement]
        let associatedTypes: [String]
        let inheritedProtocols: [String]
    }

    struct ProtocolRequirement {
        let name: String
        let kind: RequirementKind

        enum RequirementKind {
            case method
            case getter
            case setter
            case associatedType
            case witnessTable
        }
    }

    struct SwiftWitnessTable: Identifiable {
        let id = UUID()
        let conformingType: String
        let protocolName: String
        let witnesses: [(requirement: String, implementation: UInt64)]
        let address: UInt64
    }

    // MARK: - Analysis Result

    struct AnalysisResult {
        var types: [SwiftType]
        var protocols: [SwiftProtocol]
        var witnessTables: [SwiftWitnessTable]
        var typeMetadataAccessors: [UInt64: String]
        var reflectionStrings: [String]
    }

    // MARK: - Swift Metadata Constants

    private enum MetadataKind: UInt32 {
        case `class` = 0
        case `struct` = 0x200
        case `enum` = 0x201
        case optional = 0x202
        case foreignClass = 0x203
        case opaque = 0x300
        case tuple = 0x301
        case function = 0x302
        case existential = 0x303
        case metatype = 0x304
        case objcClassWrapper = 0x305
        case existentialMetatype = 0x306
        case heapLocalVariable = 0x400
        case heapGenericLocalVariable = 0x500
        case errorObject = 0x501
    }

    // MARK: - Analysis

    func analyze(binary: BinaryFile) -> AnalysisResult {
        var result = AnalysisResult(
            types: [],
            protocols: [],
            witnessTables: [],
            typeMetadataAccessors: [:],
            reflectionStrings: []
        )

        guard binary.format == .machO else {
            return result
        }

        // Find Swift sections
        let typeMetadataSection = binary.sections.first { $0.name == "__swift5_types" }
        let protocolSection = binary.sections.first { $0.name == "__swift5_protos" }
        let conformsSection = binary.sections.first { $0.name == "__swift5_proto" }
        let fieldmdSection = binary.sections.first { $0.name == "__swift5_fieldmd" }
        let assoctySection = binary.sections.first { $0.name == "__swift5_assocty" }
        let builtinSection = binary.sections.first { $0.name == "__swift5_builtin" }
        let reflstrSection = binary.sections.first { $0.name == "__swift5_reflstr" }

        // Parse type metadata
        if let typeSection = typeMetadataSection {
            result.types = parseTypeMetadata(typeSection, binary: binary)
        }

        // Parse protocols
        if let protoSection = protocolSection {
            result.protocols = parseProtocols(protoSection, binary: binary)
        }

        // Parse protocol conformances
        if let confSection = conformsSection {
            result.witnessTables = parseConformances(confSection, binary: binary)
        }

        // Parse field metadata
        if let fieldSection = fieldmdSection {
            enrichTypesWithFields(&result.types, from: fieldSection, binary: binary)
        }

        // Parse reflection strings
        if let reflSection = reflstrSection {
            result.reflectionStrings = parseReflectionStrings(reflSection)
        }

        // Find type metadata accessors
        result.typeMetadataAccessors = findTypeMetadataAccessors(binary)

        return result
    }

    // MARK: - Parsing

    private func parseTypeMetadata(_ section: Section, binary: BinaryFile) -> [SwiftType] {
        var types: [SwiftType] = []

        // Swift 5 type metadata records are relative pointers
        let data = section.data
        var offset = 0

        while offset + 4 <= data.count {
            guard let relPtr = data.readInt32LE(at: offset) else {
                offset += 4
                continue
            }

            let typeDescAddress = section.address + UInt64(offset) + UInt64(relPtr)

            if let typeDesc = parseTypeDescriptor(at: typeDescAddress, binary: binary) {
                types.append(typeDesc)
            }

            offset += 4
        }

        return types
    }

    private func parseTypeDescriptor(at address: UInt64, binary: BinaryFile) -> SwiftType? {
        guard let data = binary.read(at: address, count: 64) else { return nil }

        // Type context descriptor layout
        guard let flags = data.readUInt32LE(at: 0) else { return nil }

        let kind = MetadataKind(rawValue: flags & 0x1F)
        let typeKind: SwiftType.TypeKind

        switch kind {
        case .class:
            typeKind = .class
        case .struct:
            typeKind = .struct
        case .enum, .optional:
            typeKind = .enum
        default:
            typeKind = .unknown
        }

        // Read name
        guard let nameOffset = data.readInt32LE(at: 8) else { return nil }
        let nameAddress = address + 8 + UInt64(nameOffset)
        let name = binary.readString(at: nameAddress) ?? "Unknown"

        // Read mangled name if available
        let mangledName = demangle(name) ?? name

        return SwiftType(
            name: mangledName,
            mangledName: name,
            kind: typeKind,
            size: nil,
            alignment: nil,
            fields: [],
            methods: [],
            protocols: [],
            genericParameters: [],
            address: address
        )
    }

    private func parseProtocols(_ section: Section, binary: BinaryFile) -> [SwiftProtocol] {
        var protocols: [SwiftProtocol] = []

        let data = section.data
        var offset = 0

        while offset + 4 <= data.count {
            guard let relPtr = data.readInt32LE(at: offset) else {
                offset += 4
                continue
            }

            let protoDescAddress = section.address + UInt64(offset) + UInt64(relPtr)

            if let protoDesc = parseProtocolDescriptor(at: protoDescAddress, binary: binary) {
                protocols.append(protoDesc)
            }

            offset += 4
        }

        return protocols
    }

    private func parseProtocolDescriptor(at address: UInt64, binary: BinaryFile) -> SwiftProtocol? {
        guard let data = binary.read(at: address, count: 48) else { return nil }

        // Read name
        guard let nameOffset = data.readInt32LE(at: 8) else { return nil }
        let nameAddress = address + 8 + UInt64(nameOffset)
        let name = binary.readString(at: nameAddress) ?? "Unknown"

        return SwiftProtocol(
            name: demangle(name) ?? name,
            mangledName: name,
            requirements: [],
            associatedTypes: [],
            inheritedProtocols: []
        )
    }

    private func parseConformances(_ section: Section, binary: BinaryFile) -> [SwiftWitnessTable] {
        var tables: [SwiftWitnessTable] = []

        let data = section.data
        var offset = 0

        while offset + 16 <= data.count {
            // Protocol conformance descriptor
            guard let protoOffset = data.readInt32LE(at: offset),
                  let typeOffset = data.readInt32LE(at: offset + 4) else {
                offset += 16
                continue
            }

            let protoAddress = section.address + UInt64(offset) + UInt64(protoOffset)
            let typeAddress = section.address + UInt64(offset + 4) + UInt64(typeOffset)

            // Read protocol and type names
            let protoName = binary.readString(at: protoAddress) ?? "Unknown"
            let typeName = binary.readString(at: typeAddress) ?? "Unknown"

            tables.append(SwiftWitnessTable(
                conformingType: demangle(typeName) ?? typeName,
                protocolName: demangle(protoName) ?? protoName,
                witnesses: [],
                address: section.address + UInt64(offset)
            ))

            offset += 16
        }

        return tables
    }

    private func enrichTypesWithFields(_ types: inout [SwiftType], from section: Section, binary: BinaryFile) {
        // Parse field descriptors and match to types
        let data = section.data
        var offset = 0

        while offset + 16 <= data.count {
            guard let typeOffset = data.readInt32LE(at: offset),
                  let numFields = data.readUInt32LE(at: offset + 8) else {
                offset += 16
                continue
            }

            let typeAddress = section.address + UInt64(offset) + UInt64(typeOffset)

            // Find matching type
            if let typeIndex = types.firstIndex(where: { $0.address == typeAddress }) {
                var fields: [SwiftField] = []

                // Read field records
                let fieldsStart = offset + 16
                for i in 0..<Int(numFields) {
                    let fieldOffset = fieldsStart + i * 12

                    guard fieldOffset + 12 <= data.count,
                          let flags = data.readUInt32LE(at: fieldOffset),
                          let nameOff = data.readInt32LE(at: fieldOffset + 4) else {
                        continue
                    }

                    let nameAddress = section.address + UInt64(fieldOffset + 4) + UInt64(nameOff)
                    let fieldName = binary.readString(at: nameAddress) ?? "field\(i)"

                    let isLet = (flags & 0x2) != 0

                    fields.append(SwiftField(
                        name: fieldName,
                        type: "Unknown",  // Would need type reference resolution
                        offset: nil,
                        isLet: isLet
                    ))
                }

                // Create new type with fields
                let oldType = types[typeIndex]
                types[typeIndex] = SwiftType(
                    name: oldType.name,
                    mangledName: oldType.mangledName,
                    kind: oldType.kind,
                    size: oldType.size,
                    alignment: oldType.alignment,
                    fields: fields,
                    methods: oldType.methods,
                    protocols: oldType.protocols,
                    genericParameters: oldType.genericParameters,
                    address: oldType.address
                )
            }

            offset += 16 + Int(numFields) * 12
        }
    }

    private func parseReflectionStrings(_ section: Section) -> [String] {
        var strings: [String] = []
        let data = section.data
        var offset = 0

        while offset < data.count {
            if let str = data.readCString(at: offset), !str.isEmpty {
                strings.append(str)
                offset += str.utf8.count + 1
            } else {
                offset += 1
            }
        }

        return strings
    }

    private func findTypeMetadataAccessors(_ binary: BinaryFile) -> [UInt64: String] {
        var accessors: [UInt64: String] = [:]

        // Look for symbols matching type metadata accessor pattern
        for symbol in binary.symbols {
            if symbol.name.contains("Ma") && symbol.name.hasPrefix("$s") {
                let demangled = demangle(symbol.name) ?? symbol.name
                accessors[symbol.address] = demangled
            }
        }

        return accessors
    }

    // MARK: - Swift Demangling

    /// Demangle Swift symbol name
    private func demangle(_ name: String) -> String? {
        // Check if it's a mangled Swift name
        guard name.hasPrefix("$s") || name.hasPrefix("_$s") else {
            return nil
        }

        // Use swift-demangle if available
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/swift-demangle")
        process.arguments = ["-compact", name]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let result = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !result.isEmpty && result != name {
                return result
            }
        } catch {
            // swift-demangle not available, use basic demangling
        }

        return basicDemangle(name)
    }

    /// Basic Swift demangling (simplified)
    private func basicDemangle(_ name: String) -> String? {
        var mangled = name
        if mangled.hasPrefix("_") {
            mangled = String(mangled.dropFirst())
        }

        guard mangled.hasPrefix("$s") else { return nil }
        mangled = String(mangled.dropFirst(2))

        // Very simplified demangling - just extract identifiers
        var result = ""
        var index = mangled.startIndex

        while index < mangled.endIndex {
            // Try to read a length-prefixed identifier
            var lengthStr = ""
            while index < mangled.endIndex && mangled[index].isNumber {
                lengthStr.append(mangled[index])
                index = mangled.index(after: index)
            }

            if let length = Int(lengthStr), length > 0 {
                let endIndex = mangled.index(index, offsetBy: min(length, mangled.distance(from: index, to: mangled.endIndex)))
                let identifier = String(mangled[index..<endIndex])

                if !result.isEmpty {
                    result += "."
                }
                result += identifier

                index = endIndex
            } else {
                index = mangled.index(after: index)
            }
        }

        return result.isEmpty ? nil : result
    }
}

// MARK: - Swift Demangler Service

class SwiftDemangler {
    static let shared = SwiftDemangler()

    private var cache: [String: String] = [:]

    private init() {}

    func demangle(_ name: String) -> String {
        if let cached = cache[name] {
            return cached
        }

        guard name.hasPrefix("$s") || name.hasPrefix("_$s") || name.hasPrefix("_T") else {
            return name
        }

        // Try swift-demangle
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/swift-demangle")
        process.arguments = ["-compact", name]

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice

        do {
            try process.run()
            process.waitUntilExit()

            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            if let result = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
               !result.isEmpty {
                cache[name] = result
                return result
            }
        } catch {}

        cache[name] = name
        return name
    }

    func demangleAll(_ names: [String]) -> [String: String] {
        var results: [String: String] = [:]

        // Batch demangle
        let mangledNames = names.filter { $0.hasPrefix("$s") || $0.hasPrefix("_$s") }

        if !mangledNames.isEmpty {
            let process = Process()
            process.executableURL = URL(fileURLWithPath: "/usr/bin/swift-demangle")
            process.arguments = ["-compact"] + mangledNames

            let pipe = Pipe()
            process.standardOutput = pipe
            process.standardError = FileHandle.nullDevice

            do {
                try process.run()
                process.waitUntilExit()

                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                if let output = String(data: data, encoding: .utf8) {
                    let lines = output.split(separator: "\n")
                    for (i, name) in mangledNames.enumerated() {
                        if i < lines.count {
                            results[name] = String(lines[i])
                        }
                    }
                }
            } catch {}
        }

        // Add non-mangled names as-is
        for name in names where !mangledNames.contains(name) {
            results[name] = name
        }

        return results
    }
}
