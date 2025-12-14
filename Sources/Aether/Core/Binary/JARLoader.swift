import Foundation
import Compression

// MARK: - JAR/Java Class Loader

class JARLoader: BinaryLoaderProtocol {

    enum JARError: Error, LocalizedError {
        case invalidJAR
        case invalidClassFile
        case decompressionFailed
        case unsupportedVersion(Int)

        var errorDescription: String? {
            switch self {
            case .invalidJAR: return "Invalid JAR file"
            case .invalidClassFile: return "Invalid Java class file"
            case .decompressionFailed: return "Failed to decompress JAR entry"
            case .unsupportedVersion(let v): return "Unsupported class file version: \(v)"
            }
        }
    }

    // MARK: - JAR Structure

    struct JARFile {
        let entries: [JAREntry]
        let manifest: [String: String]
        let mainClass: String?
    }

    struct JAREntry {
        let name: String
        let data: Data
        let compressedSize: Int
        let uncompressedSize: Int
        let isDirectory: Bool
        let isClassFile: Bool
    }

    // MARK: - Java Class File Structure

    struct JavaClass {
        let minorVersion: UInt16
        let majorVersion: UInt16
        let constantPool: [ConstantPoolEntry]
        let accessFlags: UInt16
        let thisClass: String
        let superClass: String
        let interfaces: [String]
        let fields: [FieldInfo]
        let methods: [MethodInfo]
        let attributes: [AttributeInfo]

        var javaVersion: String {
            switch majorVersion {
            case 45: return "Java 1.1"
            case 46: return "Java 1.2"
            case 47: return "Java 1.3"
            case 48: return "Java 1.4"
            case 49: return "Java 5"
            case 50: return "Java 6"
            case 51: return "Java 7"
            case 52: return "Java 8"
            case 53: return "Java 9"
            case 54: return "Java 10"
            case 55: return "Java 11"
            case 56: return "Java 12"
            case 57: return "Java 13"
            case 58: return "Java 14"
            case 59: return "Java 15"
            case 60: return "Java 16"
            case 61: return "Java 17"
            case 62: return "Java 18"
            case 63: return "Java 19"
            case 64: return "Java 20"
            case 65: return "Java 21"
            default: return "Java \(majorVersion - 44)"
            }
        }
    }

    enum ConstantPoolEntry {
        case utf8(String)
        case integer(Int32)
        case float(Float)
        case long(Int64)
        case double(Double)
        case classRef(Int)
        case stringRef(Int)
        case fieldRef(classIndex: Int, nameAndTypeIndex: Int)
        case methodRef(classIndex: Int, nameAndTypeIndex: Int)
        case interfaceMethodRef(classIndex: Int, nameAndTypeIndex: Int)
        case nameAndType(nameIndex: Int, descriptorIndex: Int)
        case methodHandle(kind: Int, index: Int)
        case methodType(descriptorIndex: Int)
        case dynamic(bootstrapMethodAttrIndex: Int, nameAndTypeIndex: Int)
        case invokeDynamic(bootstrapMethodAttrIndex: Int, nameAndTypeIndex: Int)
        case module(nameIndex: Int)
        case package(nameIndex: Int)
        case placeholder // For long/double second slot
    }

    struct FieldInfo {
        let accessFlags: UInt16
        let name: String
        let descriptor: String
        let attributes: [AttributeInfo]

        var isPublic: Bool { accessFlags & 0x0001 != 0 }
        var isPrivate: Bool { accessFlags & 0x0002 != 0 }
        var isProtected: Bool { accessFlags & 0x0004 != 0 }
        var isStatic: Bool { accessFlags & 0x0008 != 0 }
        var isFinal: Bool { accessFlags & 0x0010 != 0 }
    }

    struct MethodInfo {
        let accessFlags: UInt16
        let name: String
        let descriptor: String
        let attributes: [AttributeInfo]
        var code: CodeAttribute?

        var isPublic: Bool { accessFlags & 0x0001 != 0 }
        var isPrivate: Bool { accessFlags & 0x0002 != 0 }
        var isProtected: Bool { accessFlags & 0x0004 != 0 }
        var isStatic: Bool { accessFlags & 0x0008 != 0 }
        var isFinal: Bool { accessFlags & 0x0010 != 0 }
        var isSynchronized: Bool { accessFlags & 0x0020 != 0 }
        var isNative: Bool { accessFlags & 0x0100 != 0 }
        var isAbstract: Bool { accessFlags & 0x0400 != 0 }
    }

    struct AttributeInfo {
        let name: String
        let data: Data
    }

    struct CodeAttribute {
        let maxStack: UInt16
        let maxLocals: UInt16
        let code: Data
        let exceptionTable: [ExceptionTableEntry]
        let attributes: [AttributeInfo]
    }

    struct ExceptionTableEntry {
        let startPC: UInt16
        let endPC: UInt16
        let handlerPC: UInt16
        let catchType: UInt16
    }

    // MARK: - BinaryLoaderProtocol

    func canLoad(data: Data) -> Bool {
        guard data.count >= 4 else { return false }

        // Check for JAR/ZIP (PK header)
        if data[0] == 0x50 && data[1] == 0x4B && data[2] == 0x03 && data[3] == 0x04 {
            return true
        }

        // Check for Java class file (CAFEBABE)
        if data[0] == 0xCA && data[1] == 0xFE && data[2] == 0xBA && data[3] == 0xBE {
            // Verify it's a class file, not a fat binary
            if data.count >= 8 {
                let majorVersion = (UInt16(data[6]) << 8) | UInt16(data[7])
                return majorVersion >= 45 && majorVersion <= 70
            }
        }

        return false
    }

    func load(from url: URL, data: Data) async throws -> BinaryFile {
        // Determine if it's a JAR or class file
        if data[0] == 0x50 && data[1] == 0x4B {
            return try loadJAR(from: url)
        } else {
            return try loadClassFile(from: url)
        }
    }

    // MARK: - Loading

    func loadJAR(from url: URL) throws -> BinaryFile {
        let data = try Data(contentsOf: url)

        // Use system unzip to extract to temp directory
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)

        defer {
            try? FileManager.default.removeItem(at: tempDir)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/unzip")
        process.arguments = ["-q", "-o", url.path, "-d", tempDir.path]
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice

        try process.run()
        process.waitUntilExit()

        // Find all class files
        var classes: [JavaClass] = []
        var symbols: [Symbol] = []
        var sections: [Section] = []
        var baseAddress: UInt64 = 0x10000
        var manifest: [String: String] = [:]

        // Read manifest if exists
        let manifestPath = tempDir.appendingPathComponent("META-INF/MANIFEST.MF")
        if let manifestData = try? Data(contentsOf: manifestPath),
           let manifestString = String(data: manifestData, encoding: .utf8) {
            manifest = parseManifest(manifestData)
        }

        // Find all .class files
        let enumerator = FileManager.default.enumerator(at: tempDir, includingPropertiesForKeys: nil)
        var classFiles: [URL] = []
        while let fileURL = enumerator?.nextObject() as? URL {
            if fileURL.pathExtension == "class" {
                classFiles.append(fileURL)
            }
        }

        for fileURL in classFiles.prefix(200) { // Limit to first 200 classes for performance
            let relativePath = fileURL.path.replacingOccurrences(of: tempDir.path + "/", with: "")
            if let classData = try? Data(contentsOf: fileURL) {
                if let javaClass = try? parseClassFile(data: classData) {
                    classes.append(javaClass)

                    let classAddress = baseAddress

                    // Add class as a symbol
                    symbols.append(Symbol(
                        name: javaClass.thisClass.replacingOccurrences(of: "/", with: "."),
                        address: classAddress,
                        size: UInt64(classData.count),
                        type: .object,
                        binding: .global,
                        section: "CLASSES"
                    ))

                    // Add methods as symbols
                    var methodOffset: UInt64 = 0x100
                    for method in javaClass.methods {
                        let methodName = "\(javaClass.thisClass.replacingOccurrences(of: "/", with: ".")).\(method.name)\(method.descriptor)"
                        let codeSize = UInt64(method.code?.code.count ?? 0)
                        symbols.append(Symbol(
                            name: methodName,
                            address: classAddress + methodOffset,
                            size: codeSize,
                            type: .function,
                            binding: method.isNative ? .external : .global,
                            section: "CLASSES"
                        ))
                        methodOffset += max(codeSize, 0x10)
                    }

                    // Create a section for the class
                    let className = relativePath.replacingOccurrences(of: "/", with: ".").replacingOccurrences(of: ".class", with: "")
                    sections.append(Section(
                        name: className,
                        segmentName: "CLASSES",
                        address: classAddress,
                        size: UInt64(classData.count),
                        offset: UInt32(sections.count),
                        alignment: 1,
                        flags: 0,
                        data: classData
                    ))

                    baseAddress += UInt64(classData.count) + 0x1000
                }
            }
        }

        // Create binary file
        let binary = BinaryFile(
            url: url,
            format: .java,
            architecture: .jvm,
            endianness: .big,
            is64Bit: false,
            fileSize: data.count,
            entryPoint: 0,
            baseAddress: 0x10000,
            sections: sections,
            segments: [],
            symbols: symbols,
            data: data
        )

        // Store Java-specific info
        binary.javaClasses = classes

        // Create JARFile object
        let jarFile = JARFile(entries: [], manifest: manifest, mainClass: manifest["Main-Class"])
        binary.jarFile = jarFile

        return binary
    }

    func loadClassFile(from url: URL) throws -> BinaryFile {
        let data = try Data(contentsOf: url)
        let javaClass = try parseClassFile(data: data)

        var symbols: [Symbol] = []
        let baseAddress: UInt64 = 0x10000

        // Add class as symbol
        symbols.append(Symbol(
            name: javaClass.thisClass.replacingOccurrences(of: "/", with: "."),
            address: baseAddress,
            size: UInt64(data.count),
            type: .object,
            binding: .global,
            section: "CLASS"
        ))

        // Add methods
        var methodOffset: UInt64 = 0x100
        for method in javaClass.methods {
            let codeSize = UInt64(method.code?.code.count ?? 0)
            symbols.append(Symbol(
                name: "\(javaClass.thisClass.replacingOccurrences(of: "/", with: ".")).\(method.name)\(method.descriptor)",
                address: baseAddress + methodOffset,
                size: codeSize,
                type: .function,
                binding: method.isNative ? .external : .global,
                section: "CLASS"
            ))
            methodOffset += max(codeSize, 0x10)
        }

        let section = Section(
            name: javaClass.thisClass.replacingOccurrences(of: "/", with: "."),
            segmentName: "CLASS",
            address: baseAddress,
            size: UInt64(data.count),
            offset: 0,
            alignment: 1,
            flags: 0,
            data: data
        )

        let binary = BinaryFile(
            url: url,
            format: .java,
            architecture: .jvm,
            endianness: .big,
            is64Bit: false,
            fileSize: data.count,
            entryPoint: 0,
            baseAddress: baseAddress,
            sections: [section],
            segments: [],
            symbols: symbols,
            data: data
        )

        binary.javaClasses = [javaClass]

        return binary
    }

    // MARK: - JAR Parsing

    private func parseJAR(data: Data) throws -> JARFile {
        var entries: [JAREntry] = []
        var manifest: [String: String] = [:]
        var offset = 0

        while offset < data.count - 4 {
            // Check for PK signature
            guard data[offset] == 0x50, data[offset + 1] == 0x4B else {
                offset += 1
                continue
            }

            let sig3 = data[offset + 2]
            let sig4 = data[offset + 3]

            // Central directory header (PK\x01\x02) - stop here
            if sig3 == 0x01 && sig4 == 0x02 {
                break
            }

            // End of central directory (PK\x05\x06) - stop here
            if sig3 == 0x05 && sig4 == 0x06 {
                break
            }

            // Not a local file header (PK\x03\x04) - skip
            if sig3 != 0x03 || sig4 != 0x04 {
                offset += 1
                continue
            }

            // Parse local file header
            guard offset + 30 <= data.count else {
                break
            }

            guard let compressionMethod = data.readUInt16LE(at: offset + 8),
                  let compressedSize = data.readUInt32LE(at: offset + 18),
                  let uncompressedSize = data.readUInt32LE(at: offset + 22),
                  let fileNameLength = data.readUInt16LE(at: offset + 26),
                  let extraFieldLength = data.readUInt16LE(at: offset + 28) else {
                break
            }

            let headerSize = 30
            let fileNameStart = offset + headerSize
            let fileNameEnd = fileNameStart + Int(fileNameLength)

            guard fileNameEnd <= data.count else {
                break
            }

            let fileNameData = data[fileNameStart..<fileNameEnd]
            let fileName = String(data: fileNameData, encoding: .utf8) ?? ""

            let dataStart = fileNameEnd + Int(extraFieldLength)
            let dataEnd = dataStart + Int(compressedSize)

            guard dataEnd <= data.count else {
                break
            }

            var entryData = data[dataStart..<dataEnd]

            // Decompress if needed
            if compressionMethod == 8 { // DEFLATE
                if let decompressed = decompress(Data(entryData), uncompressedSize: Int(uncompressedSize)) {
                    entryData = decompressed[...]
                } else {
                    // Decompression failed, skip entry but continue
                    offset = dataEnd
                    continue
                }
            }

            let entry = JAREntry(
                name: fileName,
                data: Data(entryData),
                compressedSize: Int(compressedSize),
                uncompressedSize: Int(uncompressedSize),
                isDirectory: fileName.hasSuffix("/"),
                isClassFile: fileName.hasSuffix(".class")
            )
            entries.append(entry)

            // Parse manifest
            if fileName == "META-INF/MANIFEST.MF" {
                manifest = parseManifest(Data(entryData))
            }

            offset = dataEnd
        }

        let mainClass = manifest["Main-Class"]

        return JARFile(entries: entries, manifest: manifest, mainClass: mainClass)
    }

    private func decompress(_ data: Data, uncompressedSize: Int) -> Data? {
        // Decompression is handled by system unzip command
        // This function is kept as a stub for parseJAR (which is no longer primary method)
        return nil
    }

    private func parseManifest(_ data: Data) -> [String: String] {
        var manifest: [String: String] = [:]

        guard let content = String(data: data, encoding: .utf8) else { return manifest }

        let lines = content.components(separatedBy: .newlines)
        var currentKey = ""
        var currentValue = ""

        for line in lines {
            if line.starts(with: " ") {
                // Continuation of previous line
                currentValue += line.dropFirst()
            } else if let colonIndex = line.firstIndex(of: ":") {
                // Save previous entry
                if !currentKey.isEmpty {
                    manifest[currentKey] = currentValue.trimmingCharacters(in: .whitespaces)
                }

                currentKey = String(line[..<colonIndex])
                currentValue = String(line[line.index(after: colonIndex)...])
            }
        }

        // Save last entry
        if !currentKey.isEmpty {
            manifest[currentKey] = currentValue.trimmingCharacters(in: .whitespaces)
        }

        return manifest
    }

    // MARK: - Class File Parsing

    private func parseClassFile(data: Data) throws -> JavaClass {
        var offset = 0

        // Magic number: 0xCAFEBABE
        guard data.count >= 10,
              data[0] == 0xCA, data[1] == 0xFE, data[2] == 0xBA, data[3] == 0xBE else {
            throw JARError.invalidClassFile
        }
        offset = 4

        // Version
        guard let minorVersion = data.readUInt16BE(at: offset),
              let majorVersion = data.readUInt16BE(at: offset + 2) else {
            throw JARError.invalidClassFile
        }
        offset += 4

        // Constant pool
        guard let constantPoolCount = data.readUInt16BE(at: offset) else {
            throw JARError.invalidClassFile
        }
        offset += 2

        var constantPool: [ConstantPoolEntry] = [.placeholder] // Index 0 is unused
        var i = 1
        while i < constantPoolCount {
            let (entry, size, isWide) = try parseConstantPoolEntry(data: data, offset: offset)
            constantPool.append(entry)
            offset += size
            i += 1

            if isWide {
                constantPool.append(.placeholder)
                i += 1
            }
        }

        // Access flags, this class, super class
        guard let accessFlags = data.readUInt16BE(at: offset),
              let thisClassIndex = data.readUInt16BE(at: offset + 2),
              let superClassIndex = data.readUInt16BE(at: offset + 4) else {
            throw JARError.invalidClassFile
        }
        offset += 6

        let thisClass = resolveClassName(index: Int(thisClassIndex), constantPool: constantPool)
        let superClass = resolveClassName(index: Int(superClassIndex), constantPool: constantPool)

        // Interfaces
        guard let interfacesCount = data.readUInt16BE(at: offset) else {
            throw JARError.invalidClassFile
        }
        offset += 2

        var interfaces: [String] = []
        for _ in 0..<interfacesCount {
            guard let interfaceIndex = data.readUInt16BE(at: offset) else {
                throw JARError.invalidClassFile
            }
            interfaces.append(resolveClassName(index: Int(interfaceIndex), constantPool: constantPool))
            offset += 2
        }

        // Fields
        guard let fieldsCount = data.readUInt16BE(at: offset) else {
            throw JARError.invalidClassFile
        }
        offset += 2

        var fields: [FieldInfo] = []
        for _ in 0..<fieldsCount {
            let (field, size) = try parseFieldInfo(data: data, offset: offset, constantPool: constantPool)
            fields.append(field)
            offset += size
        }

        // Methods
        guard let methodsCount = data.readUInt16BE(at: offset) else {
            throw JARError.invalidClassFile
        }
        offset += 2

        var methods: [MethodInfo] = []
        for _ in 0..<methodsCount {
            let (method, size) = try parseMethodInfo(data: data, offset: offset, constantPool: constantPool)
            methods.append(method)
            offset += size
        }

        // Class attributes
        guard let attributesCount = data.readUInt16BE(at: offset) else {
            throw JARError.invalidClassFile
        }
        offset += 2

        var attributes: [AttributeInfo] = []
        for _ in 0..<attributesCount {
            let (attr, size) = try parseAttributeInfo(data: data, offset: offset, constantPool: constantPool)
            attributes.append(attr)
            offset += size
        }

        return JavaClass(
            minorVersion: minorVersion,
            majorVersion: majorVersion,
            constantPool: constantPool,
            accessFlags: accessFlags,
            thisClass: thisClass,
            superClass: superClass,
            interfaces: interfaces,
            fields: fields,
            methods: methods,
            attributes: attributes
        )
    }

    private func parseConstantPoolEntry(data: Data, offset: Int) throws -> (ConstantPoolEntry, Int, Bool) {
        guard let tag = data.readUInt8(at: offset) else {
            throw JARError.invalidClassFile
        }

        switch tag {
        case 1: // CONSTANT_Utf8
            guard let length = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            let stringData = data[(offset + 3)..<(offset + 3 + Int(length))]
            let string = String(data: stringData, encoding: .utf8) ?? ""
            return (.utf8(string), 3 + Int(length), false)

        case 3: // CONSTANT_Integer
            guard let value = data.readInt32BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.integer(value), 5, false)

        case 4: // CONSTANT_Float
            guard let bits = data.readUInt32BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            let value = Float(bitPattern: bits)
            return (.float(value), 5, false)

        case 5: // CONSTANT_Long
            guard let value = data.readInt64BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.long(value), 9, true)

        case 6: // CONSTANT_Double
            guard let bits = data.readUInt64BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            let value = Double(bitPattern: bits)
            return (.double(value), 9, true)

        case 7: // CONSTANT_Class
            guard let nameIndex = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.classRef(Int(nameIndex)), 3, false)

        case 8: // CONSTANT_String
            guard let stringIndex = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.stringRef(Int(stringIndex)), 3, false)

        case 9: // CONSTANT_Fieldref
            guard let classIndex = data.readUInt16BE(at: offset + 1),
                  let nameAndTypeIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.fieldRef(classIndex: Int(classIndex), nameAndTypeIndex: Int(nameAndTypeIndex)), 5, false)

        case 10: // CONSTANT_Methodref
            guard let classIndex = data.readUInt16BE(at: offset + 1),
                  let nameAndTypeIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.methodRef(classIndex: Int(classIndex), nameAndTypeIndex: Int(nameAndTypeIndex)), 5, false)

        case 11: // CONSTANT_InterfaceMethodref
            guard let classIndex = data.readUInt16BE(at: offset + 1),
                  let nameAndTypeIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.interfaceMethodRef(classIndex: Int(classIndex), nameAndTypeIndex: Int(nameAndTypeIndex)), 5, false)

        case 12: // CONSTANT_NameAndType
            guard let nameIndex = data.readUInt16BE(at: offset + 1),
                  let descriptorIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.nameAndType(nameIndex: Int(nameIndex), descriptorIndex: Int(descriptorIndex)), 5, false)

        case 15: // CONSTANT_MethodHandle
            guard let kind = data.readUInt8(at: offset + 1),
                  let index = data.readUInt16BE(at: offset + 2) else {
                throw JARError.invalidClassFile
            }
            return (.methodHandle(kind: Int(kind), index: Int(index)), 4, false)

        case 16: // CONSTANT_MethodType
            guard let descriptorIndex = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.methodType(descriptorIndex: Int(descriptorIndex)), 3, false)

        case 17: // CONSTANT_Dynamic
            guard let bootstrapMethodAttrIndex = data.readUInt16BE(at: offset + 1),
                  let nameAndTypeIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.dynamic(bootstrapMethodAttrIndex: Int(bootstrapMethodAttrIndex), nameAndTypeIndex: Int(nameAndTypeIndex)), 5, false)

        case 18: // CONSTANT_InvokeDynamic
            guard let bootstrapMethodAttrIndex = data.readUInt16BE(at: offset + 1),
                  let nameAndTypeIndex = data.readUInt16BE(at: offset + 3) else {
                throw JARError.invalidClassFile
            }
            return (.invokeDynamic(bootstrapMethodAttrIndex: Int(bootstrapMethodAttrIndex), nameAndTypeIndex: Int(nameAndTypeIndex)), 5, false)

        case 19: // CONSTANT_Module
            guard let nameIndex = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.module(nameIndex: Int(nameIndex)), 3, false)

        case 20: // CONSTANT_Package
            guard let nameIndex = data.readUInt16BE(at: offset + 1) else {
                throw JARError.invalidClassFile
            }
            return (.package(nameIndex: Int(nameIndex)), 3, false)

        default:
            throw JARError.invalidClassFile
        }
    }

    private func parseFieldInfo(data: Data, offset: Int, constantPool: [ConstantPoolEntry]) throws -> (FieldInfo, Int) {
        guard let accessFlags = data.readUInt16BE(at: offset),
              let nameIndex = data.readUInt16BE(at: offset + 2),
              let descriptorIndex = data.readUInt16BE(at: offset + 4),
              let attributesCount = data.readUInt16BE(at: offset + 6) else {
            throw JARError.invalidClassFile
        }

        var currentOffset = offset + 8
        var attributes: [AttributeInfo] = []

        for _ in 0..<attributesCount {
            let (attr, size) = try parseAttributeInfo(data: data, offset: currentOffset, constantPool: constantPool)
            attributes.append(attr)
            currentOffset += size
        }

        let name = resolveUtf8(index: Int(nameIndex), constantPool: constantPool)
        let descriptor = resolveUtf8(index: Int(descriptorIndex), constantPool: constantPool)

        return (FieldInfo(
            accessFlags: accessFlags,
            name: name,
            descriptor: descriptor,
            attributes: attributes
        ), currentOffset - offset)
    }

    private func parseMethodInfo(data: Data, offset: Int, constantPool: [ConstantPoolEntry]) throws -> (MethodInfo, Int) {
        guard let accessFlags = data.readUInt16BE(at: offset),
              let nameIndex = data.readUInt16BE(at: offset + 2),
              let descriptorIndex = data.readUInt16BE(at: offset + 4),
              let attributesCount = data.readUInt16BE(at: offset + 6) else {
            throw JARError.invalidClassFile
        }

        var currentOffset = offset + 8
        var attributes: [AttributeInfo] = []
        var code: CodeAttribute?

        for _ in 0..<attributesCount {
            let (attr, size) = try parseAttributeInfo(data: data, offset: currentOffset, constantPool: constantPool)
            attributes.append(attr)

            if attr.name == "Code" {
                code = parseCodeAttribute(data: attr.data, constantPool: constantPool)
            }

            currentOffset += size
        }

        let name = resolveUtf8(index: Int(nameIndex), constantPool: constantPool)
        let descriptor = resolveUtf8(index: Int(descriptorIndex), constantPool: constantPool)

        return (MethodInfo(
            accessFlags: accessFlags,
            name: name,
            descriptor: descriptor,
            attributes: attributes,
            code: code
        ), currentOffset - offset)
    }

    private func parseAttributeInfo(data: Data, offset: Int, constantPool: [ConstantPoolEntry]) throws -> (AttributeInfo, Int) {
        guard let nameIndex = data.readUInt16BE(at: offset),
              let length = data.readUInt32BE(at: offset + 2) else {
            throw JARError.invalidClassFile
        }

        let name = resolveUtf8(index: Int(nameIndex), constantPool: constantPool)
        let attrData = data[(offset + 6)..<(offset + 6 + Int(length))]

        return (AttributeInfo(name: name, data: Data(attrData)), 6 + Int(length))
    }

    private func parseCodeAttribute(data: Data, constantPool: [ConstantPoolEntry]) -> CodeAttribute? {
        guard data.count >= 8,
              let maxStack = data.readUInt16BE(at: 0),
              let maxLocals = data.readUInt16BE(at: 2),
              let codeLength = data.readUInt32BE(at: 4) else {
            return nil
        }

        let codeStart = 8
        let codeEnd = codeStart + Int(codeLength)
        guard codeEnd <= data.count else { return nil }

        let code = data[codeStart..<codeEnd]

        // Parse exception table
        var offset = codeEnd
        guard let exceptionTableLength = data.readUInt16BE(at: offset) else { return nil }
        offset += 2

        var exceptionTable: [ExceptionTableEntry] = []
        for _ in 0..<exceptionTableLength {
            guard let startPC = data.readUInt16BE(at: offset),
                  let endPC = data.readUInt16BE(at: offset + 2),
                  let handlerPC = data.readUInt16BE(at: offset + 4),
                  let catchType = data.readUInt16BE(at: offset + 6) else {
                break
            }
            exceptionTable.append(ExceptionTableEntry(
                startPC: startPC,
                endPC: endPC,
                handlerPC: handlerPC,
                catchType: catchType
            ))
            offset += 8
        }

        return CodeAttribute(
            maxStack: maxStack,
            maxLocals: maxLocals,
            code: Data(code),
            exceptionTable: exceptionTable,
            attributes: []
        )
    }

    // MARK: - Helpers

    private func resolveUtf8(index: Int, constantPool: [ConstantPoolEntry]) -> String {
        guard index > 0, index < constantPool.count else { return "" }
        if case .utf8(let string) = constantPool[index] {
            return string
        }
        return ""
    }

    private func resolveClassName(index: Int, constantPool: [ConstantPoolEntry]) -> String {
        guard index > 0, index < constantPool.count else { return "" }
        if case .classRef(let nameIndex) = constantPool[index] {
            return resolveUtf8(index: nameIndex, constantPool: constantPool)
        }
        return ""
    }
}

// Data extensions are defined in BinaryLoader.swift

// MARK: - BinaryFile Extensions for Java

extension BinaryFile {
    private static var javaClassesKey = "javaClasses"
    private static var jarFileKey = "jarFile"

    var javaClasses: [JARLoader.JavaClass]? {
        get { objc_getAssociatedObject(self, &BinaryFile.javaClassesKey) as? [JARLoader.JavaClass] }
        set { objc_setAssociatedObject(self, &BinaryFile.javaClassesKey, newValue, .OBJC_ASSOCIATION_RETAIN) }
    }

    var jarFile: JARLoader.JARFile? {
        get { objc_getAssociatedObject(self, &BinaryFile.jarFileKey) as? JARLoader.JARFile }
        set { objc_setAssociatedObject(self, &BinaryFile.jarFileKey, newValue, .OBJC_ASSOCIATION_RETAIN) }
    }
}
