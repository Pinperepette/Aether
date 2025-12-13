import Foundation

// MARK: - Objective-C Runtime Analysis

/// Analyzes Objective-C runtime information in Mach-O binaries
class ObjCAnalyzer {

    // MARK: - Models

    struct ObjCClass: Identifiable {
        let id = UUID()
        let name: String
        let superclassName: String?
        let metaclass: UInt64?
        let instanceMethods: [ObjCMethod]
        let classMethods: [ObjCMethod]
        let properties: [ObjCProperty]
        let ivars: [ObjCIvar]
        let protocols: [String]
        let address: UInt64
    }

    struct ObjCMethod: Identifiable {
        let id = UUID()
        let selector: String
        let types: String
        let implementation: UInt64
        let isClassMethod: Bool

        var decodedSignature: String {
            ObjCAnalyzer.decodeTypeEncoding(types)
        }
    }

    struct ObjCProperty: Identifiable {
        let id = UUID()
        let name: String
        let attributes: String
        let getter: String?
        let setter: String?
        let type: String?
        let isReadonly: Bool
        let isWeak: Bool
        let isAtomic: Bool
    }

    struct ObjCIvar: Identifiable {
        let id = UUID()
        let name: String
        let type: String
        let offset: UInt64
        let size: Int
    }

    struct ObjCProtocol: Identifiable {
        let id = UUID()
        let name: String
        let instanceMethods: [ObjCMethod]
        let classMethods: [ObjCMethod]
        let optionalInstanceMethods: [ObjCMethod]
        let optionalClassMethods: [ObjCMethod]
        let properties: [ObjCProperty]
    }

    struct ObjCCategory: Identifiable {
        let id = UUID()
        let name: String
        let className: String
        let instanceMethods: [ObjCMethod]
        let classMethods: [ObjCMethod]
        let properties: [ObjCProperty]
    }

    struct ObjCSelector: Identifiable, Hashable {
        let id = UUID()
        let name: String
        let address: UInt64

        func hash(into hasher: inout Hasher) {
            hasher.combine(name)
        }

        static func == (lhs: ObjCSelector, rhs: ObjCSelector) -> Bool {
            lhs.name == rhs.name
        }
    }

    // MARK: - Analysis Result

    struct AnalysisResult {
        var classes: [ObjCClass]
        var protocols: [ObjCProtocol]
        var categories: [ObjCCategory]
        var selectors: [ObjCSelector]
        var classReferences: [UInt64: String]
        var selectorReferences: [UInt64: String]
    }

    // MARK: - Analysis

    /// Analyze Objective-C runtime information
    func analyze(binary: BinaryFile) -> AnalysisResult {
        var result = AnalysisResult(
            classes: [],
            protocols: [],
            categories: [],
            selectors: [],
            classReferences: [:],
            selectorReferences: [:]
        )

        guard binary.format == .machO else {
            return result
        }

        // Find ObjC sections
        let classListSection = binary.sections.first { $0.name == "__objc_classlist" }
        let catListSection = binary.sections.first { $0.name == "__objc_catlist" }
        let protoListSection = binary.sections.first { $0.name == "__objc_protolist" }
        let selRefsSection = binary.sections.first { $0.name == "__objc_selrefs" }
        let classRefsSection = binary.sections.first { $0.name == "__objc_classrefs" }
        let methNamesSection = binary.sections.first { $0.name == "__objc_methname" }
        let classNamesSection = binary.sections.first { $0.name == "__objc_classname" }

        // Parse classes
        if let classListSection = classListSection {
            result.classes = parseClassList(classListSection, binary: binary)
        }

        // Parse categories
        if let catListSection = catListSection {
            result.categories = parseCategoryList(catListSection, binary: binary)
        }

        // Parse protocols
        if let protoListSection = protoListSection {
            result.protocols = parseProtocolList(protoListSection, binary: binary)
        }

        // Parse selector references
        if let selRefsSection = selRefsSection {
            result.selectors = parseSelectorRefs(selRefsSection, binary: binary)
            for sel in result.selectors {
                result.selectorReferences[sel.address] = sel.name
            }
        }

        // Parse class references
        if let classRefsSection = classRefsSection {
            result.classReferences = parseClassRefs(classRefsSection, binary: binary)
        }

        return result
    }

    // MARK: - Parsing

    private func parseClassList(_ section: Section, binary: BinaryFile) -> [ObjCClass] {
        var classes: [ObjCClass] = []
        let pointerSize = binary.architecture.pointerSize
        let data = section.data

        for offset in stride(from: 0, to: data.count, by: pointerSize) {
            let classPtr: UInt64
            if pointerSize == 8 {
                guard let ptr = data.readUInt64LE(at: offset) else { continue }
                classPtr = ptr
            } else {
                guard let ptr = data.readUInt32LE(at: offset) else { continue }
                classPtr = UInt64(ptr)
            }

            if let objcClass = parseClass(at: classPtr, binary: binary) {
                classes.append(objcClass)
            }
        }

        return classes
    }

    private func parseClass(at address: UInt64, binary: BinaryFile) -> ObjCClass? {
        guard let classData = binary.read(at: address, count: 40) else { return nil }

        // class_ro_t structure
        let dataPtr: UInt64
        if binary.architecture.pointerSize == 8 {
            guard let ptr = classData.readUInt64LE(at: 32) else { return nil }
            dataPtr = ptr & ~0x7  // Remove flag bits
        } else {
            guard let ptr = classData.readUInt32LE(at: 16) else { return nil }
            dataPtr = UInt64(ptr) & ~0x3
        }

        guard let classRO = binary.read(at: dataPtr, count: 72) else { return nil }

        // Read class name
        let namePtr: UInt64
        if binary.architecture.pointerSize == 8 {
            guard let ptr = classRO.readUInt64LE(at: 24) else { return nil }
            namePtr = ptr
        } else {
            guard let ptr = classRO.readUInt32LE(at: 16) else { return nil }
            namePtr = UInt64(ptr)
        }

        let className = binary.readString(at: namePtr) ?? "Unknown"

        // Parse methods
        let baseMethodsPtr: UInt64
        if binary.architecture.pointerSize == 8 {
            guard let ptr = classRO.readUInt64LE(at: 32) else { return nil }
            baseMethodsPtr = ptr
        } else {
            guard let ptr = classRO.readUInt32LE(at: 20) else { return nil }
            baseMethodsPtr = UInt64(ptr)
        }

        let instanceMethods = parseMethodList(at: baseMethodsPtr, binary: binary, isClassMethod: false)

        // Parse properties
        let basePropertiesPtr: UInt64
        if binary.architecture.pointerSize == 8 {
            basePropertiesPtr = classRO.readUInt64LE(at: 64) ?? 0
        } else {
            basePropertiesPtr = UInt64(classRO.readUInt32LE(at: 40) ?? 0)
        }

        let properties = parsePropertyList(at: basePropertiesPtr, binary: binary)

        // Parse ivars
        let ivarsPtr: UInt64
        if binary.architecture.pointerSize == 8 {
            ivarsPtr = classRO.readUInt64LE(at: 48) ?? 0
        } else {
            ivarsPtr = UInt64(classRO.readUInt32LE(at: 28) ?? 0)
        }

        let ivars = parseIvarList(at: ivarsPtr, binary: binary)

        return ObjCClass(
            name: className,
            superclassName: nil,  // Would need to follow superclass pointer
            metaclass: nil,
            instanceMethods: instanceMethods,
            classMethods: [],
            properties: properties,
            ivars: ivars,
            protocols: [],
            address: address
        )
    }

    private func parseMethodList(at address: UInt64, binary: BinaryFile, isClassMethod: Bool) -> [ObjCMethod] {
        guard address != 0 else { return [] }

        var methods: [ObjCMethod] = []

        guard let header = binary.read(at: address, count: 8) else { return [] }
        guard let entsize = header.readUInt32LE(at: 0),
              let count = header.readUInt32LE(at: 4) else { return [] }

        let actualEntsize = Int(entsize & 0xFFFF)
        let methodStart = address + 8

        for i in 0..<count {
            let methodAddr = methodStart + UInt64(i) * UInt64(actualEntsize)

            guard let methodData = binary.read(at: methodAddr, count: actualEntsize) else { continue }

            let namePtr: UInt64
            let typesPtr: UInt64
            let impPtr: UInt64

            if binary.architecture.pointerSize == 8 {
                namePtr = methodData.readUInt64LE(at: 0) ?? 0
                typesPtr = methodData.readUInt64LE(at: 8) ?? 0
                impPtr = methodData.readUInt64LE(at: 16) ?? 0
            } else {
                namePtr = UInt64(methodData.readUInt32LE(at: 0) ?? 0)
                typesPtr = UInt64(methodData.readUInt32LE(at: 4) ?? 0)
                impPtr = UInt64(methodData.readUInt32LE(at: 8) ?? 0)
            }

            let selector = binary.readString(at: namePtr) ?? "unknown"
            let types = binary.readString(at: typesPtr) ?? ""

            methods.append(ObjCMethod(
                selector: selector,
                types: types,
                implementation: impPtr,
                isClassMethod: isClassMethod
            ))
        }

        return methods
    }

    private func parsePropertyList(at address: UInt64, binary: BinaryFile) -> [ObjCProperty] {
        guard address != 0 else { return [] }

        var properties: [ObjCProperty] = []

        guard let header = binary.read(at: address, count: 8) else { return [] }
        guard let entsize = header.readUInt32LE(at: 0),
              let count = header.readUInt32LE(at: 4) else { return [] }

        let propStart = address + 8

        for i in 0..<count {
            let propAddr = propStart + UInt64(i) * UInt64(entsize)

            guard let propData = binary.read(at: propAddr, count: Int(entsize)) else { continue }

            let namePtr: UInt64
            let attrsPtr: UInt64

            if binary.architecture.pointerSize == 8 {
                namePtr = propData.readUInt64LE(at: 0) ?? 0
                attrsPtr = propData.readUInt64LE(at: 8) ?? 0
            } else {
                namePtr = UInt64(propData.readUInt32LE(at: 0) ?? 0)
                attrsPtr = UInt64(propData.readUInt32LE(at: 4) ?? 0)
            }

            let name = binary.readString(at: namePtr) ?? "unknown"
            let attrs = binary.readString(at: attrsPtr) ?? ""

            let property = parsePropertyAttributes(name: name, attributes: attrs)
            properties.append(property)
        }

        return properties
    }

    private func parsePropertyAttributes(name: String, attributes: String) -> ObjCProperty {
        var type: String?
        var getter: String?
        var setter: String?
        var isReadonly = false
        var isWeak = false
        var isAtomic = true

        let parts = attributes.split(separator: ",")
        for part in parts {
            let attr = String(part)
            if attr.hasPrefix("T") {
                type = String(attr.dropFirst())
            } else if attr.hasPrefix("G") {
                getter = String(attr.dropFirst())
            } else if attr.hasPrefix("S") {
                setter = String(attr.dropFirst())
            } else if attr == "R" {
                isReadonly = true
            } else if attr == "W" {
                isWeak = true
            } else if attr == "N" {
                isAtomic = false
            }
        }

        return ObjCProperty(
            name: name,
            attributes: attributes,
            getter: getter ?? name,
            setter: setter ?? (isReadonly ? nil : "set\(name.prefix(1).uppercased())\(name.dropFirst()):"),
            type: type,
            isReadonly: isReadonly,
            isWeak: isWeak,
            isAtomic: isAtomic
        )
    }

    private func parseIvarList(at address: UInt64, binary: BinaryFile) -> [ObjCIvar] {
        guard address != 0 else { return [] }

        var ivars: [ObjCIvar] = []

        guard let header = binary.read(at: address, count: 8) else { return [] }
        guard let entsize = header.readUInt32LE(at: 0),
              let count = header.readUInt32LE(at: 4) else { return [] }

        let ivarStart = address + 8

        for i in 0..<count {
            let ivarAddr = ivarStart + UInt64(i) * UInt64(entsize)

            guard let ivarData = binary.read(at: ivarAddr, count: Int(entsize)) else { continue }

            let offsetPtr: UInt64
            let namePtr: UInt64
            let typePtr: UInt64
            let size: Int

            if binary.architecture.pointerSize == 8 {
                offsetPtr = ivarData.readUInt64LE(at: 0) ?? 0
                namePtr = ivarData.readUInt64LE(at: 8) ?? 0
                typePtr = ivarData.readUInt64LE(at: 16) ?? 0
                size = Int(ivarData.readUInt32LE(at: 28) ?? 0)
            } else {
                offsetPtr = UInt64(ivarData.readUInt32LE(at: 0) ?? 0)
                namePtr = UInt64(ivarData.readUInt32LE(at: 4) ?? 0)
                typePtr = UInt64(ivarData.readUInt32LE(at: 8) ?? 0)
                size = Int(ivarData.readUInt32LE(at: 16) ?? 0)
            }

            let name = binary.readString(at: namePtr) ?? "unknown"
            let type = binary.readString(at: typePtr) ?? ""

            // Read actual offset value
            var offset: UInt64 = 0
            if let offsetData = binary.read(at: offsetPtr, count: binary.architecture.pointerSize) {
                if binary.architecture.pointerSize == 8 {
                    offset = offsetData.readUInt64LE(at: 0) ?? 0
                } else {
                    offset = UInt64(offsetData.readUInt32LE(at: 0) ?? 0)
                }
            }

            ivars.append(ObjCIvar(
                name: name,
                type: Self.decodeTypeEncoding(type),
                offset: offset,
                size: size
            ))
        }

        return ivars
    }

    private func parseCategoryList(_ section: Section, binary: BinaryFile) -> [ObjCCategory] {
        // Similar to class list parsing
        return []
    }

    private func parseProtocolList(_ section: Section, binary: BinaryFile) -> [ObjCProtocol] {
        // Similar to class list parsing
        return []
    }

    private func parseSelectorRefs(_ section: Section, binary: BinaryFile) -> [ObjCSelector] {
        var selectors: [ObjCSelector] = []
        let pointerSize = binary.architecture.pointerSize
        let data = section.data

        for offset in stride(from: 0, to: data.count, by: pointerSize) {
            let selPtr: UInt64
            if pointerSize == 8 {
                guard let ptr = data.readUInt64LE(at: offset) else { continue }
                selPtr = ptr
            } else {
                guard let ptr = data.readUInt32LE(at: offset) else { continue }
                selPtr = UInt64(ptr)
            }

            if let selName = binary.readString(at: selPtr) {
                selectors.append(ObjCSelector(
                    name: selName,
                    address: section.address + UInt64(offset)
                ))
            }
        }

        return selectors
    }

    private func parseClassRefs(_ section: Section, binary: BinaryFile) -> [UInt64: String] {
        var refs: [UInt64: String] = [:]
        // Would need to follow class pointers to get names
        return refs
    }

    // MARK: - Type Encoding

    /// Decode Objective-C type encoding
    private static func decodeTypeEncoding(_ encoding: String) -> String {
        var result = ""
        var index = encoding.startIndex

        while index < encoding.endIndex {
            let char = encoding[index]

            switch char {
            case "c": result += "char"
            case "i": result += "int"
            case "s": result += "short"
            case "l": result += "long"
            case "q": result += "long long"
            case "C": result += "unsigned char"
            case "I": result += "unsigned int"
            case "S": result += "unsigned short"
            case "L": result += "unsigned long"
            case "Q": result += "unsigned long long"
            case "f": result += "float"
            case "d": result += "double"
            case "B": result += "BOOL"
            case "v": result += "void"
            case "*": result += "char *"
            case "@":
                // Object type
                index = encoding.index(after: index)
                if index < encoding.endIndex && encoding[index] == "\"" {
                    // Has class name
                    index = encoding.index(after: index)
                    var className = ""
                    while index < encoding.endIndex && encoding[index] != "\"" {
                        className.append(encoding[index])
                        index = encoding.index(after: index)
                    }
                    result += "\(className) *"
                } else {
                    result += "id"
                    continue
                }
            case "#": result += "Class"
            case ":": result += "SEL"
            case "^":
                // Pointer
                index = encoding.index(after: index)
                if index < encoding.endIndex {
                    result += decodeTypeEncoding(String(encoding[index])) + " *"
                }
            case "[":
                // Array
                result += "array"
            case "{":
                // Struct
                index = encoding.index(after: index)
                var structName = ""
                while index < encoding.endIndex && encoding[index] != "=" && encoding[index] != "}" {
                    structName.append(encoding[index])
                    index = encoding.index(after: index)
                }
                result += "struct \(structName)"
                // Skip to end of struct
                while index < encoding.endIndex && encoding[index] != "}" {
                    index = encoding.index(after: index)
                }
            case "?": result += "unknown"
            default:
                // Number (for argument frame offsets) - skip
                if char.isNumber {
                    while index < encoding.endIndex && encoding[index].isNumber {
                        index = encoding.index(after: index)
                    }
                    continue
                }
            }

            index = encoding.index(after: index)
            if index < encoding.endIndex && !encoding[index].isNumber {
                result += ", "
            }
        }

        return result
    }
}
