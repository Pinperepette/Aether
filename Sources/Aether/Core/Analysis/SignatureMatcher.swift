import Foundation

// MARK: - Signature Matching Engine

/// Pattern-based signature matching for identifying functions, libraries, and code patterns
class SignatureMatcher {

    // MARK: - Signature Types

    struct Signature: Codable, Identifiable {
        let id: UUID
        let name: String
        let description: String
        let category: SignatureCategory
        let architecture: Architecture
        let pattern: Pattern
        let metadata: [String: String]

        init(name: String, description: String, category: SignatureCategory,
             architecture: Architecture, pattern: Pattern, metadata: [String: String] = [:]) {
            self.id = UUID()
            self.name = name
            self.description = description
            self.category = category
            self.architecture = architecture
            self.pattern = pattern
            self.metadata = metadata
        }
    }

    enum SignatureCategory: String, Codable, CaseIterable {
        case library = "Library"
        case compiler = "Compiler"
        case packer = "Packer"
        case malware = "Malware"
        case crypto = "Crypto"
        case vulnerability = "Vulnerability"
        case custom = "Custom"
    }

    struct Pattern: Codable {
        /// Byte pattern with wildcards
        /// Format: "48 89 5C 24 ?? 48 89 6C 24 ??"
        /// ?? = wildcard (matches any byte)
        let bytes: String

        /// Optional mask for more complex patterns
        /// 1 = must match, 0 = wildcard
        let mask: String?

        /// Minimum function size (for function signatures)
        let minSize: Int?

        /// Maximum function size
        let maxSize: Int?

        /// Required strings in the function
        let requiredStrings: [String]?

        /// Required imports called by the function
        let requiredImports: [String]?
    }

    struct Match {
        let signature: Signature
        let address: UInt64
        let confidence: Double
        let matchedBytes: Data
    }

    // MARK: - Properties

    private var signatures: [Signature] = []
    private var compiledPatterns: [UUID: CompiledPattern] = [:]

    private struct CompiledPattern {
        let bytes: [UInt8?]  // nil = wildcard
        let minSize: Int?
        let maxSize: Int?
    }

    // MARK: - Initialization

    init() {
        loadBuiltInSignatures()
    }

    // MARK: - Signature Management

    func addSignature(_ signature: Signature) {
        signatures.append(signature)
        compiledPatterns[signature.id] = compilePattern(signature.pattern)
    }

    func removeSignature(id: UUID) {
        signatures.removeAll { $0.id == id }
        compiledPatterns.removeValue(forKey: id)
    }

    func loadSignatures(from url: URL) throws {
        let data = try Data(contentsOf: url)
        let loaded = try JSONDecoder().decode([Signature].self, from: data)
        for sig in loaded {
            addSignature(sig)
        }
    }

    func saveSignatures(to url: URL) throws {
        let data = try JSONEncoder().encode(signatures)
        try data.write(to: url)
    }

    // MARK: - Pattern Compilation

    private func compilePattern(_ pattern: Pattern) -> CompiledPattern {
        var bytes: [UInt8?] = []

        let parts = pattern.bytes.split(separator: " ")
        for part in parts {
            if part == "??" || part == "?" {
                bytes.append(nil)
            } else if let byte = UInt8(part, radix: 16) {
                bytes.append(byte)
            }
        }

        return CompiledPattern(
            bytes: bytes,
            minSize: pattern.minSize,
            maxSize: pattern.maxSize
        )
    }

    // MARK: - Matching

    /// Scan binary for all matching signatures
    func scan(binary: BinaryFile) -> [Match] {
        var matches: [Match] = []

        for section in binary.sections where section.containsCode {
            let sectionMatches = scanSection(section, binary: binary)
            matches.append(contentsOf: sectionMatches)
        }

        return matches
    }

    /// Scan a single section
    private func scanSection(_ section: Section, binary: BinaryFile) -> [Match] {
        var matches: [Match] = []

        for signature in signatures {
            guard signature.architecture == binary.architecture || signature.architecture == .unknown else {
                continue
            }

            guard let compiled = compiledPatterns[signature.id] else { continue }

            let sectionMatches = matchPattern(
                compiled,
                in: section.data,
                baseAddress: section.address,
                signature: signature
            )

            matches.append(contentsOf: sectionMatches)
        }

        return matches
    }

    /// Match a compiled pattern against data
    private func matchPattern(
        _ pattern: CompiledPattern,
        in data: Data,
        baseAddress: UInt64,
        signature: Signature
    ) -> [Match] {
        var matches: [Match] = []
        let patternLength = pattern.bytes.count

        guard patternLength > 0, data.count >= patternLength else { return [] }

        for offset in 0...(data.count - patternLength) {
            if matchAtOffset(pattern, in: data, offset: offset) {
                let matchedData = data.subdata(in: offset..<(offset + patternLength))
                let confidence = calculateConfidence(pattern, matchedData: matchedData)

                matches.append(Match(
                    signature: signature,
                    address: baseAddress + UInt64(offset),
                    confidence: confidence,
                    matchedBytes: matchedData
                ))
            }
        }

        return matches
    }

    private func matchAtOffset(_ pattern: CompiledPattern, in data: Data, offset: Int) -> Bool {
        for (i, expected) in pattern.bytes.enumerated() {
            guard let expected = expected else { continue }  // Wildcard

            let actual = data[data.startIndex + offset + i]
            if actual != expected {
                return false
            }
        }
        return true
    }

    private func calculateConfidence(_ pattern: CompiledPattern, matchedData: Data) -> Double {
        let totalBytes = pattern.bytes.count
        let wildcardCount = pattern.bytes.filter { $0 == nil }.count
        let matchedCount = totalBytes - wildcardCount

        // Higher confidence with fewer wildcards
        return Double(matchedCount) / Double(totalBytes)
    }

    // MARK: - Built-in Signatures

    private func loadBuiltInSignatures() {
        // Common function prologues

        // x86_64 function prologue (push rbp; mov rbp, rsp)
        addSignature(Signature(
            name: "x86_64 Function Prologue",
            description: "Standard x86_64 function prologue",
            category: .compiler,
            architecture: .x86_64,
            pattern: Pattern(
                bytes: "55 48 89 E5",
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))

        // x86_64 function prologue with stack allocation
        addSignature(Signature(
            name: "x86_64 Function Prologue (Stack Alloc)",
            description: "x86_64 function prologue with stack allocation",
            category: .compiler,
            architecture: .x86_64,
            pattern: Pattern(
                bytes: "55 48 89 E5 48 83 EC ??",
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))

        // ARM64 function prologue (stp x29, x30, [sp, #-N]!)
        addSignature(Signature(
            name: "ARM64 Function Prologue",
            description: "Standard ARM64 function prologue",
            category: .compiler,
            architecture: .arm64,
            pattern: Pattern(
                bytes: "FD 7B ?? A9",
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))

        // Crypto signatures

        // AES S-Box (partial)
        addSignature(Signature(
            name: "AES S-Box",
            description: "AES encryption S-Box lookup table",
            category: .crypto,
            architecture: .unknown,
            pattern: Pattern(
                bytes: "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76",
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))

        // RC4 key scheduling
        addSignature(Signature(
            name: "RC4 Key Schedule",
            description: "RC4 stream cipher key scheduling",
            category: .crypto,
            architecture: .unknown,
            pattern: Pattern(
                bytes: "00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F",
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))

        // Vulnerability patterns

        // Format string (x86_64 printf call pattern)
        addSignature(Signature(
            name: "Potential Format String",
            description: "Possible format string vulnerability pattern",
            category: .vulnerability,
            architecture: .x86_64,
            pattern: Pattern(
                bytes: "48 8D 3D ?? ?? ?? ?? E8",  // lea rdi, [rip+...]; call
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: ["_printf", "_sprintf", "_fprintf"]
            )
        ))

        // Packer signatures

        // UPX header
        addSignature(Signature(
            name: "UPX Packed",
            description: "UPX packer signature",
            category: .packer,
            architecture: .unknown,
            pattern: Pattern(
                bytes: "55 50 58 21",  // "UPX!"
                mask: nil,
                minSize: nil,
                maxSize: nil,
                requiredStrings: nil,
                requiredImports: nil
            )
        ))
    }
}

// MARK: - FLIRT-style Signature Support

/// FLIRT (Fast Library Identification and Recognition Technology) compatible signatures
class FLIRTMatcher {

    struct FLIRTSignature {
        let name: String
        let pattern: [UInt8?]  // nil = wildcard
        let crc16: UInt16?
        let crcLength: Int
        let totalLength: Int
        let publicNames: [(offset: Int, name: String)]
        let referencedNames: [(offset: Int, name: String)]
    }

    private var signatures: [FLIRTSignature] = []

    /// Load FLIRT signatures from .sig file
    func loadSignatures(from url: URL) throws {
        // FLIRT .sig files are binary format
        // This is a simplified implementation
        let data = try Data(contentsOf: url)
        parseSignatureFile(data)
    }

    private func parseSignatureFile(_ data: Data) {
        // FLIRT signature file parsing would go here
        // Format is documented in IDA SDK
    }

    /// Match functions against FLIRT signatures
    func matchFunctions(_ functions: [Function], in binary: BinaryFile) -> [(Function, String)] {
        var results: [(Function, String)] = []

        for function in functions {
            if let name = identifyFunction(function, in: binary) {
                results.append((function, name))
            }
        }

        return results
    }

    private func identifyFunction(_ function: Function, in binary: BinaryFile) -> String? {
        guard let section = binary.section(containing: function.startAddress),
              let functionData = binary.read(at: function.startAddress, count: Int(min(function.size, 64))) else {
            return nil
        }

        for sig in signatures {
            if matchSignature(sig, against: functionData) {
                return sig.publicNames.first?.name ?? sig.name
            }
        }

        return nil
    }

    private func matchSignature(_ signature: FLIRTSignature, against data: Data) -> Bool {
        guard data.count >= signature.pattern.count else { return false }

        for (i, expected) in signature.pattern.enumerated() {
            guard let expected = expected else { continue }
            if data[data.startIndex + i] != expected {
                return false
            }
        }

        // Verify CRC if present
        if let crc = signature.crc16, signature.crcLength > 0 {
            let crcData = data.subdata(in: signature.pattern.count..<(signature.pattern.count + signature.crcLength))
            let calculatedCRC = calculateCRC16(crcData)
            if calculatedCRC != crc {
                return false
            }
        }

        return true
    }

    private func calculateCRC16(_ data: Data) -> UInt16 {
        var crc: UInt16 = 0xFFFF

        for byte in data {
            crc ^= UInt16(byte)
            for _ in 0..<8 {
                if crc & 1 != 0 {
                    crc = (crc >> 1) ^ 0xA001
                } else {
                    crc >>= 1
                }
            }
        }

        return crc
    }
}

// MARK: - YARA Rule Support

/// YARA-style rule matching
class YARAMatcher {

    struct YARARule {
        let name: String
        let meta: [String: String]
        let strings: [YARAString]
        let condition: String
    }

    struct YARAString {
        let identifier: String
        let value: StringValue
        let modifiers: Set<StringModifier>

        enum StringValue {
            case text(String)
            case hex([UInt8?])  // nil = wildcard
            case regex(String)
        }

        enum StringModifier {
            case nocase
            case wide
            case ascii
            case fullword
        }
    }

    struct YARAMatch {
        let rule: YARARule
        let stringMatches: [(identifier: String, offset: UInt64)]
    }

    private var rules: [YARARule] = []

    /// Parse YARA rules from text
    func loadRules(_ text: String) throws {
        // Simplified YARA parser
        // Full implementation would parse complete YARA syntax
        let rulePattern = #"rule\s+(\w+)\s*\{([^}]+)\}"#
        let regex = try NSRegularExpression(pattern: rulePattern, options: [.dotMatchesLineSeparators])

        let matches = regex.matches(in: text, range: NSRange(text.startIndex..., in: text))

        for match in matches {
            if let nameRange = Range(match.range(at: 1), in: text),
               let bodyRange = Range(match.range(at: 2), in: text) {
                let name = String(text[nameRange])
                let body = String(text[bodyRange])

                if let rule = parseRuleBody(name: name, body: body) {
                    rules.append(rule)
                }
            }
        }
    }

    private func parseRuleBody(name: String, body: String) -> YARARule? {
        // Simplified parsing
        var meta: [String: String] = [:]
        var strings: [YARAString] = []
        var condition = "any of them"

        // Parse strings section
        if let stringsMatch = body.range(of: #"strings:\s*([\s\S]*?)(?:condition:|$)"#, options: .regularExpression) {
            let stringsSection = String(body[stringsMatch])
            strings = parseStrings(stringsSection)
        }

        // Parse condition
        if let condMatch = body.range(of: #"condition:\s*(.*)"#, options: .regularExpression) {
            condition = String(body[condMatch]).replacingOccurrences(of: "condition:", with: "").trimmingCharacters(in: .whitespaces)
        }

        return YARARule(name: name, meta: meta, strings: strings, condition: condition)
    }

    private func parseStrings(_ section: String) -> [YARAString] {
        var strings: [YARAString] = []

        // Match $identifier = "string" or $identifier = { hex }
        let pattern = #"\$(\w+)\s*=\s*(?:"([^"]+)"|{([^}]+)})"#
        if let regex = try? NSRegularExpression(pattern: pattern) {
            let matches = regex.matches(in: section, range: NSRange(section.startIndex..., in: section))

            for match in matches {
                guard let idRange = Range(match.range(at: 1), in: section) else { continue }
                let identifier = String(section[idRange])

                let value: YARAString.StringValue
                if let textRange = Range(match.range(at: 2), in: section) {
                    value = .text(String(section[textRange]))
                } else if let hexRange = Range(match.range(at: 3), in: section) {
                    let hexStr = String(section[hexRange])
                    let bytes = parseHexPattern(hexStr)
                    value = .hex(bytes)
                } else {
                    continue
                }

                strings.append(YARAString(identifier: "$\(identifier)", value: value, modifiers: []))
            }
        }

        return strings
    }

    private func parseHexPattern(_ hex: String) -> [UInt8?] {
        var bytes: [UInt8?] = []
        let parts = hex.split(separator: " ")

        for part in parts {
            if part == "??" || part == "?" {
                bytes.append(nil)
            } else if let byte = UInt8(part, radix: 16) {
                bytes.append(byte)
            }
        }

        return bytes
    }

    /// Scan binary with YARA rules
    func scan(binary: BinaryFile) -> [YARAMatch] {
        var matches: [YARAMatch] = []

        for rule in rules {
            if let match = matchRule(rule, in: binary) {
                matches.append(match)
            }
        }

        return matches
    }

    private func matchRule(_ rule: YARARule, in binary: BinaryFile) -> YARAMatch? {
        var stringMatches: [(String, UInt64)] = []

        for section in binary.sections {
            for yaraString in rule.strings {
                let sectionMatches = matchString(yaraString, in: section.data, baseAddress: section.address)
                stringMatches.append(contentsOf: sectionMatches.map { (yaraString.identifier, $0) })
            }
        }

        // Evaluate condition (simplified: "any of them")
        if !stringMatches.isEmpty {
            return YARAMatch(rule: rule, stringMatches: stringMatches)
        }

        return nil
    }

    private func matchString(_ yaraString: YARAString, in data: Data, baseAddress: UInt64) -> [UInt64] {
        var matches: [UInt64] = []

        switch yaraString.value {
        case .text(let text):
            if let textData = text.data(using: .utf8) {
                matches = findData(textData, in: data, baseAddress: baseAddress)
            }

        case .hex(let pattern):
            matches = findPattern(pattern, in: data, baseAddress: baseAddress)

        case .regex:
            // Regex matching would require more complex implementation
            break
        }

        return matches
    }

    private func findData(_ needle: Data, in haystack: Data, baseAddress: UInt64) -> [UInt64] {
        var matches: [UInt64] = []

        for offset in 0...(haystack.count - needle.count) {
            let slice = haystack.subdata(in: offset..<(offset + needle.count))
            if slice == needle {
                matches.append(baseAddress + UInt64(offset))
            }
        }

        return matches
    }

    private func findPattern(_ pattern: [UInt8?], in data: Data, baseAddress: UInt64) -> [UInt64] {
        var matches: [UInt64] = []

        guard !pattern.isEmpty, data.count >= pattern.count else { return [] }

        for offset in 0...(data.count - pattern.count) {
            var matched = true
            for (i, expected) in pattern.enumerated() {
                guard let expected = expected else { continue }
                if data[data.startIndex + offset + i] != expected {
                    matched = false
                    break
                }
            }
            if matched {
                matches.append(baseAddress + UInt64(offset))
            }
        }

        return matches
    }
}
