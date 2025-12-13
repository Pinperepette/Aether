import Foundation

/// Analyzes binary to find strings
class StringAnalyzer {

    private let minStringLength = 4
    private let maxStringLength = 4096

    /// Analyze binary and extract strings
    func analyze(binary: BinaryFile) -> [StringReference] {
        var strings: [StringReference] = []

        // Scan data sections for strings
        let dataSections = binary.sections.filter {
            !$0.containsCode &&
            ($0.name.contains("data") ||
             $0.name.contains("const") ||
             $0.name.contains("rodata") ||
             $0.name.contains("cstring") ||
             $0.name == "__cstring" ||
             $0.name == "__cfstring" ||
             $0.name == ".rodata" ||
             $0.name == ".data")
        }

        // Also scan code sections for inline strings
        let codeSections = binary.sections.filter { $0.containsCode }

        for section in dataSections + codeSections {
            let sectionStrings = extractStrings(from: section)
            strings.append(contentsOf: sectionStrings)
        }

        // Remove duplicates
        var seen = Set<UInt64>()
        strings = strings.filter { str in
            if seen.contains(str.address) {
                return false
            }
            seen.insert(str.address)
            return true
        }

        // Sort by address
        strings.sort { $0.address < $1.address }

        return strings
    }

    // MARK: - String Extraction

    private func extractStrings(from section: Section) -> [StringReference] {
        var strings: [StringReference] = []
        let data = section.data

        // Try ASCII/UTF-8 strings
        let asciiStrings = extractASCIIStrings(from: data, baseAddress: section.address)
        strings.append(contentsOf: asciiStrings)

        // Try UTF-16 strings (for Windows binaries or CFStrings)
        if section.name.contains("ustring") || section.name.contains("cfstring") {
            let utf16Strings = extractUTF16Strings(from: data, baseAddress: section.address)
            strings.append(contentsOf: utf16Strings)
        }

        return strings
    }

    private func extractASCIIStrings(from data: Data, baseAddress: UInt64) -> [StringReference] {
        var strings: [StringReference] = []
        var currentString: [UInt8] = []
        var stringStart: Int = 0

        for i in 0..<data.count {
            let byte = data[data.startIndex + i]

            if isPrintableASCII(byte) {
                if currentString.isEmpty {
                    stringStart = i
                }
                currentString.append(byte)
            } else {
                if byte == 0 && currentString.count >= minStringLength {
                    // Found null-terminated string
                    if let str = String(bytes: currentString, encoding: .utf8),
                       isValidString(str) {
                        strings.append(StringReference(
                            address: baseAddress + UInt64(stringStart),
                            value: str,
                            encoding: .utf8,
                            xrefs: []
                        ))
                    }
                }
                currentString.removeAll()
            }

            // Limit string length
            if currentString.count >= maxStringLength {
                currentString.removeAll()
            }
        }

        return strings
    }

    private func extractUTF16Strings(from data: Data, baseAddress: UInt64) -> [StringReference] {
        var strings: [StringReference] = []
        var currentChars: [UInt16] = []
        var stringStart: Int = 0

        var i = 0
        while i + 1 < data.count {
            let low = UInt16(data[data.startIndex + i])
            let high = UInt16(data[data.startIndex + i + 1])
            let char = low | (high << 8)

            if char > 0 && (char < 0xD800 || char > 0xDFFF) {
                // Valid BMP character
                if isPrintableUnicode(char) {
                    if currentChars.isEmpty {
                        stringStart = i
                    }
                    currentChars.append(char)
                } else if char == 0 && currentChars.count >= minStringLength {
                    // Found null-terminated UTF-16 string
                    let str = String(utf16CodeUnits: currentChars, count: currentChars.count)
                    if isValidString(str) {
                        strings.append(StringReference(
                            address: baseAddress + UInt64(stringStart),
                            value: str,
                            encoding: .utf16,
                            xrefs: []
                        ))
                    }
                    currentChars.removeAll()
                } else {
                    currentChars.removeAll()
                }
            } else {
                currentChars.removeAll()
            }

            i += 2

            if currentChars.count >= maxStringLength / 2 {
                currentChars.removeAll()
            }
        }

        return strings
    }

    // MARK: - Validation

    private func isPrintableASCII(_ byte: UInt8) -> Bool {
        // Printable ASCII: 0x20-0x7E, plus tab, newline, carriage return
        return (byte >= 0x20 && byte <= 0x7E) ||
               byte == 0x09 || byte == 0x0A || byte == 0x0D
    }

    private func isPrintableUnicode(_ char: UInt16) -> Bool {
        // Basic printable range
        return (char >= 0x20 && char <= 0x7E) ||
               (char >= 0xA0 && char <= 0xFFFF) ||
               char == 0x09 || char == 0x0A || char == 0x0D
    }

    private func isValidString(_ str: String) -> Bool {
        // Filter out likely false positives

        // Must have some letters
        let hasLetters = str.contains { $0.isLetter }
        if !hasLetters && str.count < 8 {
            return false
        }

        // Check for too many consecutive non-printable ratio
        let printableCount = str.filter { $0.isLetter || $0.isNumber || $0.isPunctuation || $0.isWhitespace }.count
        let ratio = Double(printableCount) / Double(str.count)
        if ratio < 0.7 {
            return false
        }

        // Filter out strings that look like binary data
        let suspiciousPatterns = [
            "\\x",
            "\u{FFFD}",  // Replacement character
        ]
        for pattern in suspiciousPatterns {
            if str.contains(pattern) {
                return false
            }
        }

        return true
    }
}
