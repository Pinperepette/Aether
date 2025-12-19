import Foundation

// MARK: - Cryptographic Algorithm Detection

/// Detects cryptographic algorithms and constants in binary code
class AdvancedCryptoDetector {

    // MARK: - Detection Results

    struct CryptoFinding {
        let algorithm: CryptoAlgorithm
        let address: UInt64
        let confidence: Double
        let evidence: [Evidence]
        let description: String
    }

    enum CryptoAlgorithm: String, CaseIterable {
        // Symmetric ciphers
        case aes = "AES"
        case des = "DES"
        case tripleDES = "3DES"
        case blowfish = "Blowfish"
        case twofish = "Twofish"
        case rc4 = "RC4"
        case chacha20 = "ChaCha20"
        case salsa20 = "Salsa20"
        case camellia = "Camellia"
        case serpent = "Serpent"

        // Hash functions
        case md5 = "MD5"
        case sha1 = "SHA-1"
        case sha256 = "SHA-256"
        case sha384 = "SHA-384"
        case sha512 = "SHA-512"
        case sha3 = "SHA-3"
        case blake2 = "BLAKE2"
        case whirlpool = "Whirlpool"
        case ripemd160 = "RIPEMD-160"

        // Asymmetric
        case rsa = "RSA"
        case dsa = "DSA"
        case ecdsa = "ECDSA"
        case curve25519 = "Curve25519"
        case ed25519 = "Ed25519"

        // Key derivation
        case pbkdf2 = "PBKDF2"
        case bcrypt = "bcrypt"
        case scrypt = "scrypt"
        case argon2 = "Argon2"

        // Other
        case crc32 = "CRC32"
        case base64 = "Base64"
        case unknown = "Unknown Crypto"
    }

    struct Evidence {
        let type: EvidenceType
        let address: UInt64
        let details: String

        enum EvidenceType {
            case constantMatch
            case sBoxMatch
            case magicNumber
            case structureMatch
            case instructionPattern
            case stringReference
        }
    }

    // MARK: - Crypto Constants

    /// AES S-Box (first 32 bytes for detection)
    private let aesSBox: [UInt8] = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
        0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
        0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    ]

    /// AES inverse S-Box (first 32 bytes)
    private let aesInvSBox: [UInt8] = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
        0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
        0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb
    ]

    /// AES round constants
    private let aesRcon: [UInt8] = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]

    /// DES initial permutation (first 16 values)
    private let desIP: [UInt8] = [
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4
    ]

    /// DES S-Box 1 (first row)
    private let desSBox1: [UInt8] = [
        14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7
    ]

    /// Blowfish P-array initial values
    private let blowfishP: [UInt32] = [
        0x243f6a88, 0x85a308d3, 0x13198a2e, 0x03707344,
        0xa4093822, 0x299f31d0, 0x082efa98, 0xec4e6c89
    ]

    /// MD5 constants (T[1] through T[8])
    private let md5K: [UInt32] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501
    ]

    /// MD5 initial hash values
    private let md5Init: [UInt32] = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    ]

    /// SHA-1 constants
    private let sha1K: [UInt32] = [
        0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6
    ]

    /// SHA-1 initial hash values
    private let sha1Init: [UInt32] = [
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0
    ]

    /// SHA-256 round constants (first 8)
    private let sha256K: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
    ]

    /// SHA-256 initial hash values
    private let sha256Init: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]

    /// SHA-512 round constants (first 8)
    private let sha512K: [UInt64] = [
        0x428a2f98d728ae22, 0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019,
        0x923f82a4af194f9b, 0xab1c5ed5da6d8118
    ]

    /// CRC32 polynomial
    private let crc32Poly: UInt32 = 0xedb88320

    /// CRC32 table (first 8 values)
    private let crc32Table: [UInt32] = [
        0x00000000, 0x77073096, 0xee0e612c, 0x990951ba,
        0x076dc419, 0x706af48f, 0xe963a535, 0x9e6495a3
    ]

    /// Base64 alphabet
    private let base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /// ChaCha20/Salsa20 constant "expand 32-byte k"
    private let chachaConstant: [UInt8] = [
        0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33,
        0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b
    ]

    /// Curve25519 prime (2^255 - 19)
    private let curve25519Prime: [UInt8] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f
    ]

    // MARK: - Detection

    /// Scan binary for cryptographic patterns
    func scan(binary: BinaryFile) -> [CryptoFinding] {
        var findings: [CryptoFinding] = []

        for section in binary.sections {
            // Scan for constant tables
            findings.append(contentsOf: scanForConstants(in: section))

            // Scan for magic strings
            findings.append(contentsOf: scanForStrings(in: section))
        }

        // Scan code sections for algorithmic patterns
        for section in binary.sections where section.containsCode {
            findings.append(contentsOf: scanCodePatterns(in: section, binary: binary))
        }

        // Deduplicate and rank findings
        return consolidateFindings(findings)
    }

    /// Scan section for constant tables
    private func scanForConstants(in section: Section) -> [CryptoFinding] {
        var findings: [CryptoFinding] = []
        let data = section.data

        // Scan for AES S-Box
        if let offset = findPattern(aesSBox, in: data) {
            findings.append(CryptoFinding(
                algorithm: .aes,
                address: section.address + UInt64(offset),
                confidence: 0.95,
                evidence: [Evidence(type: .sBoxMatch, address: section.address + UInt64(offset), details: "AES S-Box found")],
                description: "AES S-Box lookup table detected"
            ))
        }

        // Scan for AES inverse S-Box
        if let offset = findPattern(aesInvSBox, in: data) {
            findings.append(CryptoFinding(
                algorithm: .aes,
                address: section.address + UInt64(offset),
                confidence: 0.95,
                evidence: [Evidence(type: .sBoxMatch, address: section.address + UInt64(offset), details: "AES inverse S-Box found")],
                description: "AES inverse S-Box lookup table detected (decryption)"
            ))
        }

        // Scan for DES S-Boxes
        if let offset = findPattern(desSBox1, in: data) {
            findings.append(CryptoFinding(
                algorithm: .des,
                address: section.address + UInt64(offset),
                confidence: 0.85,
                evidence: [Evidence(type: .sBoxMatch, address: section.address + UInt64(offset), details: "DES S-Box found")],
                description: "DES S-Box detected"
            ))
        }

        // Scan for Blowfish P-array
        if let offset = findUInt32Pattern(blowfishP, in: data) {
            findings.append(CryptoFinding(
                algorithm: .blowfish,
                address: section.address + UInt64(offset),
                confidence: 0.9,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "Blowfish P-array found")],
                description: "Blowfish P-array initial values detected"
            ))
        }

        // Scan for MD5 constants
        if let offset = findUInt32Pattern(md5K, in: data) {
            findings.append(CryptoFinding(
                algorithm: .md5,
                address: section.address + UInt64(offset),
                confidence: 0.9,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "MD5 round constants found")],
                description: "MD5 round constants detected"
            ))
        }

        // Scan for SHA-1 constants
        if let offset = findUInt32Pattern(sha1K, in: data) {
            findings.append(CryptoFinding(
                algorithm: .sha1,
                address: section.address + UInt64(offset),
                confidence: 0.85,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "SHA-1 constants found")],
                description: "SHA-1 round constants detected"
            ))
        }

        // Scan for SHA-256 constants
        if let offset = findUInt32Pattern(sha256K, in: data) {
            findings.append(CryptoFinding(
                algorithm: .sha256,
                address: section.address + UInt64(offset),
                confidence: 0.9,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "SHA-256 round constants found")],
                description: "SHA-256 round constants detected"
            ))
        }

        // Scan for SHA-256 initial values
        if let offset = findUInt32Pattern(sha256Init, in: data) {
            findings.append(CryptoFinding(
                algorithm: .sha256,
                address: section.address + UInt64(offset),
                confidence: 0.85,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "SHA-256 initial hash values found")],
                description: "SHA-256 initial hash values detected"
            ))
        }

        // Scan for CRC32 table
        if let offset = findUInt32Pattern(crc32Table, in: data) {
            findings.append(CryptoFinding(
                algorithm: .crc32,
                address: section.address + UInt64(offset),
                confidence: 0.9,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "CRC32 lookup table found")],
                description: "CRC32 lookup table detected"
            ))
        }

        // Scan for ChaCha20/Salsa20 constant
        if let offset = findPattern(chachaConstant, in: data) {
            findings.append(CryptoFinding(
                algorithm: .chacha20,
                address: section.address + UInt64(offset),
                confidence: 0.95,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "ChaCha20/Salsa20 expand constant found")],
                description: "ChaCha20/Salsa20 'expand 32-byte k' constant detected"
            ))
        }

        // Scan for Curve25519 prime
        if let offset = findPattern(curve25519Prime, in: data) {
            findings.append(CryptoFinding(
                algorithm: .curve25519,
                address: section.address + UInt64(offset),
                confidence: 0.9,
                evidence: [Evidence(type: .constantMatch, address: section.address + UInt64(offset), details: "Curve25519 prime found")],
                description: "Curve25519 prime (2^255 - 19) detected"
            ))
        }

        return findings
    }

    /// Scan for crypto-related strings
    private func scanForStrings(in section: Section) -> [CryptoFinding] {
        var findings: [CryptoFinding] = []

        let cryptoStrings: [(String, CryptoAlgorithm)] = [
            ("AES", .aes), ("Rijndael", .aes),
            ("DES", .des), ("3DES", .tripleDES), ("TripleDES", .tripleDES),
            ("Blowfish", .blowfish), ("Twofish", .twofish),
            ("RC4", .rc4), ("ARCFOUR", .rc4),
            ("ChaCha", .chacha20), ("Salsa20", .salsa20),
            ("MD5", .md5), ("SHA1", .sha1), ("SHA-1", .sha1),
            ("SHA256", .sha256), ("SHA-256", .sha256),
            ("SHA512", .sha512), ("SHA-512", .sha512),
            ("RSA", .rsa), ("DSA", .dsa), ("ECDSA", .ecdsa),
            ("PBKDF2", .pbkdf2), ("bcrypt", .bcrypt), ("scrypt", .scrypt),
            ("Argon2", .argon2),
            ("Base64", .base64),
            ("BEGIN RSA", .rsa), ("BEGIN PRIVATE KEY", .rsa),
            ("BEGIN CERTIFICATE", .rsa),
        ]

        // Convert section data to string for scanning
        if let sectionString = String(data: section.data, encoding: .utf8) {
            for (searchStr, algorithm) in cryptoStrings {
                if let range = sectionString.range(of: searchStr, options: .caseInsensitive) {
                    let offset = sectionString.distance(from: sectionString.startIndex, to: range.lowerBound)
                    findings.append(CryptoFinding(
                        algorithm: algorithm,
                        address: section.address + UInt64(offset),
                        confidence: 0.7,
                        evidence: [Evidence(type: .stringReference, address: section.address + UInt64(offset), details: "String '\(searchStr)' found")],
                        description: "\(algorithm.rawValue) string reference detected"
                    ))
                }
            }

            // Check for Base64 alphabet
            if sectionString.contains(base64Alphabet) {
                findings.append(CryptoFinding(
                    algorithm: .base64,
                    address: section.address,
                    confidence: 0.8,
                    evidence: [Evidence(type: .stringReference, address: section.address, details: "Base64 alphabet found")],
                    description: "Base64 encoding alphabet detected"
                ))
            }
        }

        return findings
    }

    /// Scan code for algorithmic patterns
    private func scanCodePatterns(in section: Section, binary: BinaryFile) -> [CryptoFinding] {
        var findings: [CryptoFinding] = []

        // Look for rotation operations (common in crypto)
        // ROL, ROR, or (x << n) | (x >> (32-n))

        // Look for XOR-heavy code (common in stream ciphers)

        // Look for 64-round loops (common in SHA-256, etc.)

        return findings
    }

    // MARK: - Pattern Matching Helpers

    private func findPattern(_ pattern: [UInt8], in data: Data) -> Int? {
        guard pattern.count <= data.count else { return nil }

        for i in 0...(data.count - pattern.count) {
            var match = true
            for (j, byte) in pattern.enumerated() {
                if data[data.startIndex + i + j] != byte {
                    match = false
                    break
                }
            }
            if match {
                return i
            }
        }
        return nil
    }

    private func findUInt32Pattern(_ pattern: [UInt32], in data: Data) -> Int? {
        let bytePattern = pattern.flatMap { value -> [UInt8] in
            // Little endian
            return [
                UInt8(value & 0xFF),
                UInt8((value >> 8) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >> 24) & 0xFF)
            ]
        }
        return findPattern(bytePattern, in: data)
    }

    private func findUInt64Pattern(_ pattern: [UInt64], in data: Data) -> Int? {
        let bytePattern = pattern.flatMap { value -> [UInt8] in
            // Little endian
            return (0..<8).map { UInt8((value >> ($0 * 8)) & 0xFF) }
        }
        return findPattern(bytePattern, in: data)
    }

    // MARK: - Result Processing

    private func consolidateFindings(_ findings: [CryptoFinding]) -> [CryptoFinding] {
        // Group findings by algorithm and address range
        var consolidated: [CryptoFinding] = []
        var seen: Set<String> = []

        for finding in findings.sorted(by: { $0.confidence > $1.confidence }) {
            let key = "\(finding.algorithm)-\(finding.address / 0x1000)"  // Group by 4KB page
            if !seen.contains(key) {
                seen.insert(key)
                consolidated.append(finding)
            }
        }

        return consolidated
    }
}

// MARK: - Vulnerability Pattern Detection

/// Detects potential cryptographic vulnerabilities
class CryptoVulnerabilityDetector {

    struct Vulnerability {
        let type: VulnerabilityType
        let severity: Severity
        let address: UInt64
        let description: String
        let recommendation: String

        enum Severity: String {
            case critical = "Critical"
            case high = "High"
            case medium = "Medium"
            case low = "Low"
            case info = "Info"
        }
    }

    enum VulnerabilityType: String {
        case weakAlgorithm = "Weak Algorithm"
        case hardcodedKey = "Hardcoded Key"
        case hardcodedIV = "Hardcoded IV"
        case ecbMode = "ECB Mode"
        case staticSalt = "Static Salt"
        case weakRandom = "Weak PRNG"
        case shortKey = "Short Key"
        case noPadding = "No Padding"
        case timingLeak = "Timing Leak"
    }

    /// Weak algorithms to flag
    private let weakAlgorithms: [(AdvancedCryptoDetector.CryptoAlgorithm, Vulnerability.Severity, String)] = [
        (.md5, .high, "MD5 is cryptographically broken. Use SHA-256 or better."),
        (.sha1, .medium, "SHA-1 is deprecated. Use SHA-256 or better."),
        (.des, .critical, "DES has a 56-bit key and is considered broken."),
        (.rc4, .high, "RC4 has known biases. Use AES or ChaCha20."),
        (.blowfish, .low, "Blowfish has a small block size. Consider AES."),
    ]

    /// Analyze crypto findings for vulnerabilities
    func analyze(findings: [AdvancedCryptoDetector.CryptoFinding], binary: BinaryFile) -> [Vulnerability] {
        var vulnerabilities: [Vulnerability] = []

        // Check for weak algorithms
        for finding in findings {
            if let weakInfo = weakAlgorithms.first(where: { $0.0 == finding.algorithm }) {
                vulnerabilities.append(Vulnerability(
                    type: .weakAlgorithm,
                    severity: weakInfo.1,
                    address: finding.address,
                    description: "Use of \(finding.algorithm.rawValue) detected",
                    recommendation: weakInfo.2
                ))
            }
        }

        // Look for hardcoded keys (high entropy data near crypto constants)
        for finding in findings {
            if finding.algorithm == .aes {
                // Check for 16/24/32 byte sequences nearby that could be keys
                vulnerabilities.append(contentsOf: checkForHardcodedKeys(near: finding.address, binary: binary))
            }
        }

        // Look for ECB mode indicators
        for section in binary.sections where section.containsCode {
            // ECB mode often has no IV parameter in crypto calls
            vulnerabilities.append(contentsOf: checkForECBMode(in: section))
        }

        return vulnerabilities
    }

    private func checkForHardcodedKeys(near address: UInt64, binary: BinaryFile) -> [Vulnerability] {
        // This would analyze entropy of nearby data
        // High entropy 16/24/32 byte sequences could be keys
        return []
    }

    private func checkForECBMode(in section: Section) -> [Vulnerability] {
        // Look for crypto operations without IV setup
        return []
    }
}

// MARK: - Crypto Function Identifier

/// Identifies crypto library functions
class CryptoFunctionIdentifier {

    struct CryptoFunction {
        let name: String
        let library: String
        let algorithm: AdvancedCryptoDetector.CryptoAlgorithm
        let operation: Operation
        let address: UInt64

        enum Operation {
            case encrypt
            case decrypt
            case hash
            case sign
            case verify
            case keyGeneration
            case keyDerivation
            case random
        }
    }

    /// Known crypto function patterns
    private let knownFunctions: [(namePattern: String, library: String, algorithm: AdvancedCryptoDetector.CryptoAlgorithm, operation: CryptoFunction.Operation)] = [
        // OpenSSL
        ("EVP_EncryptInit", "OpenSSL", .aes, .encrypt),
        ("EVP_DecryptInit", "OpenSSL", .aes, .decrypt),
        ("EVP_DigestInit", "OpenSSL", .sha256, .hash),
        ("EVP_MD5", "OpenSSL", .md5, .hash),
        ("EVP_sha256", "OpenSSL", .sha256, .hash),
        ("EVP_sha512", "OpenSSL", .sha512, .hash),
        ("AES_encrypt", "OpenSSL", .aes, .encrypt),
        ("AES_decrypt", "OpenSSL", .aes, .decrypt),
        ("RSA_public_encrypt", "OpenSSL", .rsa, .encrypt),
        ("RSA_private_decrypt", "OpenSSL", .rsa, .decrypt),
        ("RSA_sign", "OpenSSL", .rsa, .sign),
        ("RSA_verify", "OpenSSL", .rsa, .verify),

        // CommonCrypto (Apple)
        ("CCCrypt", "CommonCrypto", .aes, .encrypt),
        ("CCHmac", "CommonCrypto", .sha256, .hash),
        ("CC_MD5", "CommonCrypto", .md5, .hash),
        ("CC_SHA1", "CommonCrypto", .sha1, .hash),
        ("CC_SHA256", "CommonCrypto", .sha256, .hash),
        ("CC_SHA512", "CommonCrypto", .sha512, .hash),
        ("CCKeyDerivationPBKDF", "CommonCrypto", .pbkdf2, .keyDerivation),
        ("SecRandomCopyBytes", "Security", .unknown, .random),

        // libsodium
        ("crypto_secretbox", "libsodium", .chacha20, .encrypt),
        ("crypto_secretbox_open", "libsodium", .chacha20, .decrypt),
        ("crypto_box", "libsodium", .curve25519, .encrypt),
        ("crypto_sign", "libsodium", .ed25519, .sign),
        ("crypto_hash_sha256", "libsodium", .sha256, .hash),
        ("crypto_hash_sha512", "libsodium", .sha512, .hash),
        ("crypto_pwhash", "libsodium", .argon2, .keyDerivation),

        // Crypto++
        ("CryptoPP::AES", "Crypto++", .aes, .encrypt),
        ("CryptoPP::SHA256", "Crypto++", .sha256, .hash),
        ("CryptoPP::RSA", "Crypto++", .rsa, .encrypt),
    ]

    /// Identify crypto functions in binary
    func identify(binary: BinaryFile) -> [CryptoFunction] {
        var functions: [CryptoFunction] = []

        for symbol in binary.symbols {
            for pattern in knownFunctions {
                if symbol.name.contains(pattern.namePattern) {
                    functions.append(CryptoFunction(
                        name: symbol.name,
                        library: pattern.library,
                        algorithm: pattern.algorithm,
                        operation: pattern.operation,
                        address: symbol.address
                    ))
                    break
                }
            }
        }

        return functions
    }
}
