import Foundation

/// Protocol for binary file loaders
protocol BinaryLoaderProtocol {
    func canLoad(data: Data) -> Bool
    func load(from url: URL, data: Data) async throws -> BinaryFile
}

/// Errors that can occur during binary loading
enum BinaryLoaderError: Error, LocalizedError {
    case fileNotFound(URL)
    case unsupportedFormat
    case invalidHeader
    case corruptedFile(String)
    case unsupportedArchitecture(String)
    case readError(String)

    var errorDescription: String? {
        switch self {
        case .fileNotFound(let url):
            return "File not found: \(url.path)"
        case .unsupportedFormat:
            return "Unsupported binary format"
        case .invalidHeader:
            return "Invalid file header"
        case .corruptedFile(let reason):
            return "Corrupted file: \(reason)"
        case .unsupportedArchitecture(let arch):
            return "Unsupported architecture: \(arch)"
        case .readError(let reason):
            return "Read error: \(reason)"
        }
    }
}

func debugLog(_ msg: String) {
    fputs(">>> [Loader] \(msg)\n", stderr)
    fflush(stderr)
}

/// Main binary loader that delegates to format-specific loaders
class BinaryLoader {
    private let loaders: [BinaryLoaderProtocol]

    init() {
        self.loaders = [
            JARLoader(),  // Check JAR/class first (CAFEBABE conflicts with fat binary)
            MachOLoader(),
            ELFLoader(),
            PELoader()
        ]
    }

    /// Load a binary file from URL
    func load(from url: URL) async throws -> BinaryFile {
        debugLog("load() called for \(url.lastPathComponent)")

        guard FileManager.default.fileExists(atPath: url.path) else {
            throw BinaryLoaderError.fileNotFound(url)
        }

        debugLog("Reading file data...")
        let data = try Data(contentsOf: url)
        debugLog("File size: \(data.count) bytes")

        // Find appropriate loader
        for loader in loaders {
            if loader.canLoad(data: data) {
                debugLog("Using loader: \(type(of: loader))")
                let result = try await loader.load(from: url, data: data)
                debugLog("Loader finished!")
                return result
            }
        }

        throw BinaryLoaderError.unsupportedFormat
    }

    /// Detect binary format without loading
    func detectFormat(from url: URL) throws -> BinaryFormat {
        let data = try Data(contentsOf: url, options: .mappedIfSafe)
        return BinaryFormat.detect(from: data)
    }
}

// MARK: - Data Extensions for Binary Reading

extension Data {
    func readUInt8(at offset: Int) -> UInt8? {
        guard offset >= 0, offset < count else { return nil }
        return self[startIndex + offset]
    }

    func readUInt16LE(at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= count else { return nil }
        let b0 = UInt16(self[startIndex + offset])
        let b1 = UInt16(self[startIndex + offset + 1])
        return b0 | (b1 << 8)
    }

    func readUInt16BE(at offset: Int) -> UInt16? {
        guard offset >= 0, offset + 2 <= count else { return nil }
        let b0 = UInt16(self[startIndex + offset])
        let b1 = UInt16(self[startIndex + offset + 1])
        return (b0 << 8) | b1
    }

    func readUInt32LE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        let b0 = UInt32(self[startIndex + offset])
        let b1 = UInt32(self[startIndex + offset + 1])
        let b2 = UInt32(self[startIndex + offset + 2])
        let b3 = UInt32(self[startIndex + offset + 3])
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }

    func readUInt32BE(at offset: Int) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        let b0 = UInt32(self[startIndex + offset])
        let b1 = UInt32(self[startIndex + offset + 1])
        let b2 = UInt32(self[startIndex + offset + 2])
        let b3 = UInt32(self[startIndex + offset + 3])
        return (b0 << 24) | (b1 << 16) | (b2 << 8) | b3
    }

    func readUInt64LE(at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= count else { return nil }
        var result: UInt64 = 0
        for i in 0..<8 {
            result |= UInt64(self[startIndex + offset + i]) << (i * 8)
        }
        return result
    }

    func readUInt64BE(at offset: Int) -> UInt64? {
        guard offset >= 0, offset + 8 <= count else { return nil }
        var result: UInt64 = 0
        for i in 0..<8 {
            result |= UInt64(self[startIndex + offset + i]) << ((7 - i) * 8)
        }
        return result
    }

    func readInt32LE(at offset: Int) -> Int32? {
        guard let unsigned = readUInt32LE(at: offset) else { return nil }
        return Int32(bitPattern: unsigned)
    }

    func readInt32BE(at offset: Int) -> Int32? {
        guard let unsigned = readUInt32BE(at: offset) else { return nil }
        return Int32(bitPattern: unsigned)
    }

    func readInt64BE(at offset: Int) -> Int64? {
        guard let unsigned = readUInt64BE(at: offset) else { return nil }
        return Int64(bitPattern: unsigned)
    }

    func readCString(at offset: Int, maxLength: Int = 256) -> String? {
        guard offset >= 0, offset < count else { return nil }
        var bytes: [UInt8] = []
        var currentOffset = offset

        while currentOffset < count && bytes.count < maxLength {
            let byte = self[startIndex + currentOffset]
            if byte == 0 { break }
            bytes.append(byte)
            currentOffset += 1
        }

        return String(bytes: bytes, encoding: .utf8)
    }

    func subdata(offset: Int, count: Int) -> Data? {
        guard offset >= 0, offset + count <= self.count else { return nil }
        return self[startIndex + offset ..< startIndex + offset + count]
    }
}
