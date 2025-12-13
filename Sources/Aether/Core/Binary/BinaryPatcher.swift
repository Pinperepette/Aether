import Foundation

// MARK: - Binary Patcher

/// Allows patching and modifying binary files
class BinaryPatcher {

    // MARK: - Patch Types

    struct Patch: Identifiable, Codable {
        let id: UUID
        let address: UInt64
        let originalBytes: [UInt8]
        let newBytes: [UInt8]
        let description: String
        let timestamp: Date
        var isApplied: Bool

        init(address: UInt64, originalBytes: [UInt8], newBytes: [UInt8], description: String) {
            self.id = UUID()
            self.address = address
            self.originalBytes = originalBytes
            self.newBytes = newBytes
            self.description = description
            self.timestamp = Date()
            self.isApplied = false
        }
    }

    enum PatchError: Error, LocalizedError {
        case addressOutOfRange(UInt64)
        case sizeMismatch
        case verificationFailed
        case writeError(String)
        case alreadyApplied
        case notApplied

        var errorDescription: String? {
            switch self {
            case .addressOutOfRange(let addr):
                return "Address 0x\(String(format: "%llX", addr)) is out of range"
            case .sizeMismatch:
                return "Patch size does not match original"
            case .verificationFailed:
                return "Patch verification failed - bytes don't match expected"
            case .writeError(let msg):
                return "Write error: \(msg)"
            case .alreadyApplied:
                return "Patch is already applied"
            case .notApplied:
                return "Patch is not applied"
            }
        }
    }

    // MARK: - Properties

    private var patches: [Patch] = []
    private var modifiedData: Data?
    private let binary: BinaryFile

    init(binary: BinaryFile) {
        self.binary = binary
        self.modifiedData = binary.data
    }

    // MARK: - Patch Management

    /// Create a patch to modify bytes at address
    func createPatch(at address: UInt64, newBytes: [UInt8], description: String) throws -> Patch {
        guard let section = binary.section(containing: address) else {
            throw PatchError.addressOutOfRange(address)
        }

        let offset = Int(address - section.address)
        guard offset >= 0, offset + newBytes.count <= section.data.count else {
            throw PatchError.addressOutOfRange(address)
        }

        // Read original bytes
        var originalBytes: [UInt8] = []
        for i in 0..<newBytes.count {
            originalBytes.append(section.data[section.data.startIndex + offset + i])
        }

        let patch = Patch(
            address: address,
            originalBytes: originalBytes,
            newBytes: newBytes,
            description: description
        )

        patches.append(patch)
        return patch
    }

    /// Create a NOP patch (replace instruction with NOPs)
    func createNOPPatch(at address: UInt64, size: Int, description: String) throws -> Patch {
        let nopByte: UInt8

        switch binary.architecture {
        case .x86_64, .i386:
            nopByte = 0x90
        case .arm64, .arm64e:
            // ARM64 NOP is 4 bytes: 0x1F, 0x20, 0x03, 0xD5
            return try createPatch(
                at: address,
                newBytes: Array(repeating: [0x1F, 0x20, 0x03, 0xD5], count: size / 4).flatMap { $0 },
                description: description
            )
        case .armv7:
            // ARM Thumb NOP: 0x00, 0xBF
            return try createPatch(
                at: address,
                newBytes: Array(repeating: [0x00, 0xBF], count: size / 2).flatMap { $0 },
                description: description
            )
        default:
            nopByte = 0x90
        }

        return try createPatch(
            at: address,
            newBytes: Array(repeating: nopByte, count: size),
            description: description
        )
    }

    /// Create a jump patch (redirect execution)
    func createJumpPatch(from source: UInt64, to target: UInt64, description: String) throws -> Patch {
        var bytes: [UInt8] = []

        switch binary.architecture {
        case .x86_64:
            // JMP rel32
            let offset = Int64(target) - Int64(source) - 5
            if offset >= Int32.min && offset <= Int32.max {
                bytes = [0xE9]  // JMP
                let rel32 = Int32(offset)
                bytes.append(UInt8(truncatingIfNeeded: rel32))
                bytes.append(UInt8(truncatingIfNeeded: rel32 >> 8))
                bytes.append(UInt8(truncatingIfNeeded: rel32 >> 16))
                bytes.append(UInt8(truncatingIfNeeded: rel32 >> 24))
            } else {
                // Need absolute jump for far targets
                // MOV RAX, imm64; JMP RAX
                bytes = [0x48, 0xB8]  // MOV RAX, imm64
                for i in 0..<8 {
                    bytes.append(UInt8(truncatingIfNeeded: target >> (i * 8)))
                }
                bytes += [0xFF, 0xE0]  // JMP RAX
            }

        case .arm64, .arm64e:
            // B imm26
            let offset = (Int64(target) - Int64(source)) / 4
            if offset >= -0x2000000 && offset < 0x2000000 {
                let imm26 = UInt32(bitPattern: Int32(offset)) & 0x03FFFFFF
                let insn = 0x14000000 | imm26
                bytes = [
                    UInt8(truncatingIfNeeded: insn),
                    UInt8(truncatingIfNeeded: insn >> 8),
                    UInt8(truncatingIfNeeded: insn >> 16),
                    UInt8(truncatingIfNeeded: insn >> 24)
                ]
            }

        default:
            throw PatchError.writeError("Jump patch not supported for \(binary.architecture)")
        }

        return try createPatch(at: source, newBytes: bytes, description: description)
    }

    /// Apply a patch
    func applyPatch(_ patch: Patch) throws {
        guard var index = patches.firstIndex(where: { $0.id == patch.id }) else {
            throw PatchError.notApplied
        }

        guard !patches[index].isApplied else {
            throw PatchError.alreadyApplied
        }

        // Verify original bytes match
        guard var data = modifiedData else {
            throw PatchError.writeError("No data available")
        }

        let fileOffset = try getFileOffset(for: patch.address)

        for (i, expected) in patch.originalBytes.enumerated() {
            let actual = data[data.startIndex + fileOffset + i]
            if actual != expected {
                throw PatchError.verificationFailed
            }
        }

        // Apply patch
        for (i, newByte) in patch.newBytes.enumerated() {
            data[data.startIndex + fileOffset + i] = newByte
        }

        modifiedData = data
        patches[index].isApplied = true
    }

    /// Revert a patch
    func revertPatch(_ patch: Patch) throws {
        guard var index = patches.firstIndex(where: { $0.id == patch.id }) else {
            throw PatchError.notApplied
        }

        guard patches[index].isApplied else {
            throw PatchError.notApplied
        }

        guard var data = modifiedData else {
            throw PatchError.writeError("No data available")
        }

        let fileOffset = try getFileOffset(for: patch.address)

        // Restore original bytes
        for (i, originalByte) in patch.originalBytes.enumerated() {
            data[data.startIndex + fileOffset + i] = originalByte
        }

        modifiedData = data
        patches[index].isApplied = false
    }

    /// Apply all patches
    func applyAllPatches() throws {
        for patch in patches where !patch.isApplied {
            try applyPatch(patch)
        }
    }

    /// Revert all patches
    func revertAllPatches() throws {
        for patch in patches.reversed() where patch.isApplied {
            try revertPatch(patch)
        }
    }

    /// Save patched binary
    func save(to url: URL) throws {
        guard let data = modifiedData else {
            throw PatchError.writeError("No data to save")
        }

        try data.write(to: url)
    }

    /// Get all patches
    func getAllPatches() -> [Patch] {
        return patches
    }

    // MARK: - Helpers

    private func getFileOffset(for address: UInt64) throws -> Int {
        guard let section = binary.section(containing: address) else {
            throw PatchError.addressOutOfRange(address)
        }

        let sectionOffset = Int(address - section.address)
        let fileOffset = Int(section.offset) + sectionOffset

        return fileOffset
    }
}

// MARK: - Binary Differ

/// Compare two binary files and find differences
class BinaryDiffer {

    struct Difference: Identifiable {
        let id = UUID()
        let address: UInt64
        let offset: Int
        let oldBytes: [UInt8]
        let newBytes: [UInt8]
        let type: DifferenceType

        enum DifferenceType {
            case modified
            case added
            case removed
        }
    }

    struct DiffResult {
        let differences: [Difference]
        let addedFunctions: [Function]
        let removedFunctions: [Function]
        let modifiedFunctions: [Function]
        let statistics: Statistics

        struct Statistics {
            let totalBytesChanged: Int
            let functionsAdded: Int
            let functionsRemoved: Int
            let functionsModified: Int
            let sectionsChanged: [String]
        }
    }

    /// Compare two binaries
    func diff(old: BinaryFile, new: BinaryFile) -> DiffResult {
        var differences: [Difference] = []
        var sectionsChanged: Set<String> = []

        // Compare sections
        for oldSection in old.sections {
            if let newSection = new.sections.first(where: { $0.name == oldSection.name }) {
                let sectionDiffs = diffSections(old: oldSection, new: newSection)
                if !sectionDiffs.isEmpty {
                    differences.append(contentsOf: sectionDiffs)
                    sectionsChanged.insert(oldSection.name)
                }
            } else {
                // Section removed
                let diff = Difference(
                    address: oldSection.address,
                    offset: Int(oldSection.offset),
                    oldBytes: Array(oldSection.data),
                    newBytes: [],
                    type: .removed
                )
                differences.append(diff)
                sectionsChanged.insert(oldSection.name)
            }
        }

        // Find added sections
        for newSection in new.sections {
            if !old.sections.contains(where: { $0.name == newSection.name }) {
                let diff = Difference(
                    address: newSection.address,
                    offset: Int(newSection.offset),
                    oldBytes: [],
                    newBytes: Array(newSection.data),
                    type: .added
                )
                differences.append(diff)
                sectionsChanged.insert(newSection.name)
            }
        }

        // Compare functions (would need both binaries analyzed)
        let addedFunctions: [Function] = []
        let removedFunctions: [Function] = []
        let modifiedFunctions: [Function] = []

        let stats = DiffResult.Statistics(
            totalBytesChanged: differences.reduce(0) { $0 + max($1.oldBytes.count, $1.newBytes.count) },
            functionsAdded: addedFunctions.count,
            functionsRemoved: removedFunctions.count,
            functionsModified: modifiedFunctions.count,
            sectionsChanged: Array(sectionsChanged)
        )

        return DiffResult(
            differences: differences,
            addedFunctions: addedFunctions,
            removedFunctions: removedFunctions,
            modifiedFunctions: modifiedFunctions,
            statistics: stats
        )
    }

    private func diffSections(old: Section, new: Section) -> [Difference] {
        var differences: [Difference] = []

        let minSize = min(old.data.count, new.data.count)
        var diffStart: Int? = nil
        var oldBytes: [UInt8] = []
        var newBytes: [UInt8] = []

        for i in 0..<minSize {
            let oldByte = old.data[old.data.startIndex + i]
            let newByte = new.data[new.data.startIndex + i]

            if oldByte != newByte {
                if diffStart == nil {
                    diffStart = i
                }
                oldBytes.append(oldByte)
                newBytes.append(newByte)
            } else if diffStart != nil {
                // End of difference run
                differences.append(Difference(
                    address: old.address + UInt64(diffStart!),
                    offset: Int(old.offset) + diffStart!,
                    oldBytes: oldBytes,
                    newBytes: newBytes,
                    type: .modified
                ))
                diffStart = nil
                oldBytes = []
                newBytes = []
            }
        }

        // Handle trailing difference
        if diffStart != nil {
            differences.append(Difference(
                address: old.address + UInt64(diffStart!),
                offset: Int(old.offset) + diffStart!,
                oldBytes: oldBytes,
                newBytes: newBytes,
                type: .modified
            ))
        }

        // Handle size difference
        if old.data.count < new.data.count {
            differences.append(Difference(
                address: old.address + UInt64(old.data.count),
                offset: Int(old.offset) + old.data.count,
                oldBytes: [],
                newBytes: Array(new.data[minSize...]),
                type: .added
            ))
        } else if old.data.count > new.data.count {
            differences.append(Difference(
                address: old.address + UInt64(new.data.count),
                offset: Int(old.offset) + new.data.count,
                oldBytes: Array(old.data[minSize...]),
                newBytes: [],
                type: .removed
            ))
        }

        return differences
    }

    /// Generate a unified diff view
    func generateUnifiedDiff(result: DiffResult, contextLines: Int = 3) -> String {
        var output = ""

        for diff in result.differences {
            output += String(format: "@@ 0x%llX @@\n", diff.address)

            switch diff.type {
            case .modified:
                output += "- " + diff.oldBytes.map { String(format: "%02X", $0) }.joined(separator: " ") + "\n"
                output += "+ " + diff.newBytes.map { String(format: "%02X", $0) }.joined(separator: " ") + "\n"
            case .added:
                output += "+ " + diff.newBytes.map { String(format: "%02X", $0) }.joined(separator: " ") + "\n"
            case .removed:
                output += "- " + diff.oldBytes.map { String(format: "%02X", $0) }.joined(separator: " ") + "\n"
            }
        }

        return output
    }
}

// MARK: - IPS Patch Format Support

/// IPS (International Patching System) format support
class IPSPatcher {

    private let IPS_MAGIC = Data([0x50, 0x41, 0x54, 0x43, 0x48])  // "PATCH"
    private let IPS_EOF = Data([0x45, 0x4F, 0x46])  // "EOF"

    struct IPSRecord {
        let offset: Int
        let data: Data
        let isRLE: Bool
        let rleCount: Int?
    }

    /// Create IPS patch from differences
    func createPatch(from differences: [BinaryDiffer.Difference]) -> Data {
        var patch = IPS_MAGIC

        for diff in differences {
            // 3-byte offset (big-endian)
            let offset = min(diff.offset, 0xFFFFFF)
            patch.append(UInt8((offset >> 16) & 0xFF))
            patch.append(UInt8((offset >> 8) & 0xFF))
            patch.append(UInt8(offset & 0xFF))

            // 2-byte size (big-endian)
            let size = min(diff.newBytes.count, 0xFFFF)
            patch.append(UInt8((size >> 8) & 0xFF))
            patch.append(UInt8(size & 0xFF))

            // Data
            patch.append(contentsOf: diff.newBytes.prefix(size))
        }

        patch.append(IPS_EOF)
        return patch
    }

    /// Apply IPS patch to data
    func applyPatch(_ patch: Data, to data: inout Data) throws {
        guard patch.prefix(5) == IPS_MAGIC else {
            throw BinaryPatcher.PatchError.verificationFailed
        }

        var offset = 5

        while offset + 3 <= patch.count {
            // Check for EOF
            if patch[offset..<(offset + 3)] == IPS_EOF {
                break
            }

            // Read offset (3 bytes, big-endian)
            let recordOffset = Int(patch[offset]) << 16 | Int(patch[offset + 1]) << 8 | Int(patch[offset + 2])
            offset += 3

            // Read size (2 bytes, big-endian)
            guard offset + 2 <= patch.count else { break }
            let size = Int(patch[offset]) << 8 | Int(patch[offset + 1])
            offset += 2

            if size == 0 {
                // RLE record
                guard offset + 3 <= patch.count else { break }
                let rleSize = Int(patch[offset]) << 8 | Int(patch[offset + 1])
                let rleByte = patch[offset + 2]
                offset += 3

                // Apply RLE
                for i in 0..<rleSize {
                    if recordOffset + i < data.count {
                        data[recordOffset + i] = rleByte
                    }
                }
            } else {
                // Normal record
                guard offset + size <= patch.count else { break }
                let recordData = patch[offset..<(offset + size)]
                offset += size

                // Apply data
                for (i, byte) in recordData.enumerated() {
                    if recordOffset + i < data.count {
                        data[recordOffset + i] = byte
                    }
                }
            }
        }
    }
}
