import Foundation

/// Represents a saved disassembler project
struct Project: Codable, Identifiable {
    let id: UUID
    var name: String
    var binaryPath: String
    var createdAt: Date
    var modifiedAt: Date

    // User annotations
    var comments: [UInt64: String]
    var renamedFunctions: [UInt64: String]
    var renamedSymbols: [UInt64: String]
    var bookmarks: [Bookmark]

    // Analysis state
    var analyzedSections: Set<String>
    var lastAnalysisDate: Date?

    init(name: String, binaryPath: String) {
        self.id = UUID()
        self.name = name
        self.binaryPath = binaryPath
        self.createdAt = Date()
        self.modifiedAt = Date()
        self.comments = [:]
        self.renamedFunctions = [:]
        self.renamedSymbols = [:]
        self.bookmarks = []
        self.analyzedSections = []
        self.lastAnalysisDate = nil
    }
}

/// A user bookmark
struct Bookmark: Codable, Identifiable, Hashable {
    let id: UUID
    let address: UInt64
    var name: String
    var description: String
    let createdAt: Date

    init(address: UInt64, name: String, description: String = "") {
        self.id = UUID()
        self.address = address
        self.name = name
        self.description = description
        self.createdAt = Date()
    }
}

/// Project file manager
class ProjectManager {
    static let shared = ProjectManager()

    private let fileManager = FileManager.default
    private var projectsDirectory: URL {
        let appSupport = fileManager.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        return appSupport.appendingPathComponent("Aether/Projects", isDirectory: true)
    }

    private init() {
        // Create projects directory if needed
        try? fileManager.createDirectory(at: projectsDirectory, withIntermediateDirectories: true)
    }

    // MARK: - Save/Load

    func save(_ project: Project) throws {
        var projectToSave = project
        projectToSave.modifiedAt = Date()

        let encoder = JSONEncoder()
        encoder.outputFormatting = .prettyPrinted
        encoder.dateEncodingStrategy = .iso8601

        let data = try encoder.encode(projectToSave)
        let fileURL = projectsDirectory.appendingPathComponent("\(project.id.uuidString).json")

        try data.write(to: fileURL)
    }

    func load(id: UUID) throws -> Project {
        let fileURL = projectsDirectory.appendingPathComponent("\(id.uuidString).json")
        let data = try Data(contentsOf: fileURL)

        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        return try decoder.decode(Project.self, from: data)
    }

    func delete(id: UUID) throws {
        let fileURL = projectsDirectory.appendingPathComponent("\(id.uuidString).json")
        try fileManager.removeItem(at: fileURL)
    }

    // MARK: - List Projects

    func listProjects() -> [Project] {
        do {
            let files = try fileManager.contentsOfDirectory(at: projectsDirectory, includingPropertiesForKeys: nil)
            let jsonFiles = files.filter { $0.pathExtension == "json" }

            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601

            return jsonFiles.compactMap { url -> Project? in
                guard let data = try? Data(contentsOf: url),
                      let project = try? decoder.decode(Project.self, from: data) else {
                    return nil
                }
                return project
            }.sorted { $0.modifiedAt > $1.modifiedAt }
        } catch {
            return []
        }
    }

    // MARK: - Recent Projects

    private let recentProjectsKey = "RecentProjects"
    private let maxRecentProjects = 10

    func addToRecent(_ projectId: UUID) {
        var recent = UserDefaults.standard.stringArray(forKey: recentProjectsKey) ?? []
        recent.removeAll { $0 == projectId.uuidString }
        recent.insert(projectId.uuidString, at: 0)
        recent = Array(recent.prefix(maxRecentProjects))
        UserDefaults.standard.set(recent, forKey: recentProjectsKey)
    }

    func recentProjects() -> [Project] {
        let recentIds = UserDefaults.standard.stringArray(forKey: recentProjectsKey) ?? []
        return recentIds.compactMap { idString -> Project? in
            guard let id = UUID(uuidString: idString),
                  let project = try? load(id: id) else {
                return nil
            }
            return project
        }
    }
}

// MARK: - Export Service

class ExportService {
    enum ExportFormat {
        case text
        case html
        case json
    }

    func exportDisassembly(
        instructions: [Instruction],
        format: ExportFormat,
        to url: URL
    ) throws {
        let content: String

        switch format {
        case .text:
            content = exportAsText(instructions)
        case .html:
            content = exportAsHTML(instructions)
        case .json:
            content = try exportAsJSON(instructions)
        }

        try content.write(to: url, atomically: true, encoding: .utf8)
    }

    private func exportAsText(_ instructions: [Instruction]) -> String {
        var output = ""

        for insn in instructions {
            let line = String(format: "%08llX  %-20s  %s %s",
                            insn.address,
                            insn.hexString,
                            insn.mnemonic,
                            insn.operands)
            output += line + "\n"
        }

        return output
    }

    private func exportAsHTML(_ instructions: [Instruction]) -> String {
        var output = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>Disassembly Export</title>
            <style>
                body {
                    font-family: 'SF Mono', 'Menlo', monospace;
                    background: #1E1E2E;
                    color: #CDD6F4;
                    padding: 20px;
                }
                .line {
                    white-space: pre;
                    line-height: 1.5;
                }
                .address { color: #A6E3A1; }
                .bytes { color: #6C7086; }
                .mnemonic { color: #F38BA8; }
                .operands { color: #89B4FA; }
            </style>
        </head>
        <body>
        """

        for insn in instructions {
            output += """
            <div class="line">
                <span class="address">\(String(format: "%08llX", insn.address))</span>
                <span class="bytes">\(insn.hexString.padding(toLength: 24, withPad: " ", startingAt: 0))</span>
                <span class="mnemonic">\(insn.mnemonic.padding(toLength: 8, withPad: " ", startingAt: 0))</span>
                <span class="operands">\(insn.operands)</span>
            </div>
            """
        }

        output += """
        </body>
        </html>
        """

        return output
    }

    private func exportAsJSON(_ instructions: [Instruction]) throws -> String {
        struct ExportInstruction: Encodable {
            let address: String
            let bytes: String
            let mnemonic: String
            let operands: String
            let type: String
        }

        let exportData = instructions.map { insn in
            ExportInstruction(
                address: String(format: "0x%llX", insn.address),
                bytes: insn.hexString,
                mnemonic: insn.mnemonic,
                operands: insn.operands,
                type: insn.type.rawValue
            )
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(exportData)

        return String(data: data, encoding: .utf8) ?? "[]"
    }
}
