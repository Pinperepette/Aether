import Foundation
import Combine

// MARK: - Plugin Protocol

/// Base protocol for all plugins
protocol DisassemblerPlugin: AnyObject {
    /// Unique identifier for the plugin
    var identifier: String { get }

    /// Display name
    var name: String { get }

    /// Plugin version
    var version: String { get }

    /// Plugin description
    var description: String { get }

    /// Plugin author
    var author: String { get }

    /// Initialize the plugin
    func initialize(context: PluginContext) async throws

    /// Cleanup when plugin is unloaded
    func cleanup() async
}

/// Context provided to plugins for interacting with the disassembler
@MainActor
class PluginContext: ObservableObject {
    weak var appState: AppState?

    // Events plugins can subscribe to
    let onFileLoaded = PassthroughSubject<BinaryFile, Never>()
    let onFunctionSelected = PassthroughSubject<Function, Never>()
    let onAddressNavigated = PassthroughSubject<UInt64, Never>()
    let onAnalysisComplete = PassthroughSubject<Void, Never>()

    init(appState: AppState) {
        self.appState = appState
    }

    // MARK: - API for Plugins

    /// Get current binary
    var currentBinary: BinaryFile? {
        appState?.currentFile
    }

    /// Get all functions
    var functions: [Function] {
        appState?.functions ?? []
    }

    /// Get all symbols
    var symbols: [Symbol] {
        appState?.symbols ?? []
    }

    /// Navigate to address
    func goToAddress(_ address: UInt64) {
        appState?.goToAddress(address)
    }

    /// Add a comment at address
    func addComment(_ comment: String, at address: UInt64) {
        // Store comment in project
    }

    /// Rename function
    func renameFunction(at address: UInt64, to name: String) {
        if let index = appState?.functions.firstIndex(where: { $0.startAddress == address }) {
            appState?.functions[index].name = name
        }
    }

    /// Log message to console
    func log(_ message: String) {
        print("[Plugin] \(message)")
    }

    /// Show notification to user
    func showNotification(_ message: String, type: NotificationType = .info) {
        // Integrate with UI notification system
    }

    enum NotificationType {
        case info
        case warning
        case error
        case success
    }
}

// MARK: - Analysis Plugin

/// Plugin that performs custom analysis
protocol AnalysisPlugin: DisassemblerPlugin {
    /// Run analysis on the binary
    func analyze(binary: BinaryFile, context: PluginContext) async throws -> AnalysisResult
}

struct AnalysisResult {
    var findings: [AnalysisFinding]
    var metadata: [String: Any]
}

struct AnalysisFinding {
    let address: UInt64
    let type: FindingType
    let message: String
    let severity: Severity

    enum FindingType {
        case vulnerability
        case suspiciousCode
        case cryptoUsage
        case networkActivity
        case antiDebug
        case obfuscation
        case custom(String)
    }

    enum Severity {
        case info
        case low
        case medium
        case high
        case critical
    }
}

// MARK: - Loader Plugin

/// Plugin that adds support for new file formats
protocol LoaderPlugin: DisassemblerPlugin {
    /// Check if this plugin can load the given file
    func canLoad(data: Data) -> Bool

    /// Load the binary file
    func load(from url: URL, data: Data) async throws -> BinaryFile
}

// MARK: - Processor Plugin

/// Plugin that adds support for new CPU architectures
protocol ProcessorPlugin: DisassemblerPlugin {
    /// Supported architecture identifier
    var architectureId: String { get }

    /// Disassemble data
    func disassemble(data: Data, address: UInt64) async -> [Instruction]

    /// Get register names
    var registers: [String] { get }

    /// Get calling convention info
    var callingConvention: CallingConvention { get }
}

struct CallingConvention {
    let argumentRegisters: [String]
    let returnValueRegister: String
    let calleeSavedRegisters: [String]
    let stackAlignment: Int
}

// MARK: - UI Plugin

/// Plugin that adds custom UI elements
protocol UIPlugin: DisassemblerPlugin {
    /// Custom sidebar view
    func sidebarView() -> AnyView?

    /// Custom toolbar items
    func toolbarItems() -> [ToolbarItem]?

    /// Custom context menu items
    func contextMenuItems(for address: UInt64) -> [ContextMenuItem]?
}

struct ToolbarItem {
    let id: String
    let label: String
    let icon: String
    let action: () -> Void
}

struct ContextMenuItem {
    let label: String
    let action: () -> Void
}

import SwiftUI

extension UIPlugin {
    func sidebarView() -> AnyView? { nil }
    func toolbarItems() -> [ToolbarItem]? { nil }
    func contextMenuItems(for address: UInt64) -> [ContextMenuItem]? { nil }
}

// MARK: - Plugin Manager

@MainActor
class PluginManager: ObservableObject {
    static let shared = PluginManager()

    @Published var loadedPlugins: [String: DisassemblerPlugin] = [:]
    @Published var analysisPlugins: [AnalysisPlugin] = []
    @Published var loaderPlugins: [LoaderPlugin] = []
    @Published var processorPlugins: [ProcessorPlugin] = []
    @Published var uiPlugins: [UIPlugin] = []

    private var context: PluginContext?

    private init() {}

    // MARK: - Plugin Loading

    /// Initialize plugin system with app state
    func initialize(appState: AppState) {
        context = PluginContext(appState: appState)
        loadBuiltInPlugins()
        loadExternalPlugins()
    }

    /// Load built-in plugins
    private func loadBuiltInPlugins() {
        // Register built-in analysis plugins
        registerPlugin(VulnerabilityScanner())
        registerPlugin(CryptoDetector())
        registerPlugin(StringXRefPlugin())
    }

    /// Load external plugins from plugins directory
    private func loadExternalPlugins() {
        let pluginsDir = getPluginsDirectory()

        guard let contents = try? FileManager.default.contentsOfDirectory(
            at: pluginsDir,
            includingPropertiesForKeys: nil
        ) else { return }

        for url in contents where url.pathExtension == "bundle" {
            loadPluginBundle(at: url)
        }
    }

    private func getPluginsDirectory() -> URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first!
        let pluginsDir = appSupport.appendingPathComponent("Aether/Plugins", isDirectory: true)
        try? FileManager.default.createDirectory(at: pluginsDir, withIntermediateDirectories: true)
        return pluginsDir
    }

    private func loadPluginBundle(at url: URL) {
        guard let bundle = Bundle(url: url),
              bundle.load(),
              let principalClass = bundle.principalClass as? DisassemblerPlugin.Type else {
            return
        }

        // Create instance using NSObject approach for dynamic loading
        if let objcClass = principalClass as? NSObject.Type {
            if let plugin = objcClass.init() as? DisassemblerPlugin {
                registerPlugin(plugin)
            }
        }
    }

    // MARK: - Plugin Registration

    func registerPlugin(_ plugin: DisassemblerPlugin) {
        loadedPlugins[plugin.identifier] = plugin

        if let analysis = plugin as? AnalysisPlugin {
            analysisPlugins.append(analysis)
        }
        if let loader = plugin as? LoaderPlugin {
            loaderPlugins.append(loader)
        }
        if let processor = plugin as? ProcessorPlugin {
            processorPlugins.append(processor)
        }
        if let ui = plugin as? UIPlugin {
            uiPlugins.append(ui)
        }

        // Initialize plugin
        if let ctx = context {
            Task {
                try? await plugin.initialize(context: ctx)
            }
        }
    }

    func unloadPlugin(identifier: String) async {
        guard let plugin = loadedPlugins[identifier] else { return }

        await plugin.cleanup()
        loadedPlugins.removeValue(forKey: identifier)

        // Remove from specific lists
        analysisPlugins.removeAll { $0.identifier == identifier }
        loaderPlugins.removeAll { $0.identifier == identifier }
        processorPlugins.removeAll { $0.identifier == identifier }
        uiPlugins.removeAll { $0.identifier == identifier }
    }

    // MARK: - Plugin Execution

    func runAnalysis(on binary: BinaryFile) async -> [AnalysisResult] {
        guard let ctx = context else { return [] }

        var results: [AnalysisResult] = []

        for plugin in analysisPlugins {
            do {
                let result = try await plugin.analyze(binary: binary, context: ctx)
                results.append(result)
            } catch {
                ctx.log("Analysis plugin \(plugin.name) failed: \(error)")
            }
        }

        return results
    }

    func findLoader(for data: Data) -> LoaderPlugin? {
        loaderPlugins.first { $0.canLoad(data: data) }
    }

    func findProcessor(for architecture: String) -> ProcessorPlugin? {
        processorPlugins.first { $0.architectureId == architecture }
    }
}

// MARK: - Built-in Plugins

/// Vulnerability scanner plugin
class VulnerabilityScanner: AnalysisPlugin {
    let identifier = "com.disassembler.vulnerability-scanner"
    let name = "Vulnerability Scanner"
    let version = "1.0.0"
    let description = "Scans for common vulnerabilities and dangerous patterns"
    let author = "Aether Team"

    func initialize(context: PluginContext) async throws {}
    func cleanup() async {}

    func analyze(binary: BinaryFile, context: PluginContext) async throws -> AnalysisResult {
        var findings: [AnalysisFinding] = []

        // Check for dangerous imports
        let dangerousImports = ["_gets", "_strcpy", "_strcat", "_sprintf", "_vsprintf"]
        for symbol in binary.symbols {
            if dangerousImports.contains(symbol.name) {
                findings.append(AnalysisFinding(
                    address: symbol.address,
                    type: .vulnerability,
                    message: "Use of dangerous function: \(symbol.displayName)",
                    severity: .high
                ))
            }
        }

        // Check for format string vulnerabilities
        let formatFuncs = ["_printf", "_fprintf", "_sprintf", "_snprintf"]
        for symbol in binary.symbols where formatFuncs.contains(symbol.name) {
            // Would need to analyze call sites for user-controlled format strings
        }

        return AnalysisResult(findings: findings, metadata: [:])
    }

    required init() {}
}

/// Crypto detection plugin
class CryptoDetector: AnalysisPlugin {
    let identifier = "com.disassembler.crypto-detector"
    let name = "Crypto Detector"
    let version = "1.0.0"
    let description = "Detects cryptographic algorithms and constants"
    let author = "Aether Team"

    // Known crypto constants
    private let cryptoConstants: [(name: String, values: [UInt32])] = [
        ("AES S-Box", [0x637c777b, 0xf26b6fc5, 0x3001672b, 0xfed7ab76]),
        ("SHA-256 K", [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5]),
        ("MD5 T", [0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee]),
        ("RC4 S-Box Init", [0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c]),
    ]

    func initialize(context: PluginContext) async throws {}
    func cleanup() async {}

    func analyze(binary: BinaryFile, context: PluginContext) async throws -> AnalysisResult {
        var findings: [AnalysisFinding] = []

        // Search for crypto constants in data sections
        for section in binary.sections where !section.containsCode {
            for (name, values) in cryptoConstants {
                if let address = findConstantSequence(in: section, values: values) {
                    findings.append(AnalysisFinding(
                        address: address,
                        type: .cryptoUsage,
                        message: "Detected \(name) constant",
                        severity: .info
                    ))
                }
            }
        }

        // Check for crypto library imports
        let cryptoImports = ["_CCCrypt", "_SecKeyEncrypt", "_EVP_EncryptInit", "_AES_encrypt"]
        for symbol in binary.symbols where cryptoImports.contains(symbol.name) {
            findings.append(AnalysisFinding(
                address: symbol.address,
                type: .cryptoUsage,
                message: "Crypto API usage: \(symbol.displayName)",
                severity: .info
            ))
        }

        return AnalysisResult(findings: findings, metadata: [:])
    }

    private func findConstantSequence(in section: Section, values: [UInt32]) -> UInt64? {
        let data = section.data
        guard data.count >= values.count * 4 else { return nil }

        for offset in stride(from: 0, to: data.count - values.count * 4, by: 4) {
            var found = true
            for (i, expected) in values.enumerated() {
                guard let actual = data.readUInt32LE(at: offset + i * 4) else {
                    found = false
                    break
                }
                if actual != expected {
                    found = false
                    break
                }
            }
            if found {
                return section.address + UInt64(offset)
            }
        }

        return nil
    }

    required init() {}
}

/// String cross-reference plugin
class StringXRefPlugin: AnalysisPlugin {
    let identifier = "com.disassembler.string-xref"
    let name = "String XRef Builder"
    let version = "1.0.0"
    let description = "Builds cross-references from code to strings"
    let author = "Aether Team"

    func initialize(context: PluginContext) async throws {}
    func cleanup() async {}

    func analyze(binary: BinaryFile, context: PluginContext) async throws -> AnalysisResult {
        // This would build a comprehensive string cross-reference table
        return AnalysisResult(findings: [], metadata: [:])
    }

    required init() {}
}
