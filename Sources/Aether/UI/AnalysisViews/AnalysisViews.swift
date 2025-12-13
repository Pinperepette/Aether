import SwiftUI

// MARK: - Crypto Detection View

struct CryptoDetectionView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "lock.shield")
                    .foregroundColor(.accent)
                Text("Crypto Detection Results")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            if appState.cryptoFindings.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "checkmark.shield")
                        .font(.system(size: 48))
                        .foregroundColor(.green)
                    Text("No cryptographic patterns detected")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.cryptoFindings, id: \.address) { finding in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: algorithmIcon(finding.algorithm))
                                .foregroundColor(.orange)
                            Text(finding.algorithm.rawValue)
                                .font(.headline)
                            Spacer()
                            Text(String(format: "%.0f%%", finding.confidence * 100))
                                .font(.caption)
                                .padding(.horizontal, 8)
                                .padding(.vertical, 2)
                                .background(confidenceColor(finding.confidence))
                                .cornerRadius(4)
                        }

                        Text(finding.description)
                            .font(.subheadline)
                            .foregroundColor(.secondary)

                        HStack {
                            Text(String(format: "0x%llX", finding.address))
                                .font(.system(.caption, design: .monospaced))
                                .foregroundColor(.blue)

                            Button("Go to") {
                                appState.goToAddress(finding.address)
                                dismiss()
                            }
                            .buttonStyle(.borderless)
                            .font(.caption)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .frame(width: 500, height: 400)
    }

    private func algorithmIcon(_ algo: AdvancedCryptoDetector.CryptoAlgorithm) -> String {
        switch algo {
        case .aes, .des, .tripleDES, .blowfish, .twofish, .chacha20, .salsa20, .camellia, .serpent, .rc4:
            return "lock.fill"
        case .md5, .sha1, .sha256, .sha384, .sha512, .sha3, .blake2, .whirlpool, .ripemd160:
            return "number"
        case .rsa, .dsa, .ecdsa, .curve25519, .ed25519:
            return "key.fill"
        case .pbkdf2, .bcrypt, .scrypt, .argon2:
            return "key.horizontal"
        case .crc32:
            return "checkmark.circle"
        case .base64:
            return "textformat"
        case .unknown:
            return "questionmark.circle"
        }
    }

    private func confidenceColor(_ confidence: Double) -> Color {
        if confidence >= 0.9 { return Color.green.opacity(0.3) }
        if confidence >= 0.7 { return Color.yellow.opacity(0.3) }
        return Color.orange.opacity(0.3)
    }
}

// MARK: - Deobfuscation View

struct DeobfuscationView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "eye.slash")
                    .foregroundColor(.accent)
                Text("Deobfuscation Analysis")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            if let report = appState.deobfuscationReport {
                ScrollView {
                    VStack(alignment: .leading, spacing: 16) {
                        // Summary
                        GroupBox("Summary") {
                            VStack(alignment: .leading, spacing: 8) {
                                HStack {
                                    Text("Obfuscation Score:")
                                    Spacer()
                                    Text(String(format: "%.1f%%", report.obfuscationScore * 100))
                                        .fontWeight(.bold)
                                        .foregroundColor(scoreColor(report.obfuscationScore))
                                }
                                HStack {
                                    Text("Is Obfuscated:")
                                    Spacer()
                                    Text(report.isObfuscated ? "Yes" : "No")
                                        .foregroundColor(report.isObfuscated ? .red : .green)
                                }
                            }
                        }

                        // Detected Techniques
                        if !report.detectedTechniques.isEmpty {
                            GroupBox("Detected Techniques") {
                                ForEach(Array(report.detectedTechniques.enumerated()), id: \.offset) { _, technique in
                                    VStack(alignment: .leading, spacing: 4) {
                                        HStack {
                                            Text(technique.type.rawValue)
                                                .fontWeight(.medium)
                                            Spacer()
                                            Text(String(format: "%.0f%%", technique.confidence * 100))
                                                .font(.caption)
                                                .foregroundColor(.secondary)
                                        }
                                        Text(technique.description)
                                            .font(.caption)
                                            .foregroundColor(.secondary)
                                    }
                                    .padding(.vertical, 4)
                                    Divider()
                                }
                            }
                        }

                        // Recommendations
                        if !report.recommendations.isEmpty {
                            GroupBox("Recommendations") {
                                ForEach(report.recommendations, id: \.self) { rec in
                                    HStack(alignment: .top) {
                                        Image(systemName: "lightbulb")
                                            .foregroundColor(.yellow)
                                        Text(rec)
                                            .font(.caption)
                                    }
                                    .padding(.vertical, 2)
                                }
                            }
                        }
                    }
                    .padding()
                }
            } else {
                VStack {
                    Text("No analysis results")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(width: 500, height: 450)
    }

    private func scoreColor(_ score: Double) -> Color {
        if score >= 0.7 { return .red }
        if score >= 0.4 { return .orange }
        return .green
    }
}

// MARK: - Type Recovery View

struct TypeRecoveryView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "curlybraces")
                    .foregroundColor(.accent)
                Text("Recovered Types")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            if appState.recoveredTypes.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No types recovered")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.recoveredTypes, id: \.address) { type in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Image(systemName: typeIcon(type.category))
                                .foregroundColor(.purple)
                            Text(type.name)
                                .font(.system(.body, design: .monospaced))
                                .fontWeight(.medium)
                            Spacer()
                            Text(String(format: "%.0f%%", type.confidence * 100))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Text(type.cTypeDeclaration)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.green)
                            .padding(4)
                            .background(Color.black.opacity(0.3))
                            .cornerRadius(4)

                        Text(String(format: "Address: 0x%llX, Size: %d bytes", type.address, type.size))
                            .font(.caption2)
                            .foregroundColor(.secondary)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .frame(width: 550, height: 400)
    }

    private func typeIcon(_ category: RecoveredTypeWrapper.TypeCategory) -> String {
        switch category {
        case .struct_: return "square.stack.3d.up"
        case .array: return "square.grid.3x3"
        case .enum_: return "list.number"
        case .pointer: return "arrow.right"
        case .primitive: return "textformat"
        case .function: return "function"
        case .union: return "square.on.square"
        }
    }
}

// MARK: - Idiom Recognition View

struct IdiomRecognitionView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "text.magnifyingglass")
                    .foregroundColor(.accent)
                Text("Recognized Idioms")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            if appState.recognizedIdioms.isEmpty {
                VStack(spacing: 16) {
                    Image(systemName: "doc.text.magnifyingglass")
                        .font(.system(size: 48))
                        .foregroundColor(.secondary)
                    Text("No idioms recognized")
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(appState.recognizedIdioms, id: \.startAddress) { idiom in
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            Text(idiom.category.rawValue)
                                .font(.caption)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(categoryColor(idiom.category))
                                .cornerRadius(4)

                            Text(idiom.name)
                                .fontWeight(.medium)

                            Spacer()

                            Text(String(format: "%.0f%%", idiom.confidence * 100))
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }

                        Text(idiom.description)
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text(idiom.replacement)
                            .font(.system(.caption, design: .monospaced))
                            .foregroundColor(.green)
                            .padding(4)
                            .background(Color.black.opacity(0.3))
                            .cornerRadius(4)

                        HStack {
                            Text(String(format: "0x%llX - 0x%llX", idiom.startAddress, idiom.endAddress))
                                .font(.system(.caption2, design: .monospaced))
                                .foregroundColor(.blue)

                            Button("Go to") {
                                appState.goToAddress(idiom.startAddress)
                                dismiss()
                            }
                            .buttonStyle(.borderless)
                            .font(.caption)
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .frame(width: 550, height: 450)
    }

    private func categoryColor(_ category: IdiomRecognizer.IdiomCategory) -> Color {
        switch category {
        case .stringOperation: return Color.blue.opacity(0.3)
        case .memoryOperation: return Color.orange.opacity(0.3)
        case .arithmetic: return Color.green.opacity(0.3)
        case .bitManipulation: return Color.purple.opacity(0.3)
        case .comparison: return Color.yellow.opacity(0.3)
        case .loopConstruct: return Color.red.opacity(0.3)
        case .functionPrologue, .functionEpilogue: return Color.gray.opacity(0.3)
        case .systemCall: return Color.pink.opacity(0.3)
        case .objectiveC: return Color.cyan.opacity(0.3)
        case .swift: return Color.orange.opacity(0.3)
        }
    }
}

// MARK: - Pseudo Code View

struct PseudoCodeView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            // Header
            HStack {
                Image(systemName: "doc.text")
                    .foregroundColor(.accent)
                Text("Structured Pseudo-Code")
                    .font(.headline)
                Spacer()

                Button {
                    NSPasteboard.general.clearContents()
                    NSPasteboard.general.setString(appState.structuredCode, forType: .string)
                } label: {
                    Image(systemName: "doc.on.doc")
                }
                .help("Copy to clipboard")

                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            ScrollView {
                Text(appState.structuredCode.isEmpty ? "// No code generated" : appState.structuredCode)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(.green)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding()
            }
            .background(Color.black.opacity(0.8))
        }
        .frame(width: 600, height: 500)
    }
}

// MARK: - Call Graph Window View

struct CallGraphWindowView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Image(systemName: "arrow.triangle.branch")
                    .foregroundColor(.accent)
                Text("Call Graph")
                    .font(.headline)
                Spacer()
                Button("Close") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding()
            .background(Color.sidebar)

            Divider()

            CallGraphView()
        }
        .frame(width: 900, height: 600)
    }
}

// MARK: - Export Sheet View

struct ExportSheetView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var selectedFormat: ExportManager.ExportFormat = .idaPython

    var body: some View {
        VStack(spacing: 16) {
            Text("Export Analysis")
                .font(.headline)

            Picker("Format", selection: $selectedFormat) {
                ForEach(ExportManager.ExportFormat.allCases, id: \.self) { format in
                    Text(format.rawValue).tag(format)
                }
            }
            .pickerStyle(.radioGroup)

            HStack {
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)

                Button("Export...") {
                    exportFile()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .frame(width: 300)
    }

    private func exportFile() {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.data]
        panel.nameFieldStringValue = "\(appState.currentFile?.name ?? "export").\(selectedFormat.fileExtension)"

        if panel.runModal() == .OK, let url = panel.url {
            appState.exportTo(format: selectedFormat, url: url)
            dismiss()
        }
    }
}
