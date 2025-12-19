//
//  FridaScriptView.swift
//  Aether
//
//  Frida script generation UI
//

import SwiftUI
import AppKit

struct FridaScriptView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.dismiss) var dismiss
    @State private var copiedToClipboard = false

    var body: some View {
        VStack(spacing: 0) {
            // Header with options
            headerView

            Divider()

            // Content
            if appState.isGeneratingFridaScript {
                loadingView
            } else if let error = appState.fridaScriptError {
                errorView(error)
            } else if let aiResult = appState.aiFridaScriptResult {
                aiResultView(aiResult)
            } else if let result = appState.fridaScriptResult {
                basicResultView(result)
            } else {
                emptyView
            }
        }
        .frame(width: 750, height: 650)
        .background(Color.background)
    }

    // MARK: - Header View

    var headerView: some View {
        VStack(spacing: 12) {
            HStack {
                Image(systemName: "hammer.fill")
                    .font(.title2)
                    .foregroundColor(.orange)
                Text("Frida Script Generator")
                    .font(.headline)

                Spacer()

                Button("Close") { dismiss() }
                    .keyboardShortcut(.escape, modifiers: [])
            }

            HStack(spacing: 16) {
                // Platform picker
                HStack(spacing: 8) {
                    Text("Platform:")
                        .foregroundColor(.secondary)
                    Picker("", selection: $appState.selectedFridaPlatform) {
                        ForEach(FridaPlatform.allCases) { platform in
                            Text(platform.rawValue).tag(platform)
                        }
                    }
                    .pickerStyle(.segmented)
                    .frame(width: 140)
                }

                // Hook type picker
                HStack(spacing: 8) {
                    Text("Type:")
                        .foregroundColor(.secondary)
                    Picker("", selection: $appState.selectedFridaHookType) {
                        ForEach(FridaHookType.allCases) { type in
                            Label(type.rawValue, systemImage: type.icon).tag(type)
                        }
                    }
                    .frame(width: 150)
                }

                Spacer()

                // Generate buttons
                Button {
                    appState.generateFridaScript()
                } label: {
                    Label("Basic", systemImage: "doc.text")
                }
                .disabled(appState.selectedFunction == nil)

                if appState.hasAIAPIKey {
                    Button {
                        appState.generateFridaScriptWithAI()
                    } label: {
                        Label("AI Enhanced", systemImage: "brain")
                    }
                    .buttonStyle(.borderedProminent)
                    .tint(.purple)
                    .disabled(appState.selectedFunction == nil)
                }
            }
        }
        .padding()
        .background(Color.sidebar)
    }

    // MARK: - Loading View

    var loadingView: some View {
        VStack(spacing: 16) {
            ProgressView()
                .scaleEffect(1.5)
            Text("Generating Frida script...")
                .font(.headline)
            if appState.hasAIAPIKey && appState.selectedFridaHookType == .bypass {
                Text("AI is analyzing bypass techniques...")
                    .font(.subheadline)
                    .foregroundColor(.secondary)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Error View

    func errorView(_ error: String) -> some View {
        VStack(spacing: 16) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.system(size: 48))
                .foregroundColor(.orange)

            Text("Error")
                .font(.headline)

            Text(error)
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button("Try Again") {
                appState.generateFridaScript()
            }
            .buttonStyle(.borderedProminent)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Empty View

    var emptyView: some View {
        VStack(spacing: 16) {
            Image(systemName: "hammer")
                .font(.system(size: 48))
                .foregroundColor(.secondary)

            Text("Select a function and click Generate")
                .font(.headline)
                .foregroundColor(.secondary)

            if appState.selectedFunction != nil {
                Text("Current: \(appState.selectedFunction!.displayName)")
                    .font(.subheadline)
                    .foregroundColor(.orange)
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }

    // MARK: - Basic Result View

    func basicResultView(_ result: FridaScriptResult) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    // Info header
                    GroupBox {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack {
                                Label(result.platform.rawValue, systemImage: result.platform == .iOS ? "iphone" : "desktopcomputer")
                                    .foregroundColor(.blue)
                                Spacer()
                                Label(result.hookType.rawValue, systemImage: result.hookType.icon)
                                    .foregroundColor(.orange)
                            }

                            Text(result.description)
                                .font(.callout)
                                .foregroundColor(.secondary)

                            if !result.targetFunctions.isEmpty {
                                HStack {
                                    Text("Targets:")
                                        .foregroundColor(.secondary)
                                    Text(result.targetFunctions.joined(separator: ", "))
                                        .font(.system(.body, design: .monospaced))
                                }
                            }
                        }
                    }

                    // Script
                    GroupBox("Frida Script") {
                        scriptCodeView(result.script)
                    }
                }
                .padding()
            }

            // Bottom actions
            bottomActionsView(script: result.script)
        }
    }

    // MARK: - AI Result View

    func aiResultView(_ result: AIFridaScriptResult) -> some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    // AI badge
                    HStack {
                        Image(systemName: "brain")
                            .foregroundColor(.purple)
                        Text("AI-Enhanced Script")
                            .font(.headline)
                            .foregroundColor(.purple)
                        Spacer()
                    }
                    .padding(.horizontal)

                    // Explanation
                    if !result.explanation.isEmpty {
                        GroupBox {
                            HStack(alignment: .top) {
                                Image(systemName: "lightbulb.fill")
                                    .foregroundColor(.yellow)
                                Text(result.explanation)
                                    .font(.callout)
                            }
                        } label: {
                            Label("What this script does", systemImage: "doc.text.magnifyingglass")
                        }
                    }

                    // Hook points
                    if !result.hookPoints.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(result.hookPoints, id: \.self) { point in
                                    HStack {
                                        Image(systemName: "target")
                                            .foregroundColor(.blue)
                                        Text(point)
                                            .font(.system(.body, design: .monospaced))
                                    }
                                }
                            }
                        } label: {
                            Label("Hook Points", systemImage: "target")
                        }
                    }

                    // Bypasses implemented
                    if !result.bypassImplemented.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(result.bypassImplemented, id: \.self) { bypass in
                                    HStack {
                                        Image(systemName: "checkmark.shield")
                                            .foregroundColor(.green)
                                        Text(bypass)
                                            .font(.callout)
                                    }
                                }
                            }
                        } label: {
                            Label("Bypasses Implemented", systemImage: "shield.slash")
                        }
                    }

                    // Warnings
                    if !result.warnings.isEmpty {
                        GroupBox {
                            VStack(alignment: .leading, spacing: 4) {
                                ForEach(result.warnings, id: \.self) { warning in
                                    HStack(alignment: .top) {
                                        Image(systemName: "exclamationmark.triangle")
                                            .foregroundColor(.orange)
                                        Text(warning)
                                            .font(.callout)
                                    }
                                }
                            }
                        } label: {
                            Label("Warnings", systemImage: "exclamationmark.triangle")
                        }
                    }

                    // Script
                    GroupBox {
                        scriptCodeView(result.script)
                    } label: {
                        Label("Frida Script", systemImage: "chevron.left.forwardslash.chevron.right")
                    }
                }
                .padding()
            }

            // Bottom actions
            bottomActionsView(script: result.script)
        }
    }

    // MARK: - Script Code View

    func scriptCodeView(_ script: String) -> some View {
        ScrollView([.horizontal, .vertical]) {
            Text(script)
                .font(.system(.body, design: .monospaced))
                .textSelection(.enabled)
                .padding()
                .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 300)
        .background(Color.black.opacity(0.4))
        .cornerRadius(8)
    }

    // MARK: - Bottom Actions View

    func bottomActionsView(script: String) -> some View {
        HStack(spacing: 16) {
            Button {
                copyToClipboard(script)
            } label: {
                Label(copiedToClipboard ? "Copied!" : "Copy to Clipboard", systemImage: copiedToClipboard ? "checkmark" : "doc.on.doc")
            }
            .buttonStyle(.bordered)

            Button {
                saveScriptToFile(script)
            } label: {
                Label("Save to File", systemImage: "square.and.arrow.down")
            }
            .buttonStyle(.bordered)

            Spacer()

            // Quick run instructions
            VStack(alignment: .trailing, spacing: 2) {
                Text("Run with Frida:")
                    .font(.caption)
                    .foregroundColor(.secondary)
                Text("frida -U -f <app> -l script.js")
                    .font(.system(.caption, design: .monospaced))
                    .foregroundColor(.orange)
            }
        }
        .padding()
        .background(Color.sidebar)
    }

    // MARK: - Actions

    private func copyToClipboard(_ script: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(script, forType: .string)
        copiedToClipboard = true

        // Reset after 2 seconds
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            copiedToClipboard = false
        }
    }

    private func saveScriptToFile(_ script: String) {
        let panel = NSSavePanel()
        panel.allowedContentTypes = [.javaScript]
        panel.nameFieldStringValue = generateFileName()
        panel.message = "Save Frida Script"

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try script.write(to: url, atomically: true, encoding: .utf8)
            } catch {
                appState.fridaScriptError = "Failed to save: \(error.localizedDescription)"
            }
        }
    }

    private func generateFileName() -> String {
        let functionName = appState.selectedFunction?.displayName
            .replacingOccurrences(of: " ", with: "_")
            .replacingOccurrences(of: "[", with: "")
            .replacingOccurrences(of: "]", with: "")
            .replacingOccurrences(of: ":", with: "_")
            ?? "hook"

        let hookType = appState.selectedFridaHookType.rawValue.lowercased()
        let platform = appState.selectedFridaPlatform.rawValue.lowercased()

        return "\(functionName)_\(hookType)_\(platform).js"
    }
}
