import SwiftUI

struct ToolbarView: View {
    @EnvironmentObject var appState: AppState
    @Environment(\.openSettings) private var openSettings

    var body: some View {
        HStack(spacing: 16) {
            // File operations
            HStack(spacing: 8) {
                ToolbarButton(
                    icon: "doc.badge.plus",
                    label: translate("toolbar.open"),
                    shortcut: "O"
                ) {
                    appState.openFile()
                }

                ToolbarButton(
                    icon: "square.and.arrow.down",
                    label: translate("toolbar.save"),
                    shortcut: "S"
                ) {
                    appState.saveFileAs()
                }
                .disabled(appState.currentFile == nil)

                ToolbarButton(
                    icon: "arrow.clockwise",
                    label: translate("toolbar.reload"),
                    shortcut: nil
                ) {
                    if let url = appState.currentFile?.url {
                        Task {
                            await appState.loadFile(url: url)
                        }
                    }
                }
                .disabled(appState.currentFile == nil)

                ToolbarButton(
                    icon: "xmark.circle",
                    label: translate("toolbar.close"),
                    shortcut: "W"
                ) {
                    appState.closeFile()
                }
                .disabled(appState.currentFile == nil)
            }

            // Unsaved changes indicator
            if appState.hasUnsavedChanges {
                Circle()
                    .fill(Color.orange)
                    .frame(width: 8, height: 8)
                    .help(translate("toolbar.unsavedChanges"))
            }

            Divider()
                .frame(height: 24)

            // Analysis
            HStack(spacing: 8) {
                ToolbarButton(
                    icon: "cpu",
                    label: translate("toolbar.analyze"),
                    shortcut: "A"
                ) {
                    appState.analyzeAll()
                }
                .disabled(appState.currentFile == nil)

                ToolbarButton(
                    icon: "function",
                    label: translate("toolbar.functions"),
                    shortcut: nil
                ) {
                    appState.findFunctions()
                }
                .disabled(appState.currentFile == nil)
            }

            Divider()
                .frame(height: 24)

            // View toggles
            HStack(spacing: 8) {
                ToolbarToggle(
                    icon: "rectangle.split.2x1",
                    label: translate("toolbar.decompiler"),
                    isOn: $appState.showDecompiler
                )

                ToolbarToggle(
                    icon: "rectangle.bottomhalf.filled",
                    label: translate("toolbar.hexView"),
                    isOn: $appState.showHexView
                )

                ToolbarButton(
                    icon: "point.3.connected.trianglepath.dotted",
                    label: translate("toolbar.cfg"),
                    shortcut: "G"
                ) {
                    appState.showCFG.toggle()
                }
                .disabled(appState.selectedFunction == nil)
            }

            Divider()
                .frame(height: 24)

            // AI Features
            HStack(spacing: 8) {
                if appState.hasAIAPIKey {
                    Menu {
                        // Chat
                        Button {
                            appState.showAIChat = true
                        } label: {
                            Label(translate("toolbar.ai.chat"), systemImage: "bubble.left.and.bubble.right")
                        }

                        Divider()

                        // Code Understanding
                        Button {
                            appState.explainCurrentFunction()
                        } label: {
                            Label(translate("toolbar.ai.explainFunction"), systemImage: "text.bubble")
                        }
                        .disabled(appState.selectedFunction == nil)

                        Button {
                            appState.suggestVariableNames()
                        } label: {
                            Label(translate("toolbar.ai.renameVariables"), systemImage: "textformat.abc")
                        }
                        .disabled(appState.selectedFunction == nil || appState.decompilerOutput.isEmpty)

                        Divider()

                        // Security Analysis
                        Button {
                            appState.analyzeWithAI()
                        } label: {
                            Label(translate("toolbar.ai.securityAnalysis"), systemImage: "shield.lefthalf.filled")
                        }
                        .disabled(appState.selectedFunction == nil)

                        Button {
                            appState.analyzeBinaryWithAI()
                        } label: {
                            Label(translate("toolbar.ai.analyzeBinary"), systemImage: "doc.viewfinder")
                        }
                        .disabled(appState.currentFile == nil)
                    } label: {
                        VStack(spacing: 2) {
                            Image(systemName: "brain")
                                .font(.system(size: 16))
                                .foregroundColor(.purple)
                            Text(translate("toolbar.ai"))
                                .font(.caption2)
                        }
                        .frame(minWidth: 40)
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                    }
                    .menuStyle(.borderlessButton)
                } else {
                    ToolbarButton(
                        icon: "brain",
                        label: translate("toolbar.ai"),
                        shortcut: nil
                    ) {
                        openSettings()
                    }
                    .opacity(0.5)
                    .help(translate("toolbar.ai.configure"))
                }

                ToolbarButton(
                    icon: "gear",
                    label: translate("toolbar.settings"),
                    shortcut: ","
                ) {
                    openSettings()
                }
            }

            Divider()
                .frame(height: 24)

            // Frida Script Generation
            Menu {
                Button {
                    appState.generateFridaScript()
                } label: {
                    Label(translate("toolbar.frida.generateBasic"), systemImage: "doc.text")
                }
                .disabled(appState.selectedFunction == nil)

                if appState.hasAIAPIKey {
                    Button {
                        appState.generateFridaScriptWithAI()
                    } label: {
                        Label(translate("toolbar.frida.generateWithAI"), systemImage: "brain")
                    }
                    .disabled(appState.selectedFunction == nil)
                }

                Button {
                    appState.generateMultiFunctionFridaScript()
                } label: {
                    Label(translate("toolbar.frida.hookMultiple"), systemImage: "list.bullet")
                }
                .disabled(appState.functions.isEmpty)

                Divider()

                // Platform submenu
                Menu(translate("toolbar.frida.platform")) {
                    ForEach(FridaPlatform.allCases) { platform in
                        Button {
                            appState.selectedFridaPlatform = platform
                        } label: {
                            HStack {
                                Text(platform.rawValue)
                                if appState.selectedFridaPlatform == platform {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                    }
                }

                // Hook type submenu
                Menu(translate("toolbar.frida.hookType")) {
                    ForEach(FridaHookType.allCases) { type in
                        Button {
                            appState.selectedFridaHookType = type
                        } label: {
                            HStack {
                                Label(type.rawValue, systemImage: type.icon)
                                if appState.selectedFridaHookType == type {
                                    Image(systemName: "checkmark")
                                }
                            }
                        }
                    }
                }
            } label: {
                VStack(spacing: 2) {
                    Image(systemName: "hammer.fill")
                        .font(.system(size: 16))
                        .foregroundColor(.orange)
                    Text(translate("toolbar.frida"))
                        .font(.caption2)
                }
                .frame(minWidth: 50)
                .padding(.vertical, 4)
                .padding(.horizontal, 8)
            }
            .menuStyle(.borderlessButton)
            .disabled(appState.currentFile == nil)

            Spacer()

            // Search
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)

                Text(translate("toolbar.search"))
                    .foregroundColor(.secondary)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(Color.background)
            .cornerRadius(8)
            .onTapGesture {
                appState.showSearch = true
            }

            // Quick navigation
            ToolbarButton(
                icon: "arrow.right.circle",
                label: translate("toolbar.goto"),
                shortcut: "G"
            ) {
                appState.showGoToAddress = true
            }
            .disabled(appState.currentFile == nil)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 8)
        .background(Color.sidebar)
    }

    private func openSettingsWindow() {
        openSettings()
    }
}

// MARK: - Toolbar Button

struct ToolbarButton: View {
    let icon: String
    let label: String
    let shortcut: String?
    let action: () -> Void

    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            VStack(spacing: 2) {
                Image(systemName: icon)
                    .font(.system(size: 16))

                Text(label)
                    .font(.caption2)
            }
            .frame(minWidth: 50)
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isHovered ? Color.white.opacity(0.1) : Color.clear)
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
        .foregroundColor(isHovered ? .accent : .primary)
        .onHover { hovering in
            isHovered = hovering
        }
        .help(shortcut ?? "")
    }
}

// MARK: - Toolbar Toggle

struct ToolbarToggle: View {
    let icon: String
    let label: String
    @Binding var isOn: Bool

    @State private var isHovered = false

    var body: some View {
        Button {
            isOn.toggle()
        } label: {
            VStack(spacing: 2) {
                Image(systemName: icon)
                    .font(.system(size: 16))

                Text(label)
                    .font(.caption2)
            }
            .frame(minWidth: 50)
            .padding(.vertical, 4)
            .padding(.horizontal, 8)
            .background(isOn ? Color.accent.opacity(0.3) : (isHovered ? Color.white.opacity(0.1) : Color.clear))
            .cornerRadius(6)
        }
        .buttonStyle(.plain)
        .foregroundColor(isOn ? .accent : (isHovered ? .accent : .primary))
        .onHover { hovering in
            isHovered = hovering
        }
        .help("")
    }
}
