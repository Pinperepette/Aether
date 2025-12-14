import SwiftUI

struct ToolbarView: View {
    @EnvironmentObject var appState: AppState

    var body: some View {
        HStack(spacing: 16) {
            // File operations
            HStack(spacing: 8) {
                ToolbarButton(
                    icon: "doc.badge.plus",
                    label: "Open",
                    shortcut: "O"
                ) {
                    appState.openFile()
                }

                ToolbarButton(
                    icon: "square.and.arrow.down",
                    label: "Save",
                    shortcut: "S"
                ) {
                    appState.saveFileAs()
                }
                .disabled(appState.currentFile == nil)

                ToolbarButton(
                    icon: "arrow.clockwise",
                    label: "Reload",
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
                    label: "Close",
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
                    .help("Unsaved changes")
            }

            Divider()
                .frame(height: 24)

            // Analysis
            HStack(spacing: 8) {
                ToolbarButton(
                    icon: "cpu",
                    label: "Analyze",
                    shortcut: "A"
                ) {
                    appState.analyzeAll()
                }
                .disabled(appState.currentFile == nil)

                ToolbarButton(
                    icon: "function",
                    label: "Functions",
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
                    label: "Decompiler",
                    isOn: $appState.showDecompiler
                )

                ToolbarToggle(
                    icon: "rectangle.bottomhalf.filled",
                    label: "Hex View",
                    isOn: $appState.showHexView
                )

                ToolbarButton(
                    icon: "point.3.connected.trianglepath.dotted",
                    label: "CFG",
                    shortcut: "G"
                ) {
                    appState.showCFG.toggle()
                }
                .disabled(appState.selectedFunction == nil)
            }

            Divider()
                .frame(height: 24)

            // AI Analysis
            HStack(spacing: 8) {
                if appState.hasClaudeAPIKey {
                    Menu {
                        Button {
                            appState.analyzeWithAI()
                        } label: {
                            Label("Analyze Function", systemImage: "function")
                        }
                        .disabled(appState.selectedFunction == nil)

                        Button {
                            appState.analyzeBinaryWithAI()
                        } label: {
                            Label("Analyze Binary", systemImage: "doc.viewfinder")
                        }
                        .disabled(appState.currentFile == nil)
                    } label: {
                        VStack(spacing: 2) {
                            Image(systemName: "brain")
                                .font(.system(size: 16))
                                .foregroundColor(.purple)
                            Text("AI Analysis")
                                .font(.caption2)
                        }
                        .frame(minWidth: 50)
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                    }
                    .menuStyle(.borderlessButton)
                    .disabled(appState.currentFile == nil)
                } else {
                    ToolbarButton(
                        icon: "brain",
                        label: "AI Analysis",
                        shortcut: nil
                    ) {
                        openSettings()
                    }
                    .opacity(0.5)
                }

                ToolbarButton(
                    icon: "gear",
                    label: "Settings",
                    shortcut: ","
                ) {
                    openSettings()
                }
            }

            Spacer()

            // Search
            HStack {
                Image(systemName: "magnifyingglass")
                    .foregroundColor(.secondary)

                Text("Search...")
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
                label: "Go to",
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

    private func openSettings() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
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
        .help(shortcut != nil ? "\(label) (\(shortcut!))" : label)
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
        .help(label)
    }
}
